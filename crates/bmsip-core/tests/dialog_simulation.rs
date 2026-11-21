use std::collections::HashMap;
use std::time::{Duration, Instant};

use bmsip_core::auth::hash::md5_hex;
use bmsip_core::dialog::{CallState, RegistrationState, UaConfig, UaEvent, UserAgent};
use bmsip_core::sdp::{Direction, RtpCodec, SdpSession};
use bmsip_core::sim::NetworkPolicy;
use bmsip_core::sip::{
    CallerIdentity, Method, NameAddr, ReasonHeader, SipMessage, SipRequest, SipUri,
};
use bmsip_core::transaction::{TransactionEvent, TransactionId, TransactionManager};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeId {
    Alice,
    Bob,
    Proxy,
}

struct InFlight {
    deliver_at: Instant,
    to: NodeId,
    bytes: Vec<u8>,
}

struct MiniSipCluster {
    now: Instant,
    alice: UserAgent,
    bob: UserAgent,
    proxy: TransactionManager,
    registered_contacts: HashMap<String, SipUri>,
    proxy_dialogs: HashMap<String, (NodeId, NodeId)>,
    inbound_branches: HashMap<(String, String), TransactionId>,
    in_flight: Vec<InFlight>,
    policy: NetworkPolicy,
    rng: u64,
    register_count: usize,
    unregister_count: usize,
}

impl MiniSipCluster {
    fn new(start: Instant, policy: NetworkPolicy, seed: u64) -> Self {
        let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
        let alice_cfg = UaConfig::new(
            "alice",
            "alice-pw",
            "pbx.local",
            registrar.clone(),
            "10.0.0.1",
            5060,
        );
        let bob_cfg = UaConfig::new("bob", "bob-pw", "pbx.local", registrar, "10.0.0.2", 5062);

        Self {
            now: start,
            alice: UserAgent::new(alice_cfg),
            bob: UserAgent::new(bob_cfg),
            proxy: TransactionManager::default(),
            registered_contacts: HashMap::new(),
            proxy_dialogs: HashMap::new(),
            inbound_branches: HashMap::new(),
            in_flight: Vec::new(),
            policy,
            rng: seed.max(1),
            register_count: 0,
            unregister_count: 0,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    fn schedule(&mut self, to: NodeId, bytes: Vec<u8>) {
        if (self.next_u64() % 100) < u64::from(self.policy.loss_percent) {
            return;
        }
        let min_ms = self.policy.min_delay.as_millis() as u64;
        let max_ms = self.policy.max_delay.as_millis().max(min_ms as u128) as u64;
        let delay_ms = if max_ms == min_ms {
            min_ms
        } else {
            min_ms + (self.next_u64() % (max_ms - min_ms + 1))
        };
        let delay = Duration::from_millis(delay_ms);
        self.in_flight.push(InFlight {
            deliver_at: self.now + delay,
            to,
            bytes: bytes.clone(),
        });
        if (self.next_u64() % 100) < u64::from(self.policy.duplicate_percent) {
            self.in_flight.push(InFlight {
                deliver_at: self.now + delay + Duration::from_millis(5),
                to,
                bytes,
            });
        }
    }

    fn flush_outbound(&mut self) {
        for pkt in self.alice.poll_transmit() {
            let dest = self.route_from_alice_or_bob(&pkt);
            self.schedule(dest, pkt);
        }
        for pkt in self.bob.poll_transmit() {
            let dest = self.route_from_alice_or_bob(&pkt);
            self.schedule(dest, pkt);
        }
        for pkt in self.proxy.poll_transmit() {
            let dest = self.route_from_proxy(&pkt);
            self.schedule(dest, pkt);
        }
    }

    fn route_from_alice_or_bob(&self, pkt: &[u8]) -> NodeId {
        if let Ok(SipMessage::Request(req)) = SipMessage::parse(pkt) {
            if req.uri.host == "10.0.0.2" {
                return NodeId::Bob;
            }
            if req.uri.host == "10.0.0.1" || req.uri.host == "10.0.0.99" {
                return NodeId::Alice;
            }
        } else if let Ok(SipMessage::Response(resp)) = SipMessage::parse(pkt) {
            if let Ok(via) = resp.top_via() {
                if via.sent_by.starts_with("10.0.0.1") || via.sent_by.starts_with("10.0.0.99") {
                    return NodeId::Alice;
                }
                if via.sent_by.starts_with("10.0.0.2") {
                    return NodeId::Bob;
                }
            }
        }
        NodeId::Proxy
    }

    fn route_from_proxy(&self, pkt: &[u8]) -> NodeId {
        match SipMessage::parse(pkt).unwrap() {
            SipMessage::Response(resp) => {
                let via = resp.top_via().unwrap();
                if via.sent_by.starts_with("10.0.0.2") {
                    NodeId::Bob
                } else {
                    NodeId::Alice
                }
            }
            SipMessage::Request(req) => {
                if req.uri.host == "10.0.0.2" || req.uri.user.as_deref() == Some("bob") {
                    NodeId::Bob
                } else {
                    NodeId::Alice
                }
            }
        }
    }

    fn step_until(
        &mut self,
        max_steps: usize,
        stop_at: Option<Instant>,
    ) -> (Vec<UaEvent>, Vec<UaEvent>) {
        let mut alice_events = Vec::new();
        let mut bob_events = Vec::new();

        for _ in 0..max_steps {
            self.flush_outbound();
            alice_events.extend(self.alice.drain_events());
            bob_events.extend(self.bob.drain_events());

            let pkt_dl = self.in_flight.iter().map(|p| p.deliver_at).min();
            let a_dl = self.alice.poll_timeout();
            let b_dl = self.bob.poll_timeout();
            let p_dl = self.proxy.poll_timeout();

            let next_dl = [pkt_dl, a_dl, b_dl, p_dl].into_iter().flatten().min();
            let Some(next_at) = next_dl else {
                break;
            };
            if let Some(limit) = stop_at {
                if next_at > limit {
                    break;
                }
            }
            if next_at > self.now {
                self.now = next_at;
            }

            let mut due = Vec::new();
            let mut rest = Vec::new();
            for pkt in self.in_flight.drain(..) {
                if pkt.deliver_at <= self.now {
                    due.push(pkt);
                } else {
                    rest.push(pkt);
                }
            }
            self.in_flight = rest;

            for pkt in due {
                match pkt.to {
                    NodeId::Alice => {
                        alice_events.extend(self.alice.receive_datagram(&pkt.bytes, self.now));
                    }
                    NodeId::Bob => {
                        bob_events.extend(self.bob.receive_datagram(&pkt.bytes, self.now));
                    }
                    NodeId::Proxy => {
                        if let Ok(msg) = SipMessage::parse(&pkt.bytes) {
                            let events = self.proxy.receive_message(msg, self.now);
                            self.handle_proxy_events(events);
                        }
                    }
                }
            }

            alice_events.extend(self.alice.handle_timeout(self.now));
            bob_events.extend(self.bob.handle_timeout(self.now));
            let proxy_timeouts = self.proxy.handle_timeout(self.now);
            self.handle_proxy_events(proxy_timeouts);
        }

        self.flush_outbound();
        alice_events.extend(self.alice.drain_events());
        bob_events.extend(self.bob.drain_events());
        (alice_events, bob_events)
    }

    fn handle_proxy_events(&mut self, events: Vec<TransactionEvent>) {
        for ev in events {
            if let TransactionEvent::ServerRequest { tx_id, request } = ev {
                if request.method == Method::Register {
                    self.handle_registrar(&tx_id, &request);
                } else if request.method == Method::Invite {
                    let cid = request.call_id().unwrap().to_string();
                    self.inbound_branches.insert(
                        (cid.clone(), request.top_via().unwrap().branch.unwrap()),
                        tx_id.clone(),
                    );
                    self.proxy_dialogs.insert(cid, (NodeId::Alice, NodeId::Bob));

                    // Forward direct to Bob's contact if registered, else bob's IP.
                    let target_contact = self
                        .registered_contacts
                        .get("bob")
                        .cloned()
                        .unwrap_or_else(|| SipUri::parse("sip:bob@10.0.0.2:5062").unwrap());
                    let mut fwd = request.clone();
                    fwd.uri = target_contact;
                    // Simple B2BUA/stateless proxy pass-through for INVITE test: deliver straight to Bob
                    let _ = self.proxy.send_server_response(
                        &tx_id,
                        request.create_response(100, "Trying").unwrap(),
                        self.now,
                    );
                    self.schedule(NodeId::Bob, fwd.to_bytes());
                } else if request.method == Method::Cancel {
                    let _ = self.proxy.send_server_response(
                        &tx_id,
                        request.create_response(200, "OK").unwrap(),
                        self.now,
                    );
                    self.schedule(NodeId::Bob, request.to_bytes());
                }
            }
        }
    }

    fn handle_registrar(&mut self, tx_id: &TransactionId, req: &bmsip_core::sip::SipRequest) {
        let user = req.from().unwrap().uri.user.unwrap_or_default();
        let expected_pw = if user == "alice" {
            "alice-pw"
        } else {
            "bob-pw"
        };

        let authorized = req
            .headers
            .get("Authorization")
            .is_some_and(|hdr| verify_md5_auth(hdr, &req.method, &user, expected_pw));

        if !authorized {
            let mut r401 = req.create_response(401, "Unauthorized").unwrap();
            r401.headers.set(
                "WWW-Authenticate",
                "Digest realm=\"pbx.local\", nonce=\"sim-nonce-1\", algorithm=MD5, qop=\"auth\"",
            );
            let _ = self.proxy.send_server_response(tx_id, r401, self.now);
            return;
        }

        let exp = req
            .headers
            .get("Expires")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(300);

        if exp == 0 {
            self.unregister_count += 1;
            self.registered_contacts.remove(&user);
        } else {
            self.register_count += 1;
            if let Ok(Some(c)) = req.contact() {
                self.registered_contacts.insert(user, c.uri);
            }
        }

        let mut r200 = req.create_response(200, "OK").unwrap();
        if let Some(c) = req.headers.get("Contact") {
            r200.headers.set("Contact", format!("{c};expires={exp}"));
        }
        r200.headers.set("Expires", exp.to_string());
        let _ = self.proxy.send_server_response(tx_id, r200, self.now);
    }
}

fn verify_md5_auth(header: &str, method: &Method, user: &str, password: &str) -> bool {
    let mut nonce = String::new();
    let mut uri = String::new();
    let mut nc = String::new();
    let mut cnonce = String::new();
    let mut resp = String::new();

    for part in header.trim_start_matches("Digest ").split(',') {
        let p = part.trim();
        if let Some((k, v)) = p.split_once('=') {
            let val = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "nonce" => nonce = val,
                "uri" => uri = val,
                "nc" => nc = val,
                "cnonce" => cnonce = val,
                "response" => resp = val,
                _ => {}
            }
        }
    }
    let ha1 = md5_hex(format!("{user}:pbx.local:{password}").as_bytes());
    let ha2 = md5_hex(format!("{}:{uri}", method.as_str()).as_bytes());
    let expected = md5_hex(format!("{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}").as_bytes());
    resp == expected
}

#[test]
fn registration_with_digest_challenge_auto_refresh_and_unregister() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(
        t0,
        NetworkPolicy {
            loss_percent: 25,
            duplicate_percent: 20,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(25),
        },
        101,
    );

    cluster.alice.register(cluster.now).unwrap();
    let (events, _) = cluster.step_until(100, Some(t0 + Duration::from_secs(60)));
    assert!(matches!(
        cluster.alice.registration_state(),
        RegistrationState::Registered {
            expires_secs: 300,
            ..
        }
    ));
    assert!(events.iter().any(|e| matches!(
        e,
        UaEvent::RegistrationChanged(RegistrationState::Registered { .. })
    )));
    assert_eq!(cluster.register_count, 1);

    // Advance virtual clock across 80% of 300 s (240 s) to verify automatic refresh REGISTER.
    let (refresh_events, _) = cluster.step_until(200, Some(t0 + Duration::from_secs(260)));
    assert_eq!(cluster.register_count, 2);
    assert!(refresh_events.iter().any(|e| matches!(
        e,
        UaEvent::RegistrationChanged(RegistrationState::Registered { .. })
    )));

    cluster.alice.unregister(cluster.now).unwrap();
    let _ = cluster.step_until(100, Some(cluster.now + Duration::from_secs(30)));
    assert_eq!(
        cluster.alice.registration_state(),
        &RegistrationState::Unregistered
    );
    assert_eq!(cluster.unregister_count, 1);
}

#[test]
fn two_party_call_establish_and_bye_over_lossy_network() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(
        t0,
        NetworkPolicy {
            loss_percent: 30,
            duplicate_percent: 25,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(30),
        },
        777,
    );

    let alice_call_id = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40000,
            cluster.now,
        )
        .unwrap();

    let mut bob_ringed = false;
    let mut bob_answered = false;
    let mut alice_established = false;
    let mut bob_established = false;
    let mut alice_terminated = false;
    let mut bob_terminated = false;

    for _ in 0..40 {
        let (a_ev, b_ev) = cluster.step_until(5, None);
        for ev in b_ev {
            match ev {
                UaEvent::IncomingCall { call_id, .. } if !bob_ringed => {
                    bob_ringed = true;
                    cluster.bob.ring(&call_id, cluster.now).unwrap();
                }
                UaEvent::CallEstablished { .. } => {
                    bob_established = true;
                }
                UaEvent::CallTerminated { .. } => {
                    bob_terminated = true;
                }
                _ => {}
            }
        }
        if bob_ringed && !bob_answered {
            bob_answered = true;
            cluster
                .bob
                .answer(&alice_call_id, 50000, cluster.now)
                .unwrap();
        }
        for ev in a_ev {
            match ev {
                UaEvent::CallEstablished {
                    call_id,
                    negotiated_codecs,
                    ..
                } => {
                    assert_eq!(call_id, alice_call_id);
                    assert!(!negotiated_codecs.is_empty());
                    alice_established = true;
                }
                UaEvent::CallTerminated { call_id, .. } => {
                    assert_eq!(call_id, alice_call_id);
                    alice_terminated = true;
                }
                _ => {}
            }
        }
        if alice_established
            && bob_established
            && cluster.bob.call_state(&alice_call_id) == Some(CallState::Established)
        {
            cluster.bob.hangup(&alice_call_id, cluster.now).unwrap();
            break;
        }
    }

    let (a_tail, b_tail) = cluster.step_until(100, None);
    for ev in a_tail {
        if matches!(ev, UaEvent::CallTerminated { .. }) {
            alice_terminated = true;
        }
    }
    for ev in b_tail {
        if matches!(ev, UaEvent::CallTerminated { .. }) {
            bob_terminated = true;
        }
    }

    assert!(alice_established);
    assert!(bob_established);
    assert!(alice_terminated);
    assert!(bob_terminated);
    assert_eq!(cluster.alice.call_state(&alice_call_id), None);
    assert_eq!(cluster.bob.call_state(&alice_call_id), None);
}

#[test]
fn outbound_cancel_after_ringing_and_before_provisional() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, NetworkPolicy::default(), 55);

    // Case 1: hangup while still in Calling -> CANCEL deferred until 180 Ringing arrives.
    let call_early = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40010,
            cluster.now,
        )
        .unwrap();
    assert_eq!(
        cluster.alice.call_state(&call_early),
        Some(CallState::Calling)
    );
    cluster.alice.hangup(&call_early, cluster.now).unwrap();
    assert_eq!(
        cluster.alice.call_state(&call_early),
        Some(CallState::Cancelling)
    );

    let mut early_terminated_alice = false;
    let mut early_terminated_bob = false;
    for _ in 0..40 {
        let (a_ev, b_ev) = cluster.step_until(1, None);
        for ev in b_ev {
            if let UaEvent::IncomingCall { call_id, .. } = ev {
                if cluster.bob.call_state(&call_id).is_some() {
                    cluster.bob.ring(&call_id, cluster.now).unwrap();
                }
            } else if matches!(
                ev,
                UaEvent::CallTerminated {
                    status_code: Some(487),
                    ..
                }
            ) {
                early_terminated_bob = true;
            }
        }
        for ev in a_ev {
            if matches!(
                ev,
                UaEvent::CallTerminated {
                    status_code: Some(487),
                    ..
                }
            ) {
                early_terminated_alice = true;
            }
        }
        if early_terminated_alice && early_terminated_bob {
            break;
        }
    }
    assert!(early_terminated_alice);
    assert!(early_terminated_bob);

    // Case 2: hangup after 180 Ringing -> immediate CANCEL.
    let call_ringing = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40012,
            cluster.now,
        )
        .unwrap();
    let mut alice_saw_ringing = false;
    let mut ringing_cancelled_alice = false;
    let mut ringing_cancelled_bob = false;

    for _ in 0..40 {
        let (a_ev, b_ev) = cluster.step_until(1, None);
        for ev in b_ev {
            if let UaEvent::IncomingCall { call_id, .. } = ev {
                cluster.bob.ring(&call_id, cluster.now).unwrap();
            } else if matches!(
                ev,
                UaEvent::CallTerminated {
                    status_code: Some(487),
                    ..
                }
            ) {
                ringing_cancelled_bob = true;
            }
        }
        for ev in a_ev {
            if matches!(ev, UaEvent::CallRinging { .. }) && !alice_saw_ringing {
                alice_saw_ringing = true;
                cluster.alice.hangup(&call_ringing, cluster.now).unwrap();
            } else if matches!(
                ev,
                UaEvent::CallTerminated {
                    status_code: Some(487),
                    ..
                }
            ) {
                ringing_cancelled_alice = true;
            }
        }
        if ringing_cancelled_alice && ringing_cancelled_bob {
            break;
        }
    }
    assert!(alice_saw_ringing);
    assert!(ringing_cancelled_alice);
    assert!(ringing_cancelled_bob);
}

#[test]
fn mid_call_network_handover_triggers_register_and_reinvite() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, NetworkPolicy::default(), 88);

    cluster.alice.register(cluster.now).unwrap();
    let _ = cluster.step_until(50, Some(t0 + Duration::from_secs(10)));
    assert_eq!(cluster.register_count, 1);

    let cid = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40020,
            cluster.now,
        )
        .unwrap();

    for _ in 0..30 {
        let (_, b_ev) = cluster.step_until(1, None);
        for ev in b_ev {
            if let UaEvent::IncomingCall { call_id, .. } = ev {
                cluster.bob.answer(&call_id, 50020, cluster.now).unwrap();
            }
        }
        if cluster.alice.call_state(&cid) == Some(CallState::Established)
            && cluster.bob.call_state(&cid) == Some(CallState::Established)
        {
            break;
        }
    }
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Established));

    cluster
        .alice
        .notify_network_changed("10.0.0.99", 5064, cluster.now)
        .unwrap();
    let (a_ev, b_ev) = cluster.step_until(80, Some(cluster.now + Duration::from_secs(20)));

    assert_eq!(cluster.register_count, 2);
    assert!(a_ev.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated { local_sdp, .. } if local_sdp.connection_ip == "10.0.0.99"
    )));
    assert!(b_ev.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated { remote_sdp, .. } if remote_sdp.connection_ip == "10.0.0.99"
    )));
}

#[test]
fn handles_inbound_options_keepalive() {
    let t0 = Instant::now();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        SipUri::parse("sip:pbx.local").unwrap(),
        "10.0.0.1",
        5060,
    ));

    let raw = b"OPTIONS sip:alice@10.0.0.1:5060 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.10:5060;branch=z9hG4bKopt1\r\n\
        From: <sip:asterisk@10.0.0.10>;tag=ast1\r\n\
        To: <sip:alice@10.0.0.1>\r\n\
        Call-ID: opt-keepalive-1\r\n\
        CSeq: 1 OPTIONS\r\n\
        Content-Length: 0\r\n\r\n";

    let events = alice.receive_datagram(raw, t0);
    assert!(events.is_empty());
    let outbound = alice.poll_transmit();
    assert_eq!(outbound.len(), 1);
    let resp = match SipMessage::parse(&outbound[0]).unwrap() {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected response"),
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(
        NameAddr::parse(resp.headers.get("From").unwrap())
            .unwrap()
            .tag
            .as_deref(),
        Some("ast1")
    );
}

#[test]
fn answer_does_not_duplicate_record_route_headers() {
    let t0 = Instant::now();
    let mut bob = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        SipUri::parse("sip:pbx.local:5060").unwrap(),
        "10.0.0.2",
        5062,
    ));

    let sdp = "v=0\r\n\
        o=alice 1 1 IN IP4 10.0.0.1\r\n\
        s=test\r\n\
        c=IN IP4 10.0.0.1\r\n\
        t=0 0\r\n\
        m=audio 40000 RTP/AVP 0\r\n\
        a=rtpmap:0 PCMU/8000\r\n";
    let invite = format!(
        "INVITE sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK-rr-1\r\n\
         Record-Route: <sip:10.0.0.5:5060;lr>\r\n\
         Record-Route: <sip:10.0.0.6:5060;lr>\r\n\
         From: <sip:alice@pbx.local>;tag=a1\r\n\
         To: <sip:bob@pbx.local>\r\n\
         Call-ID: rr-test-1@10.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@10.0.0.1:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{sdp}",
        sdp.len()
    );

    let evs = bob.receive_datagram(invite.as_bytes(), t0);
    assert!(evs.iter().any(
        |e| matches!(e, UaEvent::IncomingCall { call_id, .. } if call_id == "rr-test-1@10.0.0.1")
    ));
    let _ = bob.poll_transmit(); // drain 100 Trying

    bob.answer("rr-test-1@10.0.0.1", 50000, t0).unwrap();
    let out = bob.poll_transmit();
    assert_eq!(out.len(), 1);
    let resp = match SipMessage::parse(&out[0]).unwrap() {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected 200 OK"),
    };
    assert_eq!(resp.status_code, 200);
    assert_eq!(resp.headers.get_all("Record-Route").len(), 2);
}

#[test]
fn reinvite_glare_returns_491_and_out_of_order_cseq_returns_500() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, NetworkPolicy::default(), 99);

    let cid = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40040,
            cluster.now,
        )
        .unwrap();

    for _ in 0..30 {
        let (_, b_ev) = cluster.step_until(1, None);
        for ev in b_ev {
            if let UaEvent::IncomingCall { call_id, .. } = ev {
                cluster.bob.answer(&call_id, 50040, cluster.now).unwrap();
            }
        }
        if cluster.alice.call_state(&cid) == Some(CallState::Established)
            && cluster.bob.call_state(&cid) == Some(CallState::Established)
        {
            break;
        }
    }
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Established));
    let dialog = cluster.alice.dialog_id(&cid).unwrap();

    // Put Alice into ReInviting state (outbound re-INVITE pending).
    cluster
        .alice
        .reinvite(&cid, "10.0.0.1", 40042, cluster.now)
        .unwrap();
    let _ = cluster.alice.poll_transmit();
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::ReInviting));

    // Inject simultaneous inbound re-INVITE (glare) from Bob -> RFC 3261 §14.2 requires 491 Request Pending.
    let sdp = "v=0\r\n\
        o=bob 1 2 IN IP4 10.0.0.2\r\n\
        s=bmsip\r\n\
        c=IN IP4 10.0.0.2\r\n\
        t=0 0\r\n\
        m=audio 50042 RTP/AVP 0\r\n\
        a=rtpmap:0 PCMU/8000\r\n";
    let glare_reinvite = format!(
        "INVITE sip:alice@10.0.0.1:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.2:5062;branch=z9hG4bK-glare-1\r\n\
         From: <sip:bob@10.0.0.2:5062>;tag={}\r\n\
         To: <sip:alice@pbx.local>;tag={}\r\n\
         Call-ID: {cid}\r\n\
         CSeq: 10 INVITE\r\n\
         Contact: <sip:bob@10.0.0.2:5062>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{sdp}",
        dialog.remote_tag,
        dialog.local_tag,
        sdp.len()
    );
    let _ = cluster
        .alice
        .receive_datagram(glare_reinvite.as_bytes(), cluster.now);
    let glare_out = cluster.alice.poll_transmit();
    assert_eq!(glare_out.len(), 1);
    let glare_resp = match SipMessage::parse(&glare_out[0]).unwrap() {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected 491 response"),
    };
    assert_eq!(glare_resp.status_code, 491);
    // Call must remain alive in ReInviting state (not torn down).
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::ReInviting));

    // Inject an out-of-order BYE with lower CSeq (9 <= 10) -> RFC 3261 §12.2.2 requires 500 and keeps call alive.
    let stale_bye = format!(
        "BYE sip:alice@10.0.0.1:5060 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.2:5062;branch=z9hG4bK-old-bye\r\n\
         From: <sip:bob@10.0.0.2:5062>;tag={}\r\n\
         To: <sip:alice@pbx.local>;tag={}\r\n\
         Call-ID: {cid}\r\n\
         CSeq: 9 BYE\r\n\
         Content-Length: 0\r\n\r\n",
        dialog.remote_tag, dialog.local_tag
    );
    let _ = cluster
        .alice
        .receive_datagram(stale_bye.as_bytes(), cluster.now);
    let bye_out = cluster.alice.poll_transmit();
    assert_eq!(bye_out.len(), 1);
    let bye_resp = match SipMessage::parse(&bye_out[0]).unwrap() {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected 500 response"),
    };
    assert_eq!(bye_resp.status_code, 500);
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::ReInviting));
}

#[test]
fn instance_seed_prevents_call_id_and_tag_collisions_on_same_port() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut ua1 = UserAgent::new(
        UaConfig::new(
            "alice",
            "pw",
            "pbx.local",
            registrar.clone(),
            "10.0.0.1",
            5060,
        )
        .with_instance_seed(0x1111_2222),
    );
    let mut ua2 = UserAgent::new(
        UaConfig::new("alice", "pw", "pbx.local", registrar, "10.0.0.1", 5060)
            .with_instance_seed(0x3333_4444),
    );

    ua1.register(t0).unwrap();
    ua2.register(t0).unwrap();
    let reg1 = match SipMessage::parse(&ua1.poll_transmit()[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER"),
    };
    let reg2 = match SipMessage::parse(&ua2.poll_transmit()[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER"),
    };
    assert_ne!(reg1.call_id().unwrap(), reg2.call_id().unwrap());
    assert_ne!(reg1.from().unwrap().tag, reg2.from().unwrap().tag);
    assert_ne!(
        reg1.top_via().unwrap().branch,
        reg2.top_via().unwrap().branch
    );

    let c1 = ua1
        .dial(SipUri::parse("sip:bob@pbx.local").unwrap(), 40000, t0)
        .unwrap();
    let c2 = ua2
        .dial(SipUri::parse("sip:bob@pbx.local").unwrap(), 40000, t0)
        .unwrap();
    assert_ne!(c1, c2);
}

#[test]
fn digest_auth_retries_on_stale_nonce_rotation_and_stops_on_bad_password() {
    let t0 = Instant::now();
    let mut ua = UserAgent::new(UaConfig::new(
        "alice",
        "alice-pw",
        "pbx.local",
        SipUri::parse("sip:pbx.local:5060").unwrap(),
        "10.0.0.1",
        5060,
    ));

    ua.register(t0).unwrap();
    let req1 = match SipMessage::parse(&ua.poll_transmit()[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER 1"),
    };

    // First 401 challenge (stale=false).
    let mut c1 = req1.create_response(401, "Unauthorized").unwrap();
    c1.headers.set(
        "WWW-Authenticate",
        "Digest realm=\"pbx.local\", nonce=\"nonce-old\", algorithm=MD5, qop=\"auth\"",
    );
    let _ = ua.receive_datagram(&c1.to_bytes(), t0);
    let req2 = match SipMessage::parse(&ua.poll_transmit()[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER 2"),
    };
    assert!(req2.headers.get("Authorization").is_some());

    // Second 401 challenge with stale=true (nonce rotated) -> UA must retry with fresh nonce.
    let mut c2 = req2.create_response(401, "Unauthorized").unwrap();
    c2.headers.set(
        "WWW-Authenticate",
        "Digest realm=\"pbx.local\", nonce=\"nonce-fresh\", algorithm=MD5, qop=\"auth\", stale=true",
    );
    let _ = ua.receive_datagram(&c2.to_bytes(), t0);
    let out3 = ua.poll_transmit();
    assert_eq!(out3.len(), 1, "expected retry after stale=true challenge");
    let req3 = match SipMessage::parse(&out3[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER 3"),
    };
    assert!(req3
        .headers
        .get("Authorization")
        .unwrap()
        .contains("nonce=\"nonce-fresh\""));

    // Multi-Contact 200 OK -> must match our local contact's expires (180), not another device's (60).
    let mut ok = req3.create_response(200, "OK").unwrap();
    ok.headers.add(
        "Contact",
        "<sip:alice@10.9.9.9:5060;transport=udp>;expires=60, <sip:alice@10.0.0.1:5060;transport=udp>;expires=180",
    );
    ok.headers.set("Expires", "300");
    let _ = ua.receive_datagram(&ok.to_bytes(), t0);
    assert!(matches!(
        ua.registration_state(),
        RegistrationState::Registered {
            expires_secs: 180,
            ..
        }
    ));

    // Verify non-stale second 401 fails immediately without retrying.
    ua.register(t0 + Duration::from_secs(1)).unwrap();
    let r_a = match SipMessage::parse(&ua.poll_transmit()[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER"),
    };
    let mut bad1 = r_a.create_response(401, "Unauthorized").unwrap();
    bad1.headers.set(
        "WWW-Authenticate",
        "Digest realm=\"pbx.local\", nonce=\"n1\", algorithm=MD5, qop=\"auth\"",
    );
    let _ = ua.receive_datagram(&bad1.to_bytes(), t0 + Duration::from_secs(1));
    let r_b = match SipMessage::parse(&ua.poll_transmit()[0]).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected retried REGISTER"),
    };
    let mut bad2 = r_b.create_response(401, "Unauthorized").unwrap();
    bad2.headers.set(
        "WWW-Authenticate",
        "Digest realm=\"pbx.local\", nonce=\"n2\", algorithm=MD5, qop=\"auth\", stale=false",
    );
    let _ = ua.receive_datagram(&bad2.to_bytes(), t0 + Duration::from_secs(1));
    assert!(ua.poll_transmit().is_empty());
    assert!(matches!(
        ua.registration_state(),
        RegistrationState::Failed {
            status_code: Some(401),
            ..
        }
    ));
}

#[test]
fn answer_without_sdp_sends_488_and_clears_call() {
    let t0 = Instant::now();
    let mut bob = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        SipUri::parse("sip:pbx.local:5060").unwrap(),
        "10.0.0.2",
        5062,
    ));
    let invite_bad_sdp = b"INVITE sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-badsdp-1\r\n\
        From: <sip:alice@pbx.local>;tag=a9\r\n\
        To: <sip:bob@pbx.local>\r\n\
        Call-ID: badsdp-call-1\r\n\
        CSeq: 1 INVITE\r\n\
        Contact: <sip:alice@10.0.0.1:5060>\r\n\
        Content-Type: application/sdp\r\n\
        Content-Length: 10\r\n\r\nnot-an-sdp";

    let _ = bob.receive_datagram(invite_bad_sdp, t0);
    let _ = bob.poll_transmit(); // drain 100 Trying

    assert!(bob.answer("badsdp-call-1", 50000, t0).is_err());
    assert_eq!(bob.call_state("badsdp-call-1"), None);
    let out = bob.poll_transmit();
    assert_eq!(out.len(), 1);
    let resp = match SipMessage::parse(&out[0]).unwrap() {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected 488 response"),
    };
    assert_eq!(resp.status_code, 488);

    // Delayed SDP offer on bodyless initial INVITE + bodyless re-INVITE (RFC 3261 §13.2.1 / §14.1).
    let invite_no_sdp = b"INVITE sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-nosdp-1\r\n\
        From: <sip:alice@pbx.local>;tag=a10\r\n\
        To: <sip:bob@pbx.local>\r\n\
        Call-ID: delayed-offer-1\r\n\
        CSeq: 1 INVITE\r\n\
        Contact: <sip:alice@10.0.0.1:5060>\r\n\
        Content-Length: 0\r\n\r\n";
    let _ = bob.receive_datagram(invite_no_sdp, t0);
    let _ = bob.poll_transmit(); // 100 Trying
    let _ = bob.drain_events();

    bob.answer("delayed-offer-1", 50000, t0).unwrap();
    let r200 = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 200 OK offer"),
    };
    assert_eq!(r200.status_code, 200);
    let offer_sdp = SdpSession::parse(std::str::from_utf8(&r200.body).unwrap()).unwrap();
    assert_eq!(offer_sdp.audio_port, 50000);
    // CallEstablished is held until ACK completes offer/answer.
    assert!(bob.drain_events().is_empty());

    let to_hdr = r200.headers.get("To").unwrap().to_string();
    let answer_sdp = SdpSession::new("alice", "1", "10.0.0.1", 40000, vec![RtpCodec::pcmu()]);
    let mut ack = SipRequest::new(Method::Ack, SipUri::parse("sip:bob@10.0.0.2:5062").unwrap())
        .with_body("application/sdp", answer_sdp.to_string().into_bytes());
    ack.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-1");
    ack.headers.set("From", "<sip:alice@pbx.local>;tag=a10");
    ack.headers.set("To", to_hdr.clone());
    ack.headers.set("Call-ID", "delayed-offer-1");
    ack.headers.set("CSeq", "1 ACK");
    let ack_evs = bob.receive_datagram(&ack.to_bytes(), t0 + Duration::from_millis(20));
    assert!(ack_evs.iter().any(|e| matches!(
        e,
        UaEvent::CallEstablished { call_id, remote_sdp, .. }
            if call_id == "delayed-offer-1" && remote_sdp.audio_port == 40000
    )));

    // Bodyless re-INVITE -> 200 OK SDP offer -> ACK SDP answer -> CallMediaUpdated.
    let mut reinv = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    reinv
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reinv-1");
    reinv.headers.set("From", "<sip:alice@pbx.local>;tag=a10");
    reinv.headers.set("To", to_hdr.clone());
    reinv.headers.set("Call-ID", "delayed-offer-1");
    reinv.headers.set("CSeq", "2 INVITE");
    let _ = bob.receive_datagram(&reinv.to_bytes(), t0 + Duration::from_millis(40));
    let re200 = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 200 OK to bodyless re-INVITE"),
    };
    assert_eq!(re200.status_code, 200);
    assert!(!re200.body.is_empty());

    let mut reack = SipRequest::new(Method::Ack, SipUri::parse("sip:bob@10.0.0.2:5062").unwrap())
        .with_body(
            "application/sdp",
            SdpSession::new("alice", "1", "10.0.0.1", 40002, vec![RtpCodec::pcma()])
                .to_string()
                .into_bytes(),
        );
    reack
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reack-1");
    reack.headers.set("From", "<sip:alice@pbx.local>;tag=a10");
    reack.headers.set("To", to_hdr);
    reack.headers.set("Call-ID", "delayed-offer-1");
    reack.headers.set("CSeq", "2 ACK");
    let re_evs = bob.receive_datagram(&reack.to_bytes(), t0 + Duration::from_millis(60));
    assert!(re_evs.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated { call_id, remote_sdp, .. }
            if call_id == "delayed-offer-1" && remote_sdp.audio_port == 40002
    )));

    // Negative check: delayed-offer ACK missing SDP terminates the call cleanly with BYE Reason 488.
    let mut bad_inv = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    bad_inv
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-delay-bad");
    bad_inv.headers.set("From", "<sip:alice@pbx.local>;tag=a11");
    bad_inv.headers.set("To", "<sip:bob@pbx.local>");
    bad_inv.headers.set("Call-ID", "delayed-offer-bad");
    bad_inv.headers.set("CSeq", "1 INVITE");
    let _ = bob.receive_datagram(&bad_inv.to_bytes(), t0 + Duration::from_millis(80));
    let _ = bob.poll_transmit();
    bob.answer("delayed-offer-bad", 50004, t0 + Duration::from_millis(90))
        .unwrap();
    let bad_ok = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 200 OK offer on delayed-offer-bad"),
    };
    let bad_to = bad_ok.headers.get("To").unwrap().to_string();

    let mut bad_ack = SipRequest::new(Method::Ack, SipUri::parse("sip:bob@10.0.0.2:5062").unwrap());
    bad_ack
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-bad");
    bad_ack.headers.set("From", "<sip:alice@pbx.local>;tag=a11");
    bad_ack.headers.set("To", bad_to);
    bad_ack.headers.set("Call-ID", "delayed-offer-bad");
    bad_ack.headers.set("CSeq", "1 ACK");
    let bad_evs = bob.receive_datagram(&bad_ack.to_bytes(), t0 + Duration::from_millis(100));
    assert!(bad_evs.iter().any(|e| matches!(
        e,
        UaEvent::CallTerminated { call_id, status_code: Some(488), .. }
            if call_id == "delayed-offer-bad"
    )));
    let bad_bye = bob.poll_transmit();
    assert!(bad_bye.iter().any(|b| matches!(
        SipMessage::parse(b),
        Ok(SipMessage::Request(r))
            if r.method == Method::Bye
                && r.headers
                    .get("Reason")
                    .is_some_and(|v| v.contains("488"))
    )));
}

fn establish_clean_cluster_call(
    cluster: &mut MiniSipCluster,
    alice_rtp: u16,
    bob_rtp: u16,
) -> (String, Vec<UaEvent>, Vec<UaEvent>) {
    let cid = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            alice_rtp,
            cluster.now,
        )
        .unwrap();

    let mut all_alice = Vec::new();
    let mut all_bob = Vec::new();
    let mut bob_answered = false;
    let mut alice_est = false;
    let mut bob_est = false;

    for _ in 0..40 {
        let (a_ev, b_ev) = cluster.step_until(5, None);
        for ev in &b_ev {
            if let UaEvent::IncomingCall { call_id, .. } = ev {
                if !bob_answered {
                    bob_answered = true;
                    cluster.bob.answer(call_id, bob_rtp, cluster.now).unwrap();
                }
            }
            if matches!(ev, UaEvent::CallEstablished { .. }) {
                bob_est = true;
            }
        }
        for ev in &a_ev {
            if matches!(ev, UaEvent::CallEstablished { .. }) {
                alice_est = true;
            }
        }
        all_alice.extend(a_ev);
        all_bob.extend(b_ev);
        if alice_est && bob_est {
            break;
        }
    }
    assert!(alice_est && bob_est, "call failed to establish");
    (cid, all_alice, all_bob)
}

fn clean_policy() -> NetworkPolicy {
    NetworkPolicy {
        loss_percent: 0,
        duplicate_percent: 0,
        min_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(5),
    }
}

#[test]
fn call_hold_and_resume_updates_sdp_direction_and_emits_events() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, clean_policy(), 11);
    let (cid, _, _) = establish_clean_cluster_call(&mut cluster, 40000, 50000);

    cluster.alice.hold(&cid, cluster.now).unwrap();
    assert_eq!(cluster.alice.hold_state(&cid), Some((true, false)));

    let (a_hold, b_hold) = cluster.step_until(30, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_hold.iter().any(|e| matches!(
        e,
        UaEvent::CallHoldChanged {
            local_hold: true,
            remote_hold: false,
            ..
        }
    )));
    assert!(a_hold.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated {
            local_sdp,
            remote_sdp,
            ..
        } if local_sdp.direction == Direction::SendOnly && remote_sdp.direction == Direction::RecvOnly
    )));
    assert!(b_hold.iter().any(|e| matches!(
        e,
        UaEvent::CallHoldChanged {
            local_hold: false,
            remote_hold: true,
            ..
        }
    )));
    assert!(b_hold.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated {
            local_sdp,
            remote_sdp,
            ..
        } if local_sdp.direction == Direction::RecvOnly && remote_sdp.direction == Direction::SendOnly
    )));
    assert_eq!(cluster.bob.hold_state(&cid), Some((false, true)));

    cluster.alice.resume_call(&cid, cluster.now).unwrap();
    assert_eq!(cluster.alice.hold_state(&cid), Some((false, false)));

    let (a_res, b_res) = cluster.step_until(30, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_res.iter().any(|e| matches!(
        e,
        UaEvent::CallHoldChanged {
            local_hold: false,
            remote_hold: false,
            ..
        }
    )));
    assert!(a_res.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated {
            local_sdp,
            remote_sdp,
            ..
        } if local_sdp.direction == Direction::SendRecv && remote_sdp.direction == Direction::SendRecv
    )));
    assert!(b_res.iter().any(|e| matches!(
        e,
        UaEvent::CallHoldChanged {
            local_hold: false,
            remote_hold: false,
            ..
        }
    )));
    assert_eq!(cluster.bob.hold_state(&cid), Some((false, false)));

    cluster.alice.hangup(&cid, cluster.now).unwrap();
    let (a_end, b_end) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_end
        .iter()
        .any(|e| matches!(e, UaEvent::CallTerminated { .. })));
    assert!(b_end
        .iter()
        .any(|e| matches!(e, UaEvent::CallTerminated { .. })));
}

fn route_target_three(pkt: &[u8]) -> usize {
    match SipMessage::parse(pkt).unwrap() {
        SipMessage::Request(req) => {
            if req.uri.host == "10.0.0.1" {
                0
            } else if req.uri.host == "10.0.0.2" {
                1
            } else {
                2
            }
        }
        SipMessage::Response(resp) => {
            let via = resp.top_via().unwrap();
            if via.sent_by.starts_with("10.0.0.1") {
                0
            } else if via.sent_by.starts_with("10.0.0.2") {
                1
            } else {
                2
            }
        }
    }
}

fn pump_three(
    agents: &mut [&mut UserAgent; 3],
    now: &mut Instant,
    steps: usize,
) -> [Vec<UaEvent>; 3] {
    let mut evs = [Vec::new(), Vec::new(), Vec::new()];
    for _ in 0..steps {
        let mut any = false;
        let mut out = Vec::new();
        for (idx, ua) in agents.iter_mut().enumerate() {
            evs[idx].extend(ua.drain_events());
            for pkt in ua.poll_transmit() {
                any = true;
                let dest = route_target_three(&pkt);
                out.push((dest, pkt));
            }
        }
        for (dest, pkt) in out {
            evs[dest].extend(agents[dest].receive_datagram(&pkt, *now));
        }
        *now += Duration::from_millis(10);
        for (idx, ua) in agents.iter_mut().enumerate() {
            evs[idx].extend(ua.handle_timeout(*now));
        }
        if !any && evs.iter().all(|v| v.is_empty()) {
            // Still drain final transmits if timeouts queued anything.
            let rem: usize = agents.iter_mut().map(|u| u.poll_transmit().len()).sum();
            if rem == 0 {
                break;
            }
        }
    }
    for (idx, ua) in agents.iter_mut().enumerate() {
        evs[idx].extend(ua.drain_events());
    }
    evs
}

#[test]
fn blind_and_attended_transfer_refer_notify_and_invite_replaces() {
    let mut now = Instant::now();
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        reg.clone(),
        "10.0.0.1",
        5060,
    ));
    let mut bob = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        reg.clone(),
        "10.0.0.2",
        5062,
    ));
    let mut carol = UserAgent::new(UaConfig::new(
        "carol",
        "pw",
        "pbx.local",
        reg,
        "10.0.0.3",
        5064,
    ));

    // 1. Alice establishes Call 1 with Bob, and exercises blind REFER + NOTIFY.
    let call_ab = alice
        .dial(SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(), 40000, now)
        .unwrap();
    {
        let mut three = [&mut alice, &mut bob, &mut carol];
        let _ = pump_three(&mut three, &mut now, 10);
    }
    bob.answer(&call_ab, 50000, now).unwrap();
    {
        let mut three = [&mut alice, &mut bob, &mut carol];
        let _ = pump_three(&mut three, &mut now, 10);
    }
    assert_eq!(alice.call_state(&call_ab), Some(CallState::Established));

    alice
        .refer(
            &call_ab,
            SipUri::parse("sip:carol@10.0.0.3:5064").unwrap(),
            now,
        )
        .unwrap();
    let bob_evs = {
        let mut three = [&mut alice, &mut bob, &mut carol];
        pump_three(&mut three, &mut now, 10)[1].clone()
    };
    assert!(bob_evs.iter().any(|e| matches!(
        e,
        UaEvent::CallTransferRequested {
            refer_to,
            replaces: None,
            referred_by: Some(_),
            ..
        } if refer_to.user.as_deref() == Some("carol")
    )));

    bob.notify_refer_status(&call_ab, 180, "Ringing", false, now)
        .unwrap();
    bob.notify_refer_status(&call_ab, 200, "OK", true, now)
        .unwrap();
    let alice_notifies = {
        let mut three = [&mut alice, &mut bob, &mut carol];
        pump_three(&mut three, &mut now, 10)[0].clone()
    };
    assert!(alice_notifies.iter().any(|e| matches!(
        e,
        UaEvent::TransferNotify {
            status_code: 180,
            terminated: false,
            ..
        }
    )));
    assert!(alice_notifies.iter().any(|e| matches!(
        e,
        UaEvent::TransferNotify {
            status_code: 200,
            terminated: true,
            ..
        }
    )));

    // 2. Alice establishes consultation Call 2 with Carol, then initiates attended REFER (?Replaces=).
    let call_ac = alice
        .dial(
            SipUri::parse("sip:carol@10.0.0.3:5064").unwrap(),
            40010,
            now,
        )
        .unwrap();
    {
        let mut three = [&mut alice, &mut bob, &mut carol];
        let _ = pump_three(&mut three, &mut now, 10);
    }
    carol.answer(&call_ac, 51000, now).unwrap();
    {
        let mut three = [&mut alice, &mut bob, &mut carol];
        let _ = pump_three(&mut three, &mut now, 10);
    }
    assert_eq!(alice.call_state(&call_ac), Some(CallState::Established));

    alice.attended_transfer(&call_ab, &call_ac, now).unwrap();
    let bob_att = {
        let mut three = [&mut alice, &mut bob, &mut carol];
        pump_three(&mut three, &mut now, 10)[1].clone()
    };
    let (refer_to, rep) = bob_att
        .iter()
        .find_map(|e| match e {
            UaEvent::CallTransferRequested {
                refer_to,
                replaces: Some(r),
                ..
            } => Some((refer_to.clone(), r.clone())),
            _ => None,
        })
        .expect("attended REFER should carry parsed Replaces");
    assert_eq!(rep.call_id, call_ac);

    // 3. Bob dials Carol with INVITE + Replaces; Carol replaces call_ac and establishes call_bc.
    let call_bc = bob.dial_with_replaces(refer_to, rep, 50020, now).unwrap();
    let (evs_after_inv_a, evs_after_inv_c) = {
        let mut three = [&mut alice, &mut bob, &mut carol];
        let res = pump_three(&mut three, &mut now, 15);
        (res[0].clone(), res[2].clone())
    };
    assert!(evs_after_inv_c.iter().any(|e| matches!(
        e,
        UaEvent::IncomingCall {
            call_id,
            replaces_call_id: Some(old_cid),
            ..
        } if call_id == &call_bc && old_cid == &call_ac
    )));
    assert!(evs_after_inv_a.iter().any(|e| matches!(
        e,
        UaEvent::CallTerminated {
            call_id,
            reason_header: Some(rh),
            ..
        } if call_id == &call_ac && rh.cause == Some(200)
    )));

    carol.answer(&call_bc, 51010, now).unwrap();
    {
        let mut three = [&mut alice, &mut bob, &mut carol];
        let _ = pump_three(&mut three, &mut now, 15);
    }
    assert_eq!(bob.call_state(&call_bc), Some(CallState::Established));
    assert_eq!(carol.call_state(&call_bc), Some(CallState::Established));
}

#[test]
fn early_dialog_prack_100rel_and_update_offer_answer() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, clean_policy(), 23);

    let cid = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40000,
            cluster.now,
        )
        .unwrap();

    let (a_early_1, _) = cluster.step_until(15, Some(cluster.now + Duration::from_secs(1)));
    assert!(!a_early_1
        .iter()
        .any(|e| matches!(e, UaEvent::CallTerminated { .. })));

    let early_sdp = SdpSession::new(
        "bob",
        "1",
        "10.0.0.2",
        50000,
        vec![RtpCodec::pcmu(), RtpCodec::telephone_event(101)],
    );
    let rseq = cluster
        .bob
        .ring_reliable(&cid, 183, "Session Progress", Some(early_sdp), cluster.now)
        .unwrap();
    assert_eq!(rseq, 1);

    let (a_prack, _) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_prack.iter().any(|e| matches!(
        e,
        UaEvent::CallRinging {
            status_code: 183,
            early_sdp: Some(_),
            ..
        }
    )));
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Ringing));

    // Send early-dialog UPDATE updating RTP IP and port prior to 200 OK.
    cluster
        .alice
        .send_update(&cid, Some("10.0.0.99"), Some(41234), cluster.now)
        .unwrap();
    let (a_upd, b_upd) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_upd
        .iter()
        .any(|e| matches!(e, UaEvent::CallMediaUpdated { .. })));
    assert!(b_upd.iter().any(|e| matches!(
        e,
        UaEvent::CallMediaUpdated { remote_sdp, .. }
            if remote_sdp.connection_ip == "10.0.0.99" && remote_sdp.audio_port == 41234
    )));

    cluster.bob.answer(&cid, 50000, cluster.now).unwrap();
    let (a_est, b_est) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_est
        .iter()
        .any(|e| matches!(e, UaEvent::CallEstablished { .. })));
    assert!(b_est
        .iter()
        .any(|e| matches!(e, UaEvent::CallEstablished { .. })));
}

#[test]
fn session_timers_422_min_se_retry_and_automatic_refresh() {
    let t0 = Instant::now();
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut cluster = MiniSipCluster::new(t0, clean_policy(), 37);
    cluster.alice = UserAgent::new(
        UaConfig::new(
            "alice",
            "alice-pw",
            "pbx.local",
            reg.clone(),
            "10.0.0.1",
            5060,
        )
        .with_session_timers(Some(90), 90),
    );
    cluster.bob = UserAgent::new(
        UaConfig::new("bob", "bob-pw", "pbx.local", reg, "10.0.0.2", 5062)
            .with_session_timers(Some(180), 180),
    );

    // Alice offers Session-Expires=90 < Bob Min-SE=180 -> 422 retry bumps to 180 automatically.
    let (cid, _, _) = establish_clean_cluster_call(&mut cluster, 40000, 50000);
    let est_at = cluster.now;
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Established));

    // Advance across multiple 90 s refresh cycles past initial 180 s timeout; keepalive UPDATE keeps call alive.
    let (a_evs, b_evs) = cluster.step_until(120, Some(est_at + Duration::from_secs(280)));
    assert!(cluster.now >= est_at + Duration::from_secs(180));
    assert!(!a_evs
        .iter()
        .any(|e| matches!(e, UaEvent::CallTerminated { .. })));
    assert!(!b_evs
        .iter()
        .any(|e| matches!(e, UaEvent::CallTerminated { .. })));
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Established));
    assert_eq!(cluster.bob.call_state(&cid), Some(CallState::Established));

    // When all refresh packets are dropped, Session-Expires eventually expires with Reason cause=408.
    cluster.policy.loss_percent = 100;
    let (a_exp, b_exp) = cluster.step_until(120, Some(cluster.now + Duration::from_secs(250)));
    assert!(
        b_exp.iter().any(|e| matches!(
            e,
            UaEvent::CallTerminated {
                status_code: Some(408),
                reason_header: Some(rh),
                ..
            } if rh.cause == Some(408)
        )) || a_exp.iter().any(|e| matches!(
            e,
            UaEvent::CallTerminated {
                status_code: Some(408),
                reason_header: Some(rh),
                ..
            } if rh.cause == Some(408)
        )),
        "expected Session-Timers expiry with status 408 and Reason cause=408"
    );
}

#[test]
fn reason_header_and_p_asserted_identity_privacy_roundtrip() {
    let t0 = Instant::now();
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut cluster = MiniSipCluster::new(t0, clean_policy(), 41);
    cluster.alice = UserAgent::new(
        UaConfig::new("alice", "alice-pw", "pbx.local", reg, "10.0.0.1", 5060)
            .with_caller_identity(
                Some(NameAddr::parse("\"Alice Corp\" <sip:+15550100@pbx.local>").unwrap()),
                Some("id".to_string()),
            ),
    );

    let (cid, _, b_init) = establish_clean_cluster_call(&mut cluster, 40000, 50000);
    let identity: Option<CallerIdentity> = b_init.iter().find_map(|e| match e {
        UaEvent::IncomingCall {
            caller_identity, ..
        } => caller_identity.clone(),
        _ => None,
    });
    let identity = identity.expect("expected P-Asserted-Identity + Privacy on IncomingCall");
    assert_eq!(
        identity
            .asserted_identity
            .as_ref()
            .and_then(|a| a.uri.user.as_deref()),
        Some("+15550100")
    );
    assert_eq!(identity.privacy, vec!["id".to_string()]);

    cluster
        .alice
        .hangup_with_reason(
            &cid,
            Some(ReasonHeader::q850(16, "Normal call clearing")),
            cluster.now,
        )
        .unwrap();
    let (_, b_end) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(b_end.iter().any(|e| matches!(
        e,
        UaEvent::CallTerminated {
            reason_header: Some(rh),
            ..
        } if rh.protocol == "Q.850"
            && rh.cause == Some(16)
            && rh.text.as_deref() == Some("Normal call clearing")
    )));
}

#[test]
fn early_media_183_session_progress_negotiates_codecs_and_transitions_to_200_ok() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, clean_policy(), 53);

    let cid = cluster
        .alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
            40000,
            cluster.now,
        )
        .unwrap();
    let (_, b_in) = cluster.step_until(15, Some(cluster.now + Duration::from_secs(1)));
    assert!(b_in
        .iter()
        .any(|e| matches!(e, UaEvent::IncomingCall { call_id, .. } if call_id == &cid)));

    let early_ans = cluster
        .bob
        .ring_early_media(&cid, 183, 50000, false, cluster.now)
        .unwrap();
    assert_eq!(early_ans.audio_port, 50000);
    assert_eq!(cluster.bob.local_rtp_port(&cid), Some(50000));
    assert!(!cluster.bob.negotiated_codecs(&cid).unwrap().is_empty());

    let (a_early, _) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_early.iter().any(|e| matches!(
        e,
        UaEvent::CallRinging {
            status_code: 183,
            early_sdp: Some(sdp),
            ..
        } if sdp.audio_port == 50000
    )));
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Ringing));
    assert_eq!(
        cluster.alice.remote_sdp(&cid).map(|s| s.audio_port),
        Some(50000)
    );
    assert!(!cluster.alice.negotiated_codecs(&cid).unwrap().is_empty());

    // Answer passes 0 so UAS reuses its early-media local RTP port 50000.
    cluster.bob.answer(&cid, 0, cluster.now).unwrap();
    let (a_est, b_est) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(a_est
        .iter()
        .any(|e| matches!(e, UaEvent::CallEstablished { .. })));
    assert!(b_est
        .iter()
        .any(|e| matches!(e, UaEvent::CallEstablished { .. })));
    assert_eq!(cluster.bob.local_rtp_port(&cid), Some(50000));
}

#[test]
fn sip_info_dtmf_relay_and_raw_dtmf_roundtrip_and_invalid_rejection() {
    let t0 = Instant::now();
    let mut cluster = MiniSipCluster::new(t0, clean_policy(), 61);
    let (cid, _, _) = establish_clean_cluster_call(&mut cluster, 40000, 50000);

    // Invalid digit rejected synchronously.
    assert!(cluster
        .alice
        .send_info_dtmf(&cid, 'Z', 160, cluster.now)
        .is_err());

    // Valid RFC 2976 SIP INFO application/dtmf-relay delivery.
    cluster
        .alice
        .send_info_dtmf(&cid, '*', 220, cluster.now)
        .unwrap();
    let (_, b_evs) = cluster.step_until(20, Some(cluster.now + Duration::from_secs(2)));
    assert!(b_evs.iter().any(|e| matches!(
        e,
        UaEvent::DtmfReceived {
            call_id,
            digit: '*',
            duration_ms: 220,
        } if call_id == &cid
    )));

    // Validate inbound raw INFO with `application/dtmf` and reject unsupported MIME types with 415.
    let dlg = cluster.alice.dialog_id(&cid).unwrap();
    let raw_dtmf = format!(
        "INFO sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-raw-info-1\r\n\
         From: <sip:alice@pbx.local>;tag={}\r\n\
         To: <sip:bob@pbx.local>;tag={}\r\n\
         Call-ID: {cid}\r\n\
         CSeq: 90 INFO\r\n\
         Content-Type: application/dtmf\r\n\
         Content-Length: 1\r\n\r\n#",
        dlg.local_tag, dlg.remote_tag
    );
    let raw_evs = cluster
        .bob
        .receive_datagram(raw_dtmf.as_bytes(), cluster.now);
    assert!(raw_evs.iter().any(|e| matches!(
        e,
        UaEvent::DtmfReceived {
            call_id,
            digit: '#',
            duration_ms: 160,
        } if call_id == &cid
    )));
    let ok_wire = cluster.bob.poll_transmit();
    assert_eq!(ok_wire.len(), 1);
    let SipMessage::Response(ok_resp) = SipMessage::parse(&ok_wire[0]).unwrap() else {
        panic!("expected 200 OK response to INFO");
    };
    assert_eq!(ok_resp.status_code, 200);

    let bad_ct = format!(
        "INFO sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-raw-info-2\r\n\
         From: <sip:alice@pbx.local>;tag={}\r\n\
         To: <sip:bob@pbx.local>;tag={}\r\n\
         Call-ID: {cid}\r\n\
         CSeq: 91 INFO\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 2\r\n\r\n{{}}",
        dlg.local_tag, dlg.remote_tag
    );
    let _ = cluster.bob.receive_datagram(bad_ct.as_bytes(), cluster.now);
    let rej_wire = cluster.bob.poll_transmit();
    assert_eq!(rej_wire.len(), 1);
    let SipMessage::Response(rej_resp) = SipMessage::parse(&rej_wire[0]).unwrap() else {
        panic!("expected 415 response to unsupported INFO Content-Type");
    };
    assert_eq!(rej_resp.status_code, 415);
}

#[test]
fn tcp_and_tls_transport_sets_via_contact_and_skips_udp_retransmits() {
    use bmsip_core::sip::SipTransport;

    for (transport, expected_via, expected_param) in [
        (SipTransport::Tcp, "TCP", "tcp"),
        (SipTransport::Tls, "TLS", "tls"),
    ] {
        let t0 = Instant::now();
        let mut ua = UserAgent::new(
            UaConfig::new(
                "alice",
                "secret",
                "pbx.local",
                SipUri::parse("sip:pbx.local:5061").unwrap(),
                "10.0.0.1",
                5061,
            )
            .with_transport(transport),
        );
        assert_eq!(ua.transport(), transport);

        ua.register(t0).unwrap();
        let out = ua.poll_transmit();
        assert_eq!(out.len(), 1);
        let SipMessage::Request(reg) = SipMessage::parse(&out[0]).unwrap() else {
            panic!("expected REGISTER");
        };
        assert_eq!(reg.top_via().unwrap().transport, expected_via);
        assert!(
            reg.headers
                .get("Contact")
                .unwrap()
                .contains(&format!("transport={expected_param}")),
            "Contact missing transport={expected_param}: {:?}",
            reg.headers.get("Contact")
        );

        // Advance well past T1 (500 ms -> 2 s): reliable transports MUST NOT retransmit via Timer E.
        let _ = ua.handle_timeout(t0 + Duration::from_secs(2));
        assert!(
            ua.poll_transmit().is_empty(),
            "reliable transport {transport} must not emit Timer E retransmissions"
        );

        // Verify INVITE also uses the configured Via/Contact transport and skips Timer A retransmits.
        let _cid = ua
            .dial(SipUri::parse("sip:bob@pbx.local:5061").unwrap(), 40000, t0)
            .unwrap();
        let inv_out = ua.poll_transmit();
        assert_eq!(inv_out.len(), 1);
        let SipMessage::Request(inv) = SipMessage::parse(&inv_out[0]).unwrap() else {
            panic!("expected INVITE");
        };
        assert_eq!(inv.top_via().unwrap().transport, expected_via);
        assert!(inv
            .headers
            .get("Contact")
            .unwrap()
            .contains(&format!("transport={expected_param}")));
        let _ = ua.handle_timeout(t0 + Duration::from_secs(2));
        assert!(
            ua.poll_transmit().is_empty(),
            "reliable transport {transport} must not emit Timer A retransmissions"
        );
    }
}

#[test]
fn sdes_srtp_tls_enforcement_crypto_seed_hold_and_dtls_488_rejection() {
    use bmsip_core::sdp::{NegotiatedSrtp, SdpMediaProfile, SrtpMode, SrtpSuite};
    use bmsip_core::sip::SipTransport;

    let t0 = Instant::now();
    let reg_tls = SipUri::parse("sip:pbx.local:5061;transport=tls").unwrap();
    let reg_udp = SipUri::parse("sip:pbx.local:5060").unwrap();

    // 1. SdesRequired over unencrypted UDP is rejected by default (RFC 4568 §8).
    let mut insecure_ua = UserAgent::new(
        UaConfig::new(
            "alice",
            "pw",
            "pbx.local",
            reg_udp.clone(),
            "10.0.0.1",
            5060,
        )
        .with_srtp_mode(SrtpMode::SdesRequired),
    );
    assert!(
        insecure_ua
            .dial(SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(), 40000, t0)
            .is_err(),
        "SdesRequired over plain UDP must be rejected unless allow_insecure_cleartext_sdes is set"
    );

    // 2. SdesOptional over plain UDP must NOT leak a=crypto keys in cleartext SDP.
    let mut opt_udp = UserAgent::new(
        UaConfig::new(
            "alice",
            "pw",
            "pbx.local",
            reg_udp.clone(),
            "10.0.0.1",
            5060,
        )
        .with_srtp_mode(SrtpMode::SdesOptional),
    );
    let _ = opt_udp
        .dial(SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(), 40000, t0)
        .unwrap();
    let opt_inv = String::from_utf8(opt_udp.poll_transmit().remove(0)).unwrap();
    assert!(
        !opt_inv.contains("a=crypto:"),
        "SdesOptional over plain UDP must not emit a=crypto keys in cleartext"
    );

    // 3. SDES-SRTP (`SrtpMode::SdesRequired`) over TLS with independent 256-bit `crypto_seed`s
    //    + mid-call Hold re-INVITE key continuity.
    let mut alice = UserAgent::new(
        UaConfig::new(
            "alice",
            "pw",
            "pbx.local",
            reg_tls.clone(),
            "10.0.0.1",
            5061,
        )
        .with_transport(SipTransport::Tls)
        .with_instance_seed(0x1111)
        .with_crypto_seed([0xAAu8; 32])
        .with_srtp_mode(SrtpMode::SdesRequired),
    );
    let mut bob = UserAgent::new(
        UaConfig::new("bob", "pw", "pbx.local", reg_tls.clone(), "10.0.0.2", 5063)
            .with_transport(SipTransport::Tls)
            .with_instance_seed(0x1111) // Same instance_seed, different crypto_seed -> must produce distinct keys!
            .with_crypto_seed([0xBBu8; 32])
            .with_srtp_mode(SrtpMode::SdesRequired),
    );

    let cid = alice
        .dial(
            SipUri::parse("sip:bob@10.0.0.2:5063;transport=tls").unwrap(),
            40000,
            t0,
        )
        .unwrap();
    let inv_pkt = alice.poll_transmit().remove(0);
    let b_evs = bob.receive_datagram(&inv_pkt, t0);
    let _ = bob.poll_transmit(); // 100 Trying
    assert!(b_evs.iter().any(|e| matches!(
        e,
        UaEvent::IncomingCall {
            remote_sdp: Some(sdp),
            ..
        } if sdp.profile == SdpMediaProfile::RtpSavp && sdp.crypto.len() == 2
    )));

    bob.answer(&cid, 50000, t0).unwrap();
    let _ = bob.drain_events();
    let ok_pkt = bob.poll_transmit().remove(0);
    let a_evs = alice.receive_datagram(&ok_pkt, t0);
    let ack_pkt = alice.poll_transmit().remove(0);
    let _ = bob.receive_datagram(&ack_pkt, t0);
    assert!(a_evs
        .iter()
        .any(|e| matches!(e, UaEvent::CallEstablished { .. })));

    let (a_tx, a_rx) = match alice.negotiated_srtp(&cid).expect("alice SDES") {
        NegotiatedSrtp::Sdes {
            suite,
            local_key_salt,
            remote_key_salt,
        } => {
            assert_eq!(*suite, SrtpSuite::AesCm128HmacSha1_80);
            (*local_key_salt, *remote_key_salt)
        }
    };
    let (b_tx, b_rx) = match bob.negotiated_srtp(&cid).expect("bob SDES") {
        NegotiatedSrtp::Sdes {
            suite,
            local_key_salt,
            remote_key_salt,
        } => {
            assert_eq!(*suite, SrtpSuite::AesCm128HmacSha1_80);
            (*local_key_salt, *remote_key_salt)
        }
    };
    assert_eq!(a_tx, b_rx);
    assert_eq!(b_tx, a_rx);
    assert_ne!(a_tx, b_tx);

    // Mid-call Hold re-INVITE must preserve the exact same SDES master keys (RFC 4568 §6.1.3).
    alice.hold(&cid, t0 + Duration::from_secs(1)).unwrap();
    let _ = alice.drain_events();
    let reinv_pkt = alice.poll_transmit().remove(0);
    let _ = bob.receive_datagram(&reinv_pkt, t0 + Duration::from_secs(1));
    let reinv_ok = bob
        .poll_transmit()
        .into_iter()
        .last()
        .expect("200 OK to re-INVITE");
    let _ = alice.receive_datagram(&reinv_ok, t0 + Duration::from_secs(1));
    let _ = alice.poll_transmit();
    assert_eq!(
        alice.negotiated_srtp(&cid),
        Some(&NegotiatedSrtp::Sdes {
            suite: SrtpSuite::AesCm128HmacSha1_80,
            local_key_salt: a_tx,
            remote_key_salt: a_rx,
        })
    );

    // 4. Incoming DTLS-SRTP (`UDP/TLS/RTP/SAVPF`) offer must be rejected cleanly with 488 Not Acceptable Here.
    let dtls_sdp = "\
        v=0\r\n\
        o=webrtc 99 99 IN IP4 10.0.0.9\r\n\
        s=WebRTC\r\n\
        c=IN IP4 10.0.0.9\r\n\
        t=0 0\r\n\
        m=audio 40100 UDP/TLS/RTP/SAVPF 0\r\n\
        a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11\r\n\
        a=setup:actpass\r\n\
        a=sendrecv\r\n";
    let dtls_inv = format!(
        "INVITE sip:bob@10.0.0.2:5063;transport=tls SIP/2.0\r\n\
         Via: SIP/2.0/TLS 10.0.0.9:5061;branch=z9hG4bKdtls488\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:webrtc@pbx.local>;tag=wtag1\r\n\
         To: <sip:bob@pbx.local>\r\n\
         Call-ID: dtls-reject-call@10.0.0.9\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:webrtc@10.0.0.9:5061;transport=tls>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{dtls_sdp}",
        dtls_sdp.len()
    );
    let _ = bob.receive_datagram(dtls_inv.as_bytes(), t0 + Duration::from_secs(2));
    let _ = bob.poll_transmit(); // 100 Trying
    assert!(bob
        .answer(
            "dtls-reject-call@10.0.0.9",
            50100,
            t0 + Duration::from_secs(2)
        )
        .is_err());
    let resp_488 = String::from_utf8(bob.poll_transmit().remove(0)).unwrap();
    assert!(
        resp_488.starts_with("SIP/2.0 488 "),
        "expected 488 Not Acceptable Here for DTLS-SRTP offer, got: {resp_488}"
    );
}

#[test]
fn p0_rfc6026_accepted_state_absorbs_invite_retransmit_until_timer_l() {
    let t0 = Instant::now();
    let mut uac = TransactionManager::default();
    let mut uas = TransactionManager::default();

    let mut inv = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    inv.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-acc-1");
    inv.headers.set("From", "<sip:alice@pbx.local>;tag=a1");
    inv.headers.set("To", "<sip:bob@pbx.local>");
    inv.headers.set("Call-ID", "ist-accepted-1@10.0.0.1");
    inv.headers.set("CSeq", "1 INVITE");

    let _ = uac.start_client_transaction(inv.clone(), t0).unwrap();
    let wire_inv = uac.poll_transmit().remove(0);

    let evs1 = uas.receive_message(SipMessage::parse(&wire_inv).unwrap(), t0);
    let TransactionEvent::ServerRequest { tx_id, request } = &evs1[0] else {
        panic!("expected initial ServerRequest");
    };
    let mut ok = request.create_response(200, "OK").unwrap();
    ok.headers.set("To", "<sip:bob@pbx.local>;tag=b1");
    let _ = uas.send_server_response(tx_id, ok, t0).unwrap();
    let _ = uas.poll_transmit();
    assert_eq!(uas.active_server_count(), 1);

    // Retransmitted INVITE arriving during Timer L must be absorbed without creating a new ServerRequest.
    let evs_retx = uas.receive_message(
        SipMessage::parse(&wire_inv).unwrap(),
        t0 + Duration::from_secs(1),
    );
    assert!(evs_retx.is_empty());
    assert!(uas.poll_transmit().is_empty());
    assert_eq!(uas.active_server_count(), 1);

    // ACK must emit AckFor2xx and keep IST in Accepted until Timer L (64 * 500ms = 32s).
    let mut ack = SipRequest::new(Method::Ack, SipUri::parse("sip:bob@10.0.0.2:5062").unwrap());
    ack.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-2");
    ack.headers.set("From", "<sip:alice@pbx.local>;tag=a1");
    ack.headers.set("To", "<sip:bob@pbx.local>;tag=b1");
    ack.headers.set("Call-ID", "ist-accepted-1@10.0.0.1");
    ack.headers.set("CSeq", "1 ACK");
    let ack_evs = uas.receive_message(
        SipMessage::parse(&ack.to_bytes()).unwrap(),
        t0 + Duration::from_secs(2),
    );
    assert!(matches!(
        ack_evs.as_slice(),
        [TransactionEvent::AckFor2xx(_)]
    ));
    assert_eq!(uas.active_server_count(), 1);

    let term_evs = uas.handle_timeout(t0 + Duration::from_secs(33));
    assert!(term_evs
        .iter()
        .any(|e| matches!(e, TransactionEvent::TransactionTerminated(_))));
    assert_eq!(uas.active_server_count(), 0);
}

#[test]
fn p0_hangup_sends_cancel_immediately_after_100_trying() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        registrar,
        "10.0.0.1",
        5060,
    ));

    let call_id = alice
        .dial(SipUri::parse("sip:bob@pbx.local").unwrap(), 40000, t0)
        .unwrap();
    let inv_bytes = alice.poll_transmit().remove(0);
    let SipMessage::Request(inv) = SipMessage::parse(&inv_bytes).unwrap() else {
        panic!("expected INVITE");
    };

    let trying = inv.create_response(100, "Trying").unwrap().to_bytes();
    let _ = alice.receive_datagram(&trying, t0 + Duration::from_millis(50));
    let _ = alice.poll_transmit();

    alice
        .hangup(&call_id, t0 + Duration::from_millis(100))
        .unwrap();
    let out = alice.poll_transmit();
    assert_eq!(out.len(), 1);
    let SipMessage::Request(cancel) = SipMessage::parse(&out[0]).unwrap() else {
        panic!("expected CANCEL");
    };
    assert_eq!(cancel.method, Method::Cancel);
    assert_eq!(cancel.call_id().unwrap(), call_id);
}

#[test]
fn p0_bodyless_200_ok_after_early_media_183_transitions_to_established() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        registrar,
        "10.0.0.1",
        5060,
    ));
    let call_id = alice
        .dial(SipUri::parse("sip:bob@pbx.local").unwrap(), 40000, t0)
        .unwrap();
    let inv_bytes = alice.poll_transmit().remove(0);
    let SipMessage::Request(inv) = SipMessage::parse(&inv_bytes).unwrap() else {
        panic!("expected INVITE");
    };

    let early_sdp = SdpSession::new("bob", "55", "10.0.0.2", 50000, vec![RtpCodec::pcmu()]);
    let mut r183 = inv
        .create_response(183, "Session Progress")
        .unwrap()
        .with_body("application/sdp", early_sdp.to_string().into_bytes());
    r183.headers.set("To", "<sip:bob@pbx.local>;tag=b-early");
    r183.headers.set("Contact", "<sip:bob@10.0.0.2:5062>");
    let _ = alice.receive_datagram(&r183.to_bytes(), t0 + Duration::from_millis(20));

    let mut r200 = inv.create_response(200, "OK").unwrap();
    r200.headers.set("To", "<sip:bob@pbx.local>;tag=b-early");
    r200.headers.set("Contact", "<sip:bob@10.0.0.2:5062>");
    let evs = alice.receive_datagram(&r200.to_bytes(), t0 + Duration::from_millis(40));
    assert!(evs
        .iter()
        .any(|e| matches!(e, UaEvent::CallEstablished { call_id: cid, .. } if cid == &call_id)));

    // Calling hangup must now emit BYE cleanly (state == Established).
    alice
        .hangup(&call_id, t0 + Duration::from_millis(60))
        .unwrap();
    let bye_found = alice
        .poll_transmit()
        .into_iter()
        .filter_map(|b| SipMessage::parse(&b).ok())
        .any(|m| matches!(m, SipMessage::Request(r) if r.method == Method::Bye));
    assert!(
        bye_found,
        "expected BYE after bodyless 200 OK established call"
    );
}

#[test]
fn p0_bodyless_200_ok_to_reinvite_recovers_established_state() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        registrar,
        "10.0.0.1",
        5060,
    ));
    let call_id = alice
        .dial(SipUri::parse("sip:bob@pbx.local").unwrap(), 40000, t0)
        .unwrap();
    let inv_bytes = alice.poll_transmit().remove(0);
    let SipMessage::Request(inv) = SipMessage::parse(&inv_bytes).unwrap() else {
        panic!("expected INVITE");
    };
    let ans = SdpSession::new("bob", "1", "10.0.0.2", 50000, vec![RtpCodec::pcmu()]);
    let mut ok1 = inv
        .create_response(200, "OK")
        .unwrap()
        .with_body("application/sdp", ans.to_string().into_bytes());
    ok1.headers.set("To", "<sip:bob@pbx.local>;tag=b1");
    ok1.headers.set("Contact", "<sip:bob@10.0.0.2:5060>");
    let _ = alice.receive_datagram(&ok1.to_bytes(), t0 + Duration::from_millis(10));
    let _ = alice.poll_transmit(); // ACK

    alice
        .hold(&call_id, t0 + Duration::from_millis(20))
        .unwrap();
    assert_eq!(alice.call_state(&call_id), Some(CallState::ReInviting));
    let reinv_bytes = alice.poll_transmit().remove(0);
    let SipMessage::Request(reinv) = SipMessage::parse(&reinv_bytes).unwrap() else {
        panic!("expected re-INVITE");
    };
    let ok2 = reinv.create_response(200, "OK").unwrap(); // bodyless 200 OK to re-INVITE
    let evs = alice.receive_datagram(&ok2.to_bytes(), t0 + Duration::from_millis(30));
    assert_eq!(alice.call_state(&call_id), Some(CallState::Established));
    assert!(evs
        .iter()
        .any(|e| matches!(e, UaEvent::CallMediaUpdated { call_id: cid, .. } if cid == &call_id)));
}

#[test]
fn p0_200_ok_ack_timeout_sends_bye_per_rfc3261() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut bob = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        registrar,
        "10.0.0.2",
        5062,
    ));

    let offer = SdpSession::new("alice", "1", "10.0.0.1", 40000, vec![RtpCodec::pcmu()]);
    let inv = format!(
        "INVITE sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-noack-1\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@pbx.local>;tag=a1\r\n\
         To: <sip:bob@pbx.local>\r\n\
         Call-ID: no-ack-timeout@10.0.0.1\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@10.0.0.1:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{}",
        offer.to_string().len(),
        offer
    );
    let _ = bob.receive_datagram(inv.as_bytes(), t0);
    let _ = bob.poll_transmit(); // 100 Trying
    bob.answer("no-ack-timeout@10.0.0.1", 50000, t0).unwrap();
    let _ = bob.poll_transmit(); // initial 200 OK

    // Wrong CSeq ACK (e.g. CSeq 99 ACK) must NOT clear awaiting_ack.
    let stale_ack = b"ACK sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-wrong\r\n\
        Max-Forwards: 70\r\n\
        From: <sip:alice@pbx.local>;tag=a1\r\n\
        To: <sip:bob@pbx.local>;tag=unexpected\r\n\
        Call-ID: no-ack-timeout@10.0.0.1\r\n\
        CSeq: 99 ACK\r\n\
        Content-Length: 0\r\n\r\n";
    let _ = bob.receive_datagram(stale_ack, t0 + Duration::from_millis(10));

    let mut saw_bye = false;
    let mut saw_term = false;
    for _ in 0..30 {
        let Some(dl) = bob.poll_timeout() else {
            break;
        };
        let evs = bob.handle_timeout(dl);
        for pkt in bob.poll_transmit() {
            if let Ok(SipMessage::Request(r)) = SipMessage::parse(&pkt) {
                if r.method == Method::Bye {
                    saw_bye = true;
                }
            }
        }
        if evs
            .iter()
            .any(|e| matches!(e, UaEvent::CallTerminated { .. }))
        {
            saw_term = true;
            break;
        }
    }
    assert!(
        saw_bye,
        "expected BYE on 200 OK ACK timeout (RFC 3261 §13.3.1.4)"
    );
    assert!(saw_term, "expected CallTerminated on 200 OK ACK timeout");
}

#[test]
fn p0_forked_second_2xx_triggers_ack_and_bye_for_forked_leg() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        registrar,
        "10.0.0.1",
        5060,
    ));

    let call_id = alice
        .dial(SipUri::parse("sip:bob@pbx.local").unwrap(), 40000, t0)
        .unwrap();
    let inv_bytes = alice.poll_transmit().remove(0);
    let SipMessage::Request(inv) = SipMessage::parse(&inv_bytes).unwrap() else {
        panic!("expected INVITE");
    };

    let ans1 = SdpSession::new("bob1", "1", "10.0.0.2", 50000, vec![RtpCodec::pcmu()]);
    let mut r200_1 = inv
        .create_response(200, "OK")
        .unwrap()
        .with_body("application/sdp", ans1.to_string().into_bytes());
    r200_1.headers.set("To", "<sip:bob@pbx.local>;tag=leg1");
    r200_1.headers.set("Contact", "<sip:bob1@10.0.0.2:5060>");
    let _ = alice.receive_datagram(&r200_1.to_bytes(), t0 + Duration::from_millis(10));
    let _ = alice.poll_transmit(); // primary ACK

    let ans2 = SdpSession::new("bob2", "2", "10.0.0.3", 50002, vec![RtpCodec::pcmu()]);
    let mut r200_2 = inv
        .create_response(200, "OK")
        .unwrap()
        .with_body("application/sdp", ans2.to_string().into_bytes());
    r200_2.headers.set("To", "<sip:bob@pbx.local>;tag=leg2");
    r200_2.headers.set("Contact", "<sip:bob2@10.0.0.3:5060>");
    let _ = alice.receive_datagram(&r200_2.to_bytes(), t0 + Duration::from_millis(20));

    let out: Vec<SipRequest> = alice
        .poll_transmit()
        .into_iter()
        .filter_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) => Some(r),
            SipMessage::Response(_) => None,
        })
        .collect();

    assert!(out.iter().any(|r| {
        r.method == Method::Ack
            && r.uri.host == "10.0.0.3"
            && r.to().ok().and_then(|t| t.tag).as_deref() == Some("leg2")
    }));
    assert!(out.iter().any(|r| {
        r.method == Method::Bye
            && r.uri.host == "10.0.0.3"
            && r.to().ok().and_then(|t| t.tag).as_deref() == Some("leg2")
    }));
    assert_eq!(alice.call_state(&call_id), Some(CallState::Established));
}

#[test]
fn p1_tel_uri_stacked_407_401_sha256_preference_and_ack_auth() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut alice = UserAgent::new(UaConfig::new(
        "alice",
        "secretpw",
        "pbx.local",
        registrar,
        "10.0.0.1",
        5060,
    ));

    let call_id = alice
        .dial(SipUri::parse("tel:+1-555-0199").unwrap(), 40000, t0)
        .unwrap();
    let inv1_bytes = alice.poll_transmit().remove(0);
    let SipMessage::Request(inv1) = SipMessage::parse(&inv1_bytes).unwrap() else {
        panic!("expected INVITE");
    };
    assert_eq!(inv1.uri.scheme, bmsip_core::sip::SipScheme::Tel);

    // 1. Proxy sends 407 offering MD5 first and SHA-256 second -> UAC must prefer SHA-256.
    let mut r407 = inv1
        .create_response(407, "Proxy Authentication Required")
        .unwrap();
    r407.headers.add(
        "Proxy-Authenticate",
        "Digest realm=\"proxy\", nonce=\"n1\", algorithm=MD5, qop=\"auth\"",
    );
    r407.headers.add(
        "Proxy-Authenticate",
        "Digest realm=\"proxy\", nonce=\"n2\", algorithm=SHA-256, qop=\"auth\"",
    );
    let _ = alice.receive_datagram(&r407.to_bytes(), t0 + Duration::from_millis(10));
    let inv2_bytes = alice
        .poll_transmit()
        .into_iter()
        .find(|b| matches!(SipMessage::parse(b), Ok(SipMessage::Request(r)) if r.method == Method::Invite))
        .unwrap();
    let SipMessage::Request(inv2) = SipMessage::parse(&inv2_bytes).unwrap() else {
        unreachable!();
    };
    let proxy_hdr = inv2.headers.get("Proxy-Authorization").unwrap().to_string();
    assert!(proxy_hdr.contains("algorithm=SHA-256"));

    // 2. Endpoint also challenges 401 -> retry must retain Proxy-Authorization alongside Authorization.
    let mut r401 = inv2.create_response(401, "Unauthorized").unwrap();
    r401.headers.set(
        "WWW-Authenticate",
        "Digest realm=\"uas\", nonce=\"n3\", algorithm=MD5, qop=\"auth\"",
    );
    let _ = alice.receive_datagram(&r401.to_bytes(), t0 + Duration::from_millis(20));
    let inv3_bytes = alice
        .poll_transmit()
        .into_iter()
        .find(|b| matches!(SipMessage::parse(b), Ok(SipMessage::Request(r)) if r.method == Method::Invite))
        .unwrap();
    let SipMessage::Request(inv3) = SipMessage::parse(&inv3_bytes).unwrap() else {
        unreachable!();
    };
    assert!(inv3.headers.get("Proxy-Authorization").is_some());
    assert!(inv3.headers.get("Authorization").is_some());

    // 3. 200 OK -> ACK carries both Proxy-Authorization and Authorization.
    let ans = SdpSession::new("bob", "1", "10.0.0.2", 50000, vec![RtpCodec::pcmu()]);
    let mut r200 = inv3
        .create_response(200, "OK")
        .unwrap()
        .with_body("application/sdp", ans.to_string().into_bytes());
    r200.headers.set("To", "<tel:+1-555-0199>;tag=btag1");
    r200.headers.set("Contact", "<sip:bob@10.0.0.2:5060>");
    let _ = alice.receive_datagram(&r200.to_bytes(), t0 + Duration::from_millis(30));
    let ack = alice
        .poll_transmit()
        .into_iter()
        .filter_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) if r.method == Method::Ack => Some(r),
            _ => None,
        })
        .next()
        .expect("expected ACK");
    assert!(ack.headers.get("Proxy-Authorization").is_some());
    assert!(ack.headers.get("Authorization").is_some());
    assert_eq!(alice.call_state(&call_id), Some(CallState::Established));
}

#[test]
fn p1_register_423_min_expires_retry_and_zero_contact_expires_unregisters() {
    let t0 = Instant::now();
    let registrar = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut cfg = UaConfig::new("alice", "pw", "pbx.local", registrar, "10.0.0.1", 5060);
    cfg.expires_secs = 30;
    let mut ua = UserAgent::new(cfg);

    ua.register(t0).unwrap();
    let reg1 = match SipMessage::parse(&ua.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected REGISTER"),
    };
    let mut r423 = reg1.create_response(423, "Interval Too Brief").unwrap();
    r423.headers.set("Min-Expires", "999999");
    let _ = ua.receive_datagram(&r423.to_bytes(), t0 + Duration::from_millis(10));

    let reg2 = match SipMessage::parse(&ua.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected retried REGISTER"),
    };
    assert_eq!(reg2.headers.get("Expires"), Some("86400"));

    // 200 OK with Contact ;expires=0 must yield Unregistered instead of clamping to 1s.
    let mut r200 = reg2.create_response(200, "OK").unwrap();
    r200.headers
        .set("Contact", "<sip:alice@10.0.0.1:5060>;expires=0");
    let _ = ua.receive_datagram(&r200.to_bytes(), t0 + Duration::from_millis(20));
    assert_eq!(ua.registration_state(), &RegistrationState::Unregistered);
}

#[test]
fn p1_early_bye_487_cancel_timeout_reinvite_rollback_and_uas_to_tag() {
    let t0 = Instant::now();
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();

    // 1. OPTIONS without To-tag must receive 200 OK with a generated To-tag.
    let mut uas = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        reg.clone(),
        "10.0.0.2",
        5062,
    ));
    let mut opt = SipRequest::new(
        Method::Options,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    opt.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt");
    opt.headers.set("From", "<sip:alice@pbx.local>;tag=a1");
    opt.headers.set("To", "<sip:bob@pbx.local>");
    opt.headers.set("Call-ID", "opt-1");
    opt.headers.set("CSeq", "1 OPTIONS");
    let _ = uas.receive_datagram(&opt.to_bytes(), t0);
    let opt_resp = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected OPTIONS 200 OK"),
    };
    assert!(opt_resp.to().unwrap().tag.is_some());

    // 2. Early-dialog inbound BYE sends 487 on pending INVITE transaction.
    let mut uac = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        reg,
        "10.0.0.1",
        5060,
    ));
    let cid_in = "early-bye-1";
    let mut inv = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    )
    .with_body(
        "application/sdp",
        SdpSession::new("alice", "1", "10.0.0.1", 40000, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    inv.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv");
    inv.headers.set("From", "<sip:alice@pbx.local>;tag=atag1");
    inv.headers.set("To", "<sip:bob@pbx.local>");
    inv.headers.set("Call-ID", cid_in);
    inv.headers.set("CSeq", "1 INVITE");
    let _ = uas.receive_datagram(&inv.to_bytes(), t0);
    let _ = uas.poll_transmit(); // 100
    uas.ring(cid_in, t0 + Duration::from_millis(5)).unwrap();
    let r180 = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 180"),
    };
    let bob_tag = r180.to().unwrap().tag.unwrap();

    let mut bye = SipRequest::new(Method::Bye, SipUri::parse("sip:bob@10.0.0.2:5062").unwrap());
    bye.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bye");
    bye.headers.set("From", "<sip:alice@pbx.local>;tag=atag1");
    bye.headers
        .set("To", format!("<sip:bob@pbx.local>;tag={bob_tag}"));
    bye.headers.set("Call-ID", cid_in);
    bye.headers.set("CSeq", "2 BYE");
    let _ = uas.receive_datagram(&bye.to_bytes(), t0 + Duration::from_millis(10));
    let resps: Vec<u16> = uas
        .poll_transmit()
        .into_iter()
        .filter_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Response(r) => Some(r.status_code),
            _ => None,
        })
        .collect();
    assert!(resps.contains(&200));
    assert!(resps.contains(&487));

    // 3. CANCEL deadline (64 * T1) terminates Cancelling call even if 487 never arrives.
    let cancel_cid = uac
        .dial(SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(), 40002, t0)
        .unwrap();
    let inv_req = match SipMessage::parse(&uac.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected INVITE"),
    };
    let r100 = inv_req.create_response(100, "Trying").unwrap();
    let _ = uac.receive_datagram(&r100.to_bytes(), t0 + Duration::from_millis(5));
    uac.hangup(&cancel_cid, t0 + Duration::from_millis(10))
        .unwrap();
    let _ = uac.poll_transmit();
    let mut terminated = false;
    let mut cur = t0 + Duration::from_millis(10);
    for _ in 0..40 {
        let Some(dl) = uac.poll_timeout() else {
            break;
        };
        cur = dl;
        let evs = uac.handle_timeout(cur);
        let _ = uac.poll_transmit();
        if evs
            .iter()
            .any(|e| matches!(e, UaEvent::CallTerminated { call_id, .. } if call_id == &cancel_cid))
        {
            terminated = true;
            break;
        }
    }
    assert!(terminated);

    // 4. Failed hold re-INVITE rolls back local_hold and emits reverted CallHoldChanged.
    let cid_hold = uac
        .dial(SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(), 40004, cur)
        .unwrap();
    let hold_inv = match SipMessage::parse(&uac.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected INVITE"),
    };
    let mut r200_h = hold_inv.create_response(200, "OK").unwrap().with_body(
        "application/sdp",
        SdpSession::new("bob", "1", "10.0.0.2", 50004, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    r200_h.headers.set("To", "<sip:bob@10.0.0.2:5062>;tag=bt2");
    r200_h.headers.set("Contact", "<sip:bob@10.0.0.2:5062>");
    let _ = uac.receive_datagram(&r200_h.to_bytes(), cur + Duration::from_millis(5));
    let _ = uac.poll_transmit();

    uac.hold(&cid_hold, cur + Duration::from_millis(10))
        .unwrap();
    let reinv = match SipMessage::parse(&uac.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected hold re-INVITE"),
    };
    let r488 = reinv.create_response(488, "Not Acceptable Here").unwrap();
    let evs = uac.receive_datagram(&r488.to_bytes(), cur + Duration::from_millis(20));
    assert_eq!(uac.call_state(&cid_hold), Some(CallState::Established));
    assert!(evs.iter().any(|e| matches!(
        e,
        UaEvent::CallHoldChanged {
            local_hold: false,
            ..
        }
    )));
}

#[test]
fn p1_session_timer_require_uas_fallback_and_isolated_422_config() {
    let t0 = Instant::now();
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut cfg = UaConfig::new("alice", "pw", "pbx.local", reg.clone(), "10.0.0.1", 5060);
    cfg.session_expires_secs = Some(180);
    cfg.min_se_secs = 90;
    let mut ua = UserAgent::new(cfg);

    // 422 Min-SE on Call 1 must not mutate ua.config().min_se_secs for Call 2.
    let _cid1 = ua
        .dial(SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(), 40000, t0)
        .unwrap();
    let inv1 = match SipMessage::parse(&ua.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected INVITE"),
    };
    let mut r422 = inv1
        .create_response(422, "Session Interval Too Small")
        .unwrap();
    r422.headers.set("Min-SE", "1800");
    let _ = ua.receive_datagram(&r422.to_bytes(), t0 + Duration::from_millis(5));
    let _ = ua.poll_transmit();
    assert_eq!(ua.config().min_se_secs, 90);
    assert_eq!(ua.config().session_expires_secs, Some(180));

    let cid2 = ua
        .dial(SipUri::parse("sip:carol@10.0.0.3:5062").unwrap(), 40002, t0)
        .unwrap();
    let inv2 = match SipMessage::parse(&ua.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected INVITE 2"),
    };
    assert_eq!(inv2.headers.get("Session-Expires"), Some("180"));
    assert_eq!(inv2.headers.get("Min-SE"), Some("90"));

    // Establish cid2 with refresher=uac, Session-Expires: 6 -> triggers UPDATE refresh -> 405 falls back to re-INVITE.
    let mut r200 = inv2.create_response(200, "OK").unwrap().with_body(
        "application/sdp",
        SdpSession::new("carol", "1", "10.0.0.3", 50002, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    r200.headers
        .set("To", "<sip:carol@10.0.0.3:5062>;tag=ctag1");
    r200.headers.set("Contact", "<sip:carol@10.0.0.3:5062>");
    r200.headers.set("Session-Expires", "6;refresher=uac");
    let _ = ua.receive_datagram(&r200.to_bytes(), t0 + Duration::from_millis(10));
    let _ = ua.poll_transmit();

    let t_ref = t0 + Duration::from_secs(4);
    let _ = ua.handle_timeout(t_ref);
    let upd = ua
        .poll_transmit()
        .into_iter()
        .filter_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) if r.method == Method::Update => Some(r),
            _ => None,
        })
        .next()
        .expect("expected UPDATE refresh");
    assert_eq!(upd.method, Method::Update);
    let r405 = upd.create_response(405, "Method Not Allowed").unwrap();
    let _ = ua.receive_datagram(&r405.to_bytes(), t_ref + Duration::from_millis(5));
    let reinv = match SipMessage::parse(&ua.poll_transmit().remove(0)).unwrap() {
        SipMessage::Request(r) => r,
        _ => panic!("expected re-INVITE fallback"),
    };
    assert_eq!(reinv.method, Method::Invite);

    // 200 OK to fallback re-INVITE without Session-Expires clears session timer so no later 408 BYE fires.
    let mut r200_re = reinv.create_response(200, "OK").unwrap().with_body(
        "application/sdp",
        SdpSession::new("carol", "2", "10.0.0.3", 50002, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    r200_re.headers.set("Contact", "<sip:carol@10.0.0.3:5062>");
    let _ = ua.receive_datagram(&r200_re.to_bytes(), t_ref + Duration::from_millis(10));
    let _ = ua.poll_transmit();
    let _ = ua.handle_timeout(t_ref + Duration::from_secs(30));
    assert_eq!(ua.call_state(&cid2), Some(CallState::Established));

    // UAS side: Request with Supported: timer -> Require: timer + refresher=uac; without Supported -> refresher=uas and no Require.
    let mut uas_cfg = UaConfig::new("bob", "pw", "pbx.local", reg, "10.0.0.2", 5062);
    uas_cfg.session_expires_secs = Some(90);
    let mut uas = UserAgent::new(uas_cfg);
    let mut inv_sup = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    )
    .with_body(
        "application/sdp",
        SdpSession::new("uac", "1", "10.0.0.1", 40010, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    inv_sup
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-s1");
    inv_sup.headers.set("From", "<sip:a@pbx.local>;tag=a1");
    inv_sup.headers.set("To", "<sip:bob@pbx.local>");
    inv_sup.headers.set("Call-ID", "se-uas-1");
    inv_sup.headers.set("CSeq", "1 INVITE");
    inv_sup.headers.set("Supported", "timer");
    let _ = uas.receive_datagram(&inv_sup.to_bytes(), t0);
    let _ = uas.poll_transmit();
    uas.answer("se-uas-1", 50010, t0 + Duration::from_millis(5))
        .unwrap();
    let ans_sup = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 200 OK"),
    };
    assert!(ans_sup
        .headers
        .get("Require")
        .is_some_and(|v| v.contains("timer")));
    assert_eq!(
        ans_sup.headers.get("Session-Expires"),
        Some("90;refresher=uac")
    );

    let mut inv_nosup = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    )
    .with_body(
        "application/sdp",
        SdpSession::new("uac", "1", "10.0.0.1", 40012, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    inv_nosup
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-s2");
    inv_nosup.headers.set("From", "<sip:a@pbx.local>;tag=a2");
    inv_nosup.headers.set("To", "<sip:bob@pbx.local>");
    inv_nosup.headers.set("Call-ID", "se-uas-2");
    inv_nosup.headers.set("CSeq", "1 INVITE");
    inv_nosup.headers.set("Session-Expires", "90");
    let _ = uas.receive_datagram(&inv_nosup.to_bytes(), t0);
    let _ = uas.poll_transmit();
    uas.answer("se-uas-2", 50012, t0 + Duration::from_millis(5))
        .unwrap();
    let ans_nosup = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 200 OK"),
    };
    assert_eq!(
        ans_nosup.headers.get("Session-Expires"),
        Some("90;refresher=uas")
    );
    assert!(ans_nosup.headers.get("Require").is_none());
}

#[test]
fn p2_100rel_retransmits_rack_cseq_check_single_inflight_and_504_timeout() {
    let t0 = Instant::now();
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut uas = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        reg,
        "10.0.0.2",
        5062,
    ));

    let inv = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    )
    .with_body(
        "application/sdp",
        SdpSession::new("alice", "1", "10.0.0.1", 40000, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    let mut inv = inv;
    inv.headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-100rel-1");
    inv.headers.set("From", "<sip:alice@pbx.local>;tag=a1");
    inv.headers.set("To", "<sip:bob@pbx.local>");
    inv.headers.set("Call-ID", "rel-call-1");
    inv.headers.set("CSeq", "42 INVITE");

    let _ = uas.receive_datagram(&inv.to_bytes(), t0);
    let _ = uas.poll_transmit(); // 100 Trying

    let rseq = uas
        .ring_reliable("rel-call-1", 183, "Session Progress", None, t0)
        .unwrap();
    // Second reliable 1xx must be rejected until PRACK arrives (RFC 3262 §3).
    assert!(uas
        .ring_reliable("rel-call-1", 180, "Ringing", None, t0)
        .is_err());

    let r183 = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 183"),
    };
    let to_hdr = r183.headers.get("To").unwrap().to_string();

    // Retransmit fires at T1 = 500 ms.
    let _ = uas.handle_timeout(t0 + Duration::from_millis(500));
    let retx = uas.poll_transmit();
    assert_eq!(retx.len(), 1);
    let r183_retx = match SipMessage::parse(&retx[0]).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 183 retransmission"),
    };
    assert_eq!(r183_retx.status_code, 183);

    // Wrong RAck CSeq must return 481 and leave reliable 1xx pending.
    let mut bad_prack = SipRequest::new(
        Method::Prack,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    bad_prack
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-prack-bad");
    bad_prack
        .headers
        .set("From", "<sip:alice@pbx.local>;tag=a1");
    bad_prack.headers.set("To", to_hdr.clone());
    bad_prack.headers.set("Call-ID", "rel-call-1");
    bad_prack.headers.set("CSeq", "43 PRACK");
    bad_prack.headers.set("RAck", format!("{rseq} 999 INVITE"));
    let _ = uas.receive_datagram(&bad_prack.to_bytes(), t0 + Duration::from_millis(600));
    let bad_resp = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 481 response to wrong RAck CSeq"),
    };
    assert_eq!(bad_resp.status_code, 481);

    // Valid PRACK clears pending reliable 1xx and returns 200 OK.
    let mut good_prack = SipRequest::new(
        Method::Prack,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    good_prack
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-prack-ok");
    good_prack
        .headers
        .set("From", "<sip:alice@pbx.local>;tag=a1");
    good_prack.headers.set("To", to_hdr);
    good_prack.headers.set("Call-ID", "rel-call-1");
    good_prack.headers.set("CSeq", "44 PRACK");
    good_prack.headers.set("RAck", format!("{rseq} 42 INVITE"));
    let _ = uas.receive_datagram(&good_prack.to_bytes(), t0 + Duration::from_millis(700));
    let ok_resp = match SipMessage::parse(&uas.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 200 OK to PRACK"),
    };
    assert_eq!(ok_resp.status_code, 200);

    // Next reliable 180 can now be sent, and if left unacked for 64*T1 (32s) -> 504 Server Time-out.
    let _rseq2 = uas
        .ring_reliable(
            "rel-call-1",
            180,
            "Ringing",
            None,
            t0 + Duration::from_secs(1),
        )
        .unwrap();
    let _ = uas.poll_transmit();
    let term_evs = uas.handle_timeout(t0 + Duration::from_secs(34));
    assert!(term_evs.iter().any(|e| matches!(
        e,
        UaEvent::CallTerminated {
            status_code: Some(504),
            ..
        }
    )));
    let out_fin = uas.poll_transmit();
    assert!(out_fin.iter().any(|b| matches!(
        SipMessage::parse(b),
        Ok(SipMessage::Response(r)) if r.status_code == 504
    )));
}

#[test]
fn p2_reinvite_491_backoff_retry_update_glare_and_replaces_codes() {
    let t0 = Instant::now();
    let policy = clean_policy();
    let mut cluster = MiniSipCluster::new(t0, policy, 7);

    // Distinct hosts on same port with instance_seed=0 still produce unique Call-IDs.
    let reg = SipUri::parse("sip:pbx.local:5060").unwrap();
    let mut u1 = UserAgent::new(UaConfig::new(
        "alice",
        "pw",
        "pbx.local",
        reg.clone(),
        "10.0.0.10",
        5060,
    ));
    let mut u2 = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        reg.clone(),
        "10.0.0.11",
        5060,
    ));
    let c1 = u1
        .dial(SipUri::parse("sip:x@10.0.0.2:5060").unwrap(), 40000, t0)
        .unwrap();
    let c2 = u2
        .dial(SipUri::parse("sip:x@10.0.0.2:5060").unwrap(), 40002, t0)
        .unwrap();
    assert_ne!(c1, c2);

    // 1. Re-INVITE 491 backoff retry on established call + UPDATE glare 491.
    let (cid, _, _) = establish_clean_cluster_call(&mut cluster, 40020, 50020);
    let quiet_until = cluster.now + Duration::from_secs(6);
    let _ = cluster.step_until(10, Some(quiet_until));
    cluster.alice.hold(&cid, cluster.now).unwrap();
    let reinv = cluster
        .alice
        .poll_transmit()
        .into_iter()
        .find_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) if r.method == Method::Invite => Some(r),
            _ => None,
        })
        .unwrap();

    // Inbound UPDATE with SDP while ReInviting MUST get 491 Request Pending.
    let mut upd_glare = SipRequest::new(Method::Update, reinv.uri.clone()).with_body(
        "application/sdp",
        SdpSession::new("bob", "9", "10.0.0.2", 50022, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    upd_glare
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.2:5062;branch=z9hG4bK-upd-glare");
    upd_glare
        .headers
        .set("From", reinv.headers.get("To").unwrap());
    upd_glare
        .headers
        .set("To", reinv.headers.get("From").unwrap());
    upd_glare.headers.set("Call-ID", cid.clone());
    upd_glare.headers.set("CSeq", "99 UPDATE");
    let _ = cluster.alice.receive_datagram(
        &upd_glare.to_bytes(),
        cluster.now + Duration::from_millis(5),
    );
    let upd_resp = match SipMessage::parse(&cluster.alice.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 491 to glare UPDATE"),
    };
    assert_eq!(upd_resp.status_code, 491);

    // Receive 491 Request Pending for Alice's re-INVITE -> backs off 2.1..4.0s (Call-ID owner) and retries.
    let mut r491 = reinv.create_response(491, "Request Pending").unwrap();
    r491.headers.set("To", reinv.headers.get("To").unwrap());
    let _ = cluster
        .alice
        .receive_datagram(&r491.to_bytes(), cluster.now + Duration::from_millis(10));
    assert_eq!(cluster.alice.call_state(&cid), Some(CallState::Established));

    let dl = cluster
        .alice
        .poll_timeout()
        .expect("expected 491 retry deadline");
    assert!(dl >= cluster.now + Duration::from_millis(2110));
    assert!(dl <= cluster.now + Duration::from_millis(4010));
    cluster.now = dl;
    let _ = cluster.alice.handle_timeout(cluster.now);
    let retried_reinv = cluster
        .alice
        .poll_transmit()
        .into_iter()
        .find_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) if r.method == Method::Invite => Some(r),
            _ => None,
        })
        .expect("expected re-INVITE backoff retry");
    assert_eq!(retried_reinv.method, Method::Invite);

    // Non-owner (Bob Inbound call) receiving 491 backs off 0.1..2.0s before retrying hold re-INVITE.
    let mut bob_cluster = MiniSipCluster::new(t0, clean_policy(), 11);
    let (bob_cid, _, _) = establish_clean_cluster_call(&mut bob_cluster, 40030, 50030);
    let bob_quiet = bob_cluster.now + Duration::from_secs(6);
    let _ = bob_cluster.step_until(10, Some(bob_quiet));
    bob_cluster.bob.hold(&bob_cid, bob_cluster.now).unwrap();
    let bob_reinv = bob_cluster
        .bob
        .poll_transmit()
        .into_iter()
        .find_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) if r.method == Method::Invite => Some(r),
            _ => None,
        })
        .unwrap();
    let mut bob_491 = bob_reinv.create_response(491, "Request Pending").unwrap();
    bob_491
        .headers
        .set("To", bob_reinv.headers.get("To").unwrap());
    let _ = bob_cluster.bob.receive_datagram(
        &bob_491.to_bytes(),
        bob_cluster.now + Duration::from_millis(10),
    );
    let bob_dl = bob_cluster
        .bob
        .poll_timeout()
        .expect("expected non-owner 491 retry deadline");
    assert!(bob_dl >= bob_cluster.now + Duration::from_millis(110));
    assert!(bob_dl <= bob_cluster.now + Duration::from_millis(2010));
    bob_cluster.now = bob_dl;
    let _ = bob_cluster.bob.handle_timeout(bob_cluster.now);
    let bob_retried = bob_cluster
        .bob
        .poll_transmit()
        .into_iter()
        .find_map(|b| match SipMessage::parse(&b).ok()? {
            SipMessage::Request(r) if r.method == Method::Invite => Some(r),
            _ => None,
        })
        .expect("expected non-owner re-INVITE backoff retry");
    assert_eq!(bob_retried.method, Method::Invite);

    // 2. Replaces status codes: 481 on inbound early dialog, 486 on confirmed early-only, 603 on terminating.
    let mut bob = UserAgent::new(UaConfig::new(
        "bob",
        "pw",
        "pbx.local",
        reg,
        "10.0.0.2",
        5062,
    ));
    let mut early_in = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    )
    .with_body(
        "application/sdp",
        SdpSession::new("alice", "1", "10.0.0.1", 40000, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    early_in
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-rep-1");
    early_in
        .headers
        .set("From", "<sip:alice@pbx.local>;tag=rt1");
    early_in.headers.set("To", "<sip:bob@pbx.local>");
    early_in.headers.set("Call-ID", "rep-target-1");
    early_in.headers.set("CSeq", "1 INVITE");
    let _ = bob.receive_datagram(&early_in.to_bytes(), t0);
    let _ = bob.poll_transmit();
    bob.ring("rep-target-1", t0).unwrap();
    let r180 = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 180"),
    };
    let bob_tag = r180.to().unwrap().tag.unwrap();

    // UPDATE in Incoming/Ringing with port 0 MUST fail without mutating state.
    assert!(bob.send_update("rep-target-1", None, None, t0).is_err());

    let rep_val =
        bmsip_core::sip::ReplacesHeader::new("rep-target-1", bob_tag.clone(), "rt1").to_string();
    let mut inv_rep = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    inv_rep.headers.add(
        "Via",
        "SIP/2.0/UDP 10.0.0.3:5060;branch=z9hG4bK-rep-early-in",
    );
    inv_rep.headers.set("From", "<sip:carol@pbx.local>;tag=ct1");
    inv_rep.headers.set("To", "<sip:bob@pbx.local>");
    inv_rep.headers.set("Call-ID", "rep-new-1");
    inv_rep.headers.set("CSeq", "1 INVITE");
    inv_rep.headers.set("Replaces", rep_val.clone());
    let _ = bob.receive_datagram(&inv_rep.to_bytes(), t0);
    let resp_early_in = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 481 for non-UAC-initiated early dialog"),
    };
    assert_eq!(resp_early_in.status_code, 481);

    // Establish rep-target-1 -> early-only Replaces MUST return 486 Busy Here.
    bob.answer("rep-target-1", 50030, t0).unwrap();
    let _ = bob.poll_transmit();
    let mut inv_early_only = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    inv_early_only
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.3:5060;branch=z9hG4bK-rep-486");
    inv_early_only
        .headers
        .set("From", "<sip:carol@pbx.local>;tag=ct2");
    inv_early_only.headers.set("To", "<sip:bob@pbx.local>");
    inv_early_only.headers.set("Call-ID", "rep-new-2");
    inv_early_only.headers.set("CSeq", "1 INVITE");
    inv_early_only
        .headers
        .set("Replaces", format!("{rep_val};early-only"));
    let _ = bob.receive_datagram(&inv_early_only.to_bytes(), t0);
    let resp_486 = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 486 Busy Here for confirmed dialog + early-only"),
    };
    assert_eq!(resp_486.status_code, 486);

    // Hangup moves rep-target-1 to Terminating -> Replaces MUST return 603 Decline.
    bob.hangup("rep-target-1", t0).unwrap();
    let _ = bob.poll_transmit();
    let mut inv_term = SipRequest::new(
        Method::Invite,
        SipUri::parse("sip:bob@10.0.0.2:5062").unwrap(),
    );
    inv_term
        .headers
        .add("Via", "SIP/2.0/UDP 10.0.0.3:5060;branch=z9hG4bK-rep-603");
    inv_term
        .headers
        .set("From", "<sip:carol@pbx.local>;tag=ct3");
    inv_term.headers.set("To", "<sip:bob@pbx.local>");
    inv_term.headers.set("Call-ID", "rep-new-3");
    inv_term.headers.set("CSeq", "1 INVITE");
    inv_term.headers.set("Replaces", rep_val);
    let _ = bob.receive_datagram(&inv_term.to_bytes(), t0);
    let resp_603 = match SipMessage::parse(&bob.poll_transmit().remove(0)).unwrap() {
        SipMessage::Response(r) => r,
        _ => panic!("expected 603 Decline for terminating dialog"),
    };
    assert_eq!(resp_603.status_code, 603);
}
