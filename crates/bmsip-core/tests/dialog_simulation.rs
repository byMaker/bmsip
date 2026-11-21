use std::collections::HashMap;
use std::time::{Duration, Instant};

use bmsip_core::auth::hash::md5_hex;
use bmsip_core::dialog::{CallState, RegistrationState, UaConfig, UaEvent, UserAgent};
use bmsip_core::sim::NetworkPolicy;
use bmsip_core::sip::{Method, NameAddr, SipMessage, SipUri};
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
    let invite_no_sdp = b"INVITE sip:bob@10.0.0.2:5062 SIP/2.0\r\n\
        Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-nosdp-1\r\n\
        From: <sip:alice@pbx.local>;tag=a9\r\n\
        To: <sip:bob@pbx.local>\r\n\
        Call-ID: nosdp-call-1\r\n\
        CSeq: 1 INVITE\r\n\
        Contact: <sip:alice@10.0.0.1:5060>\r\n\
        Content-Length: 0\r\n\r\n";

    let _ = bob.receive_datagram(invite_no_sdp, t0);
    let _ = bob.poll_transmit(); // drain 100 Trying

    assert!(bob.answer("nosdp-call-1", 50000, t0).is_err());
    assert_eq!(bob.call_state("nosdp-call-1"), None);
    let out = bob.poll_transmit();
    assert_eq!(out.len(), 1);
    let resp = match SipMessage::parse(&out[0]).unwrap() {
        SipMessage::Response(r) => r,
        SipMessage::Request(_) => panic!("expected 488 response"),
    };
    assert_eq!(resp.status_code, 488);
}
