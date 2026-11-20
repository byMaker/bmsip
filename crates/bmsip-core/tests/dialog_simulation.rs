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
