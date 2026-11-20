use std::time::{Duration, Instant};

use bmsip_core::auth::{DigestChallenge, DigestCredentials};
use bmsip_core::dialog::{UaConfig, UserAgent};
use bmsip_core::sdp::{negotiate_offer_answer, Direction, RtpCodec, SdpSession};
use bmsip_core::sim::{NetworkPolicy, VirtualNetwork};
use bmsip_core::sip::{Method, SipMessage, SipRequest, SipResponse, SipUri};
use bmsip_core::transaction::{RfcTimers, TransactionEvent};

fn build_request(method: Method, call_id: &str, branch: &str, cseq_num: u32) -> SipRequest {
    let mut req = SipRequest::new(method.clone(), SipUri::parse("sip:bob@pbx.local").unwrap());
    req.headers.add(
        "Via",
        format!("SIP/2.0/UDP 10.0.0.1:5060;branch={branch};rport"),
    );
    req.headers
        .set("From", "\"Alice\" <sip:alice@pbx.local>;tag=alice-tag-1");
    req.headers.set("To", "<sip:bob@pbx.local>");
    req.headers.set("Call-ID", call_id);
    req.headers.set("CSeq", format!("{cseq_num} {method}"));
    req.headers.set("Max-Forwards", "70");
    req.headers
        .set("Contact", "<sip:alice@10.0.0.1:5060;transport=udp>");
    req
}

#[test]
fn register_succeeds_over_lossy_and_duplicating_network() {
    let t0 = Instant::now();
    let policy = NetworkPolicy {
        loss_percent: 40,
        duplicate_percent: 30,
        min_delay: Duration::from_millis(15),
        max_delay: Duration::from_millis(60),
    };
    let mut net = VirtualNetwork::new(t0, RfcTimers::default(), policy, 0x1234_5678);

    let reg = build_request(Method::Register, "call-reg-1", "z9hG4bK-reg-1", 1);
    let client_tx = net.client.start_client_transaction(reg, net.now()).unwrap();

    let mut server_seen_requests = 0usize;
    let mut client_final_codes = Vec::new();
    let mut client_terminated = false;

    for _ in 0..200 {
        let Some(events) = net.step() else {
            break;
        };
        for ev in events.server_events {
            if let TransactionEvent::ServerRequest { tx_id, request } = ev {
                server_seen_requests += 1;
                let mut resp = request.create_response(200, "OK").unwrap();
                resp.headers.set("To", "<sip:bob@pbx.local>;tag=srv-reg-1");
                net.server
                    .send_server_response(&tx_id, resp, net.now())
                    .unwrap();
            }
        }
        for ev in events.client_events {
            match ev {
                TransactionEvent::ClientFinal { tx_id, response } => {
                    assert_eq!(tx_id, client_tx);
                    client_final_codes.push(response.status_code);
                }
                TransactionEvent::TransactionTerminated(tx_id) if tx_id == client_tx => {
                    client_terminated = true;
                }
                TransactionEvent::TransactionTimeout(tx_id) => {
                    panic!("unexpected transaction timeout: {:?}", tx_id);
                }
                _ => {}
            }
        }
    }

    assert_eq!(
        server_seen_requests, 1,
        "NIST must suppress duplicate/retransmitted REGISTER requests to TU"
    );
    assert_eq!(
        client_final_codes,
        vec![200],
        "NICT must deliver final 200 OK exactly once despite duplicates"
    );
    assert!(client_terminated);
    assert_eq!(net.client.active_client_count(), 0);
    assert_eq!(net.server.active_server_count(), 0);
    assert!(
        net.stats.packets_dropped > 0 || net.stats.packets_duplicated > 0,
        "simulation should have exercised packet loss or duplication"
    );
}

#[test]
fn register_handles_401_digest_challenge_and_sha256_auth() {
    let t0 = Instant::now();
    let mut net = VirtualNetwork::new(
        t0,
        RfcTimers::default(),
        NetworkPolicy {
            loss_percent: 25,
            duplicate_percent: 20,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(25),
        },
        42,
    );

    let reg1 = build_request(Method::Register, "call-auth-1", "z9hG4bK-auth-1", 1);
    net.client
        .start_client_transaction(reg1, net.now())
        .unwrap();

    let mut challenge_header: Option<String> = None;
    for _ in 0..100 {
        let Some(events) = net.step() else { break };
        for ev in events.server_events {
            if let TransactionEvent::ServerRequest { tx_id, request } = ev {
                let mut resp = request.create_response(401, "Unauthorized").unwrap();
                resp.headers.set(
                    "WWW-Authenticate",
                    "Digest realm=\"pbx.local\", nonce=\"srv-nonce-99\", algorithm=SHA-256, qop=\"auth\"",
                );
                net.server
                    .send_server_response(&tx_id, resp, net.now())
                    .unwrap();
            }
        }
        for ev in events.client_events {
            if let TransactionEvent::ClientFinal { response, .. } = ev {
                assert_eq!(response.status_code, 401);
                challenge_header = response.headers.get("WWW-Authenticate").map(str::to_string);
            }
        }
    }

    let challenge = DigestChallenge::parse(&challenge_header.unwrap()).unwrap();
    let creds = DigestCredentials::new("alice", "s3cr3t", Some("client-nonce-7".to_string()));
    let auth_header = creds
        .authorize(&challenge, &Method::Register, "sip:bob@pbx.local")
        .unwrap();

    let mut reg2 = build_request(Method::Register, "call-auth-1", "z9hG4bK-auth-2", 2);
    reg2.headers.set("Authorization", auth_header);
    net.client
        .start_client_transaction(reg2, net.now())
        .unwrap();

    let mut verified_auth = false;
    let mut final_200 = false;
    for _ in 0..100 {
        let Some(events) = net.step() else { break };
        for ev in events.server_events {
            if let TransactionEvent::ServerRequest { tx_id, request } = ev {
                let auth = request.headers.get("Authorization").unwrap_or("");
                assert!(auth.contains("algorithm=SHA-256"));
                assert!(auth.contains("username=\"alice\""));
                verified_auth = true;
                let resp = request.create_response(200, "OK").unwrap();
                net.server
                    .send_server_response(&tx_id, resp, net.now())
                    .unwrap();
            }
        }
        for ev in events.client_events {
            if let TransactionEvent::ClientFinal { response, .. } = ev {
                if response.status_code == 200 {
                    final_200 = true;
                }
            }
        }
    }

    assert!(verified_auth);
    assert!(final_200);
    assert_eq!(net.client.active_client_count(), 0);
    assert_eq!(net.server.active_server_count(), 0);
}

#[test]
fn invite_non2xx_486_triggers_auto_ack_and_clean_timer_reclaim_under_loss() {
    let t0 = Instant::now();
    let policy = NetworkPolicy {
        loss_percent: 40,
        duplicate_percent: 25,
        min_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(30),
    };
    let mut net = VirtualNetwork::new(t0, RfcTimers::default(), policy, 999);

    let invite = build_request(Method::Invite, "call-inv-486", "z9hG4bK-inv-1", 10);
    net.client
        .start_client_transaction(invite, net.now())
        .unwrap();

    let mut client_provisionals = Vec::new();
    let mut client_finals = Vec::new();
    let mut server_ack_received = false;

    for _ in 0..300 {
        let Some(events) = net.step() else {
            break;
        };
        for ev in events.server_events {
            match ev {
                TransactionEvent::ServerRequest { tx_id, request } => {
                    let r180 = request.create_response(180, "Ringing").unwrap();
                    net.server
                        .send_server_response(&tx_id, r180, net.now())
                        .unwrap();

                    let mut r486 = request.create_response(486, "Busy Here").unwrap();
                    r486.headers
                        .set("To", "<sip:bob@pbx.local>;tag=bob-busy-tag");
                    net.server
                        .send_server_response(&tx_id, r486, net.now())
                        .unwrap();
                }
                TransactionEvent::ServerAckReceived(tx_id) => {
                    assert_eq!(tx_id.branch, "z9hG4bK-inv-1");
                    server_ack_received = true;
                }
                _ => {}
            }
        }
        for ev in events.client_events {
            match ev {
                TransactionEvent::ClientProvisional { response, .. } => {
                    client_provisionals.push(response.status_code);
                }
                TransactionEvent::ClientFinal { response, .. } => {
                    client_finals.push(response.status_code);
                }
                TransactionEvent::TransactionTimeout(id) => {
                    panic!("unexpected timeout: {:?}", id);
                }
                _ => {}
            }
        }
    }

    assert!(!client_provisionals.is_empty() || !client_finals.is_empty());
    assert_eq!(client_finals, vec![486]);
    assert!(
        server_ack_received,
        "IST must receive auto-generated ACK for 486 Busy Here"
    );
    assert_eq!(net.client.active_client_count(), 0);
    assert_eq!(net.server.active_server_count(), 0);
}

#[test]
fn invite_200_ok_with_sdp_offer_answer_and_ack_for_2xx() {
    let t0 = Instant::now();
    let policy = NetworkPolicy {
        loss_percent: 35,
        duplicate_percent: 20,
        min_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(30),
    };
    let mut net = VirtualNetwork::new(t0, RfcTimers::default(), policy, 2026);

    let offer_sdp = SdpSession::new(
        "alice",
        "777",
        "10.0.0.1",
        40000,
        vec![
            RtpCodec::opus(),
            RtpCodec::pcmu(),
            RtpCodec::telephone_event(101),
        ],
    );
    let invite = build_request(Method::Invite, "call-inv-200", "z9hG4bK-inv-200", 1)
        .with_body("application/sdp", offer_sdp.to_string().into_bytes());
    let inv_tx = net
        .client
        .start_client_transaction(invite.clone(), net.now())
        .unwrap();

    let mut server_seen = 0usize;
    let mut client_got_200 = false;
    let mut server_got_ack_2xx = false;
    let mut negotiated_codecs_on_server = Vec::new();
    let mut saved_200: Option<SipResponse> = None;
    let mut ack_seq = 0u32;

    for _ in 0..300 {
        let Some(events) = net.step() else {
            // In RFC 3261 Section 13.3.1.4, the UAS Dialog (above IST) retransmits 200 OK
            // until ACK arrives. Simulate that TU retransmit if ACK was lost.
            if let Some(ref r200) = saved_200 {
                if !server_got_ack_2xx {
                    net.server.send_stateless_response(r200.clone());
                    continue;
                }
            }
            break;
        };
        for ev in events.server_events {
            match ev {
                TransactionEvent::ServerRequest { tx_id, request } => {
                    server_seen += 1;
                    let offer_text = std::str::from_utf8(&request.body).unwrap();
                    let parsed_offer = SdpSession::parse(offer_text).unwrap();
                    let (answer_sdp, negotiated) = negotiate_offer_answer(
                        &parsed_offer,
                        &[RtpCodec::pcmu(), RtpCodec::telephone_event(101)],
                        "10.0.0.2",
                        50000,
                    )
                    .unwrap();
                    negotiated_codecs_on_server = negotiated;

                    let r180 = request.create_response(180, "Ringing").unwrap();
                    net.server
                        .send_server_response(&tx_id, r180, net.now())
                        .unwrap();

                    let mut r200 = request
                        .create_response(200, "OK")
                        .unwrap()
                        .with_body("application/sdp", answer_sdp.to_string().into_bytes());
                    r200.headers.set("To", "<sip:bob@pbx.local>;tag=bob-ok-1");
                    r200.headers.set("Contact", "<sip:bob@10.0.0.2:5060>");
                    saved_200 = Some(r200.clone());
                    net.server
                        .send_server_response(&tx_id, r200, net.now())
                        .unwrap();
                }
                TransactionEvent::AckFor2xx(ack_req) => {
                    assert_eq!(ack_req.call_id().unwrap(), "call-inv-200");
                    assert_eq!(ack_req.to().unwrap().tag.as_deref(), Some("bob-ok-1"));
                    server_got_ack_2xx = true;
                }
                _ => {}
            }
        }
        for ev in events.client_events {
            let response = match ev {
                TransactionEvent::ClientFinal { tx_id, response } => {
                    assert_eq!(tx_id, inv_tx);
                    Some(response)
                }
                TransactionEvent::Unmatched2xx(response) => Some(response),
                _ => None,
            };
            if let Some(response) = response {
                assert_eq!(response.status_code, 200);
                let answer =
                    SdpSession::parse(std::str::from_utf8(&response.body).unwrap()).unwrap();
                assert_eq!(answer.direction, Direction::SendRecv);
                assert_eq!(answer.audio_port, 50000);
                assert_eq!(answer.codecs[0].encoding_name, "PCMU");
                client_got_200 = true;

                ack_seq += 1;
                let mut ack =
                    SipRequest::new(Method::Ack, SipUri::parse("sip:bob@10.0.0.2:5060").unwrap());
                ack.headers.add(
                    "Via",
                    format!("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ack-{ack_seq};rport"),
                );
                ack.headers
                    .set("From", response.headers.get("From").unwrap());
                ack.headers.set("To", response.headers.get("To").unwrap());
                ack.headers
                    .set("Call-ID", response.headers.get("Call-ID").unwrap());
                ack.headers.set("CSeq", "1 ACK");
                net.client.send_ack_for_2xx(ack).unwrap();
            }
        }
    }

    assert_eq!(server_seen, 1);
    assert!(client_got_200);
    assert!(server_got_ack_2xx);
    assert_eq!(negotiated_codecs_on_server.len(), 2);
    assert_eq!(net.client.active_client_count(), 0);
    assert_eq!(net.server.active_server_count(), 0);
}

#[test]
fn client_transaction_times_out_when_network_drops_everything() {
    let t0 = Instant::now();
    let policy = NetworkPolicy {
        loss_percent: 100,
        duplicate_percent: 0,
        min_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(10),
    };
    let mut net = VirtualNetwork::new(t0, RfcTimers::default(), policy, 1);

    let req = build_request(Method::Register, "call-drop-all", "z9hG4bK-drop-all", 1);
    let tx_id = net.client.start_client_transaction(req, net.now()).unwrap();

    let mut timed_out = false;
    for _ in 0..100 {
        let Some(events) = net.step() else { break };
        for ev in events.client_events {
            if ev == TransactionEvent::TransactionTimeout(tx_id.clone()) {
                timed_out = true;
            }
        }
    }

    assert!(timed_out);
    // Timer F is 64 * T1 = 32s. Check virtual time progressed to 32s without sleeping!
    assert_eq!(net.now().duration_since(t0), Duration::from_secs(32));
    // Initial send + 10 retransmits (0.5, 1, 2, 4, 4, 4, 4, 4, 4, 4s -> 31.5s) = 11 packets
    assert_eq!(net.stats.packets_sent, 11);
    assert_eq!(net.stats.packets_dropped, 11);
    assert_eq!(net.client.active_client_count(), 0);
}

#[test]
fn malformed_wire_message_does_not_panic_and_emits_warning() {
    let t0 = Instant::now();
    let mut tm = bmsip_core::transaction::TransactionManager::default();
    let raw = b"OPTIONS sip:alice@example.com SIP/2.0\r\nFrom: <sip:a@b>\r\nTo: <sip:c@d>\r\nCall-ID: 1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    let msg = SipMessage::parse(raw).unwrap();
    let events = tm.receive_message(msg, t0);
    assert!(matches!(
        events.as_slice(),
        [TransactionEvent::ProtocolWarning(_)]
    ));
}

#[test]
fn deterministic_mutation_fuzz_sip_sdp_auth_and_ua_never_panic() {
    let mut prng: u64 = 0x517c_c1b7_2722_0a95;
    let next_u64 = |state: &mut u64| -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    };

    let seed_sip = build_request(Method::Invite, "call-fuzz", "z9hG4bK-fuzz", 7)
        .with_body(
            "application/sdp",
            b"v=0\r\no=alice 1 1 IN IP4 10.0.0.1\r\ns=x\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\nm=audio 4000 RTP/AVP 9 0 101\r\na=rtpmap:101 telephone-event/8000\r\n"
                .to_vec(),
        )
        .to_bytes();
    let seed_auth = b"Digest realm=\"asterisk\", nonce=\"abc\", qop=\"auth\", algorithm=SHA-256";
    let seed_oversized = b"INVITE sip:bob@pbx.local SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:b@c>\r\nCall-ID: id\r\nCSeq: 1 INVITE\r\nContent-Length: 99999999\r\n\r\nhi";

    let t0 = Instant::now();
    let mut ua = UserAgent::new(UaConfig::new(
        "alice",
        "secret",
        "pbx.local",
        SipUri::parse("sip:pbx.local:5060").unwrap(),
        "10.0.0.1",
        5060,
    ));
    let mut buf = Vec::with_capacity(512);

    for iter in 0..4_000usize {
        let seed: &[u8] = match iter % 4 {
            0 => &seed_sip,
            1 => seed_auth,
            2 => seed_oversized,
            _ => &[],
        };
        let target_len = (next_u64(&mut prng) as usize) % 380;
        buf.clear();
        for i in 0..target_len {
            let base = if i < seed.len() { seed[i] } else { b'a' };
            let r = next_u64(&mut prng);
            let mut byte = if (r & 3) == 0 { (r >> 8) as u8 } else { base };
            if (r & 31) == 0 {
                byte = if (r & 32) == 0 { b'\r' } else { b'\n' };
            }
            buf.push(byte);
        }

        let _ = SipMessage::parse(&buf);
        let text = String::from_utf8_lossy(&buf);
        let _ = SdpSession::parse(&text);
        let _ = DigestChallenge::parse(&text);
        let _ = SipUri::parse(&text);
        let now = t0 + Duration::from_millis(iter as u64);
        let _ = ua.receive_datagram(&buf, now);
    }
}
