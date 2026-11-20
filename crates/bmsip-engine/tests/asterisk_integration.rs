use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use bmsip_core::dialog::{CallState, RegistrationState, UaConfig, UaEvent, UserAgent};
use bmsip_core::sip::SipUri;

fn resolve_asterisk() -> SocketAddr {
    ("asterisk", 5060)
        .to_socket_addrs()
        .expect("resolve asterisk:5060")
        .next()
        .expect("at least one address for asterisk:5060")
}

fn discover_local_ip(remote: SocketAddr) -> IpAddr {
    let probe = UdpSocket::bind("0.0.0.0:0").expect("bind probe socket");
    probe.connect(remote).expect("connect probe socket");
    probe.local_addr().expect("probe local_addr").ip()
}

fn pump_pair(
    ua_a: &mut UserAgent,
    sock_a: &UdpSocket,
    events_a: &mut Vec<UaEvent>,
    ua_b: &mut UserAgent,
    sock_b: &UdpSocket,
    events_b: &mut Vec<UaEvent>,
    asterisk_addr: SocketAddr,
) {
    for pkt in ua_a.poll_transmit() {
        sock_a.send_to(&pkt, asterisk_addr).expect("send a");
    }
    for pkt in ua_b.poll_transmit() {
        sock_b.send_to(&pkt, asterisk_addr).expect("send b");
    }

    let mut buf = [0u8; 8192];
    let now = Instant::now();

    loop {
        match sock_a.recv_from(&mut buf) {
            Ok((len, _)) => events_a.extend(ua_a.receive_datagram(&buf[..len], now)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => panic!("recv_from a failed: {e}"),
        }
    }

    loop {
        match sock_b.recv_from(&mut buf) {
            Ok((len, _)) => events_b.extend(ua_b.receive_datagram(&buf[..len], now)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => panic!("recv_from b failed: {e}"),
        }
    }

    let now = Instant::now();
    if ua_a.poll_timeout().is_some_and(|dl| now >= dl) {
        events_a.extend(ua_a.handle_timeout(now));
    }
    if ua_b.poll_timeout().is_some_and(|dl| now >= dl) {
        events_b.extend(ua_b.handle_timeout(now));
    }
    events_a.extend(ua_a.drain_events());
    events_b.extend(ua_b.drain_events());

    for pkt in ua_a.poll_transmit() {
        sock_a.send_to(&pkt, asterisk_addr).expect("send a");
    }
    for pkt in ua_b.poll_transmit() {
        sock_b.send_to(&pkt, asterisk_addr).expect("send b");
    }
}

#[test]
fn live_asterisk_register_call_answer_and_bye() {
    let asterisk_addr = resolve_asterisk();
    let local_ip = discover_local_ip(asterisk_addr);

    let sock_1001 = UdpSocket::bind((local_ip, 0)).expect("bind 1001");
    let sock_1002 = UdpSocket::bind((local_ip, 0)).expect("bind 1002");
    sock_1001.set_nonblocking(true).expect("nonblocking 1001");
    sock_1002.set_nonblocking(true).expect("nonblocking 1002");

    let port_1001 = sock_1001.local_addr().unwrap().port();
    let port_1002 = sock_1002.local_addr().unwrap().port();
    let registrar = SipUri::parse("sip:asterisk:5060").unwrap();

    let mut ua_1001 = UserAgent::new(UaConfig::new(
        "1001",
        "secret1001",
        "asterisk",
        registrar.clone(),
        local_ip.to_string(),
        port_1001,
    ));
    let mut ua_1002 = UserAgent::new(UaConfig::new(
        "1002",
        "secret1002",
        "asterisk",
        registrar,
        local_ip.to_string(),
        port_1002,
    ));

    let mut events_1001 = Vec::new();
    let mut events_1002 = Vec::new();

    // Step 1: Register both endpoints with live Asterisk (401 Digest MD5 challenge -> 200 OK).
    let now = Instant::now();
    ua_1001.register(now).unwrap();
    ua_1002.register(now).unwrap();

    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        pump_pair(
            &mut ua_1001,
            &sock_1001,
            &mut events_1001,
            &mut ua_1002,
            &sock_1002,
            &mut events_1002,
            asterisk_addr,
        );
        if matches!(
            ua_1001.registration_state(),
            RegistrationState::Registered { .. }
        ) && matches!(
            ua_1002.registration_state(),
            RegistrationState::Registered { .. }
        ) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(
        matches!(
            ua_1001.registration_state(),
            RegistrationState::Registered { .. }
        ),
        "1001 failed to register: {:?}, events: {:?}",
        ua_1001.registration_state(),
        events_1001
    );
    assert!(
        matches!(
            ua_1002.registration_state(),
            RegistrationState::Registered { .. }
        ),
        "1002 failed to register: {:?}, events: {:?}",
        ua_1002.registration_state(),
        events_1002
    );

    // Step 2: 1001 dials 1002 through Asterisk B2BUA.
    let call_1001 = ua_1001
        .dial(
            SipUri::parse("sip:1002@asterisk:5060").unwrap(),
            41000,
            Instant::now(),
        )
        .unwrap();

    let mut call_1002: Option<String> = None;
    let mut sent_ring = false;
    let mut sent_answer = false;
    let mut est_1001 = false;
    let mut est_1002 = false;

    let call_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < call_deadline {
        let ev1_start = events_1001.len();
        let ev2_start = events_1002.len();
        pump_pair(
            &mut ua_1001,
            &sock_1001,
            &mut events_1001,
            &mut ua_1002,
            &sock_1002,
            &mut events_1002,
            asterisk_addr,
        );

        for ev in &events_1002[ev2_start..] {
            match ev {
                UaEvent::IncomingCall { call_id, .. } if call_1002.is_none() => {
                    call_1002 = Some(call_id.clone());
                }
                UaEvent::CallEstablished {
                    negotiated_codecs, ..
                } => {
                    assert!(!negotiated_codecs.is_empty());
                    est_1002 = true;
                }
                _ => {}
            }
        }
        for ev in &events_1001[ev1_start..] {
            if let UaEvent::CallEstablished {
                call_id,
                negotiated_codecs,
                ..
            } = ev
            {
                assert_eq!(call_id, &call_1001);
                assert!(!negotiated_codecs.is_empty());
                est_1001 = true;
            }
        }

        if let Some(cid2) = call_1002.clone() {
            if !sent_ring {
                sent_ring = true;
                ua_1002.ring(&cid2, Instant::now()).unwrap();
            } else if !sent_answer {
                sent_answer = true;
                ua_1002.answer(&cid2, 42000, Instant::now()).unwrap();
            }
        }

        if est_1001 && est_1002 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(est_1001, "1001 did not establish call: {:?}", events_1001);
    assert!(est_1002, "1002 did not establish call: {:?}", events_1002);
    assert_eq!(ua_1001.call_state(&call_1001), Some(CallState::Established));

    // Step 3: 1001 hangs up (BYE) and both sides terminate cleanly.
    ua_1001.hangup(&call_1001, Instant::now()).unwrap();

    let mut term_1001 = false;
    let mut term_1002 = false;
    let bye_deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < bye_deadline {
        let ev1_start = events_1001.len();
        let ev2_start = events_1002.len();
        pump_pair(
            &mut ua_1001,
            &sock_1001,
            &mut events_1001,
            &mut ua_1002,
            &sock_1002,
            &mut events_1002,
            asterisk_addr,
        );

        for ev in &events_1001[ev1_start..] {
            if matches!(ev, UaEvent::CallTerminated { .. }) {
                term_1001 = true;
            }
        }
        for ev in &events_1002[ev2_start..] {
            if matches!(ev, UaEvent::CallTerminated { .. }) {
                term_1002 = true;
            }
        }
        if term_1001 && term_1002 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    assert!(term_1001, "1001 did not terminate call: {:?}", events_1001);
    assert!(term_1002, "1002 did not terminate call: {:?}", events_1002);

    // Step 4: Unregister both endpoints cleanly.
    ua_1001.unregister(Instant::now()).unwrap();
    ua_1002.unregister(Instant::now()).unwrap();
    let unreg_deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < unreg_deadline {
        pump_pair(
            &mut ua_1001,
            &sock_1001,
            &mut events_1001,
            &mut ua_1002,
            &sock_1002,
            &mut events_1002,
            asterisk_addr,
        );
        if ua_1001.registration_state() == &RegistrationState::Unregistered
            && ua_1002.registration_state() == &RegistrationState::Unregistered
        {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        ua_1001.registration_state(),
        &RegistrationState::Unregistered
    );
    assert_eq!(
        ua_1002.registration_state(),
        &RegistrationState::Unregistered
    );
}
