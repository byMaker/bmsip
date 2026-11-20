use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use bmsip_core::dialog::{CallState, RegistrationState, UaConfig, UaEvent, UserAgent};
use bmsip_core::sdp::RtpCodec;
use bmsip_core::sip::SipUri;
use bmsip_engine::{EngineCommand, EngineConfig, EngineEvent, SipEngine, WavAudioPort};
use bmsip_media::{DtmfDigit, G711Kind, JitterBufferConfig, MediaSession, PlayoutFrame, WavPcm16};

static ASTERISK_TEST_MUTEX: Mutex<()> = Mutex::new(());

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
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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

fn pump_single(
    ua: &mut UserAgent,
    sock: &UdpSocket,
    events: &mut Vec<UaEvent>,
    asterisk_addr: SocketAddr,
) {
    for pkt in ua.poll_transmit() {
        sock.send_to(&pkt, asterisk_addr).expect("send sip");
    }
    let mut buf = [0u8; 8192];
    let now = Instant::now();
    loop {
        match sock.recv_from(&mut buf) {
            Ok((len, _)) => events.extend(ua.receive_datagram(&buf[..len], now)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => panic!("recv_from failed: {e}"),
        }
    }
    let now = Instant::now();
    if ua.poll_timeout().is_some_and(|dl| now >= dl) {
        events.extend(ua.handle_timeout(now));
    }
    events.extend(ua.drain_events());
    for pkt in ua.poll_transmit() {
        sock.send_to(&pkt, asterisk_addr).expect("send sip");
    }
}

#[test]
fn live_asterisk_rtp_g711_audio_echo_and_wav_roundtrip() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let asterisk_addr = resolve_asterisk();
    let local_ip = discover_local_ip(asterisk_addr);

    let sock_sip = UdpSocket::bind((local_ip, 0)).expect("bind sip");
    let sock_rtp = UdpSocket::bind((local_ip, 0)).expect("bind rtp");
    sock_sip.set_nonblocking(true).expect("nonblocking sip");
    sock_rtp.set_nonblocking(true).expect("nonblocking rtp");

    let sip_port = sock_sip.local_addr().unwrap().port();
    let rtp_port = sock_rtp.local_addr().unwrap().port();
    let registrar = SipUri::parse("sip:asterisk:5060").unwrap();

    let mut ua = UserAgent::new(UaConfig::new(
        "1001",
        "secret1001",
        "asterisk",
        registrar,
        local_ip.to_string(),
        sip_port,
    ));
    let mut events = Vec::new();

    // 1. Register 1001 with Asterisk.
    ua.register(Instant::now()).unwrap();
    let reg_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < reg_deadline {
        pump_single(&mut ua, &sock_sip, &mut events, asterisk_addr);
        if matches!(
            ua.registration_state(),
            RegistrationState::Registered { .. }
        ) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        ua.registration_state(),
        RegistrationState::Registered { .. }
    ));

    // 2. Dial extension 601 (Asterisk Echo()).
    let call_id = ua
        .dial(
            SipUri::parse("sip:601@asterisk:5060").unwrap(),
            rtp_port,
            Instant::now(),
        )
        .unwrap();

    let mut established_remote: Option<(SocketAddr, G711Kind)> = None;
    let call_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < call_deadline {
        let start = events.len();
        pump_single(&mut ua, &sock_sip, &mut events, asterisk_addr);
        for ev in &events[start..] {
            if let UaEvent::CallEstablished {
                remote_sdp,
                negotiated_codecs,
                ..
            } = ev
            {
                let codec = negotiated_codecs
                    .iter()
                    .find_map(|c| G711Kind::from_payload_type(c.payload_type))
                    .unwrap_or(G711Kind::Pcmu);
                let remote_ip: IpAddr = remote_sdp.connection_ip.parse().expect("valid remote IP");
                let remote_addr = SocketAddr::new(remote_ip, remote_sdp.audio_port);
                established_remote = Some((remote_addr, codec));
            }
        }
        if established_remote.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let (remote_rtp_addr, codec) = established_remote.expect("call to 601 did not establish");

    // 3. Stream 400 ms of 400 Hz test tone (20 x 20 ms PCM frames) plus 100 ms silence tail
    //    and collect echoed RTP packets from Asterisk Echo().
    let tone = WavPcm16::generate_sine_wave(8000, 400, 400, 12000);
    let mut media = MediaSession::new(
        codec,
        101,
        0x1001_2026,
        JitterBufferConfig {
            min_depth_frames: 2,
            max_depth_frames: 8,
            initial_depth_frames: 2,
            frame_samples: 160,
        },
    );

    let media_start = Instant::now();
    let mut frames_to_send: Vec<Vec<i16>> = tone
        .samples
        .as_chunks::<160>()
        .0
        .iter()
        .map(|c| c.to_vec())
        .collect();
    frames_to_send.extend(std::iter::repeat_n(vec![0i16; 160], 10));

    let mut rtp_buf = [0u8; 2048];
    for frame in &frames_to_send {
        let pkt = media.encode_pcm_frame(frame).unwrap();
        sock_rtp.send_to(&pkt, remote_rtp_addr).expect("send rtp");

        // Drain any echoed RTP packets and keep SIP signalling responsive.
        loop {
            match sock_rtp.recv_from(&mut rtp_buf) {
                Ok((len, _)) => {
                    let arrival_samples = (media_start.elapsed().as_millis() as u32) * 8;
                    let _ = media.receive_rtp(&rtp_buf[..len], arrival_samples);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => panic!("recv rtp failed: {e}"),
            }
        }
        pump_single(&mut ua, &sock_sip, &mut events, asterisk_addr);
        thread::sleep(Duration::from_millis(20));
    }

    // Drain tail echoed RTP packets for 150 ms.
    let drain_until = Instant::now() + Duration::from_millis(150);
    while Instant::now() < drain_until {
        loop {
            match sock_rtp.recv_from(&mut rtp_buf) {
                Ok((len, _)) => {
                    let arrival_samples = (media_start.elapsed().as_millis() as u32) * 8;
                    let _ = media.receive_rtp(&rtp_buf[..len], arrival_samples);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(e) => panic!("recv rtp failed: {e}"),
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    let rx_count = media.stats().received_count();
    assert!(
        rx_count >= 15,
        "expected >= 15 echoed RTP packets from Asterisk Echo(), got {rx_count}"
    );

    let mut echoed_samples = Vec::new();
    for _ in 0..(rx_count as usize + 4) {
        let pf = media.pop_playout_frame();
        if matches!(pf, PlayoutFrame::Normal(_) | PlayoutFrame::Concealed(_)) {
            echoed_samples.extend_from_slice(pf.samples());
        }
    }

    let echoed_wav = WavPcm16::new(8000, echoed_samples);
    let wav_bytes = echoed_wav.encode();
    let decoded_wav = WavPcm16::decode(&wav_bytes).unwrap();
    assert!(
        decoded_wav.rms_energy() > 1000,
        "expected echoed audio RMS > 1000, got {}",
        decoded_wav.rms_energy()
    );

    // 4. Hang up call and unregister cleanly.
    ua.hangup(&call_id, Instant::now()).unwrap();
    let bye_deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < bye_deadline {
        pump_single(&mut ua, &sock_sip, &mut events, asterisk_addr);
        if ua.call_state(&call_id).is_none() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ua.call_state(&call_id), None);

    ua.unregister(Instant::now()).unwrap();
    let unreg_deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < unreg_deadline {
        pump_single(&mut ua, &sock_sip, &mut events, asterisk_addr);
        if ua.registration_state() == &RegistrationState::Unregistered {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ua.registration_state(), &RegistrationState::Unregistered);
}

fn wait_for_engine_event<F>(
    engine: &SipEngine,
    timeout: Duration,
    mut pred: F,
) -> Option<EngineEvent>
where
    F: FnMut(&EngineEvent) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(50)) {
            if pred(&ev) {
                return Some(ev);
            }
        }
    }
    None
}

#[test]
fn live_asterisk_two_engines_call_audio_dtmf_lifecycle_and_blackbox() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let asterisk_addr = resolve_asterisk();
    let registrar = SipUri::parse("sip:asterisk:5060").unwrap();

    // Engine 1001 streams a 400 Hz tone via WavAudioPort.
    let tone_1001 = WavPcm16::generate_sine_wave(8000, 400, 1200, 12000);
    let (port_1001, _handle_1001) = WavAudioPort::new(tone_1001, true);
    let eng_1001 = SipEngine::spawn(
        EngineConfig::new(
            UaConfig::new(
                "1001",
                "secret1001",
                "asterisk",
                registrar.clone(),
                "0.0.0.0",
                0,
            ),
            asterisk_addr,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ),
        Box::new(port_1001),
    )
    .unwrap();

    // Engine 1002 records incoming audio from 1001 via WavAudioPort.
    let silence_1002 = WavPcm16::new(8000, vec![0; 160]);
    let (port_1002, handle_1002) = WavAudioPort::new(silence_1002, true);
    let eng_1002 = SipEngine::spawn(
        EngineConfig::new(
            UaConfig::new("1002", "secret1002", "asterisk", registrar, "0.0.0.0", 0),
            asterisk_addr,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ),
        Box::new(port_1002),
    )
    .unwrap();

    // 1. Register both independent SipEngine instances.
    eng_1001.send_command(EngineCommand::Register).unwrap();
    eng_1002.send_command(EngineCommand::Register).unwrap();

    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some()
    );

    // 2. 1001 dials 1002 through Asterisk.
    eng_1001
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:1002@asterisk:5060").unwrap(),
        })
        .unwrap();

    let call_id_1001 = match wait_for_engine_event(&eng_1001, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };

    let call_id_1002 = match wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall on 1002")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };

    eng_1002
        .send_command(EngineCommand::Ring {
            call_id: call_id_1002.clone(),
        })
        .unwrap();
    eng_1002
        .send_command(EngineCommand::Answer {
            call_id: call_id_1002.clone(),
        })
        .unwrap();

    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some()
    );

    // 3. Exchange live RTP audio for ~350 ms and transmit DTMF '5'.
    eng_1001
        .send_command(EngineCommand::SendDtmf {
            call_id: call_id_1001.clone(),
            digit: DtmfDigit::D5,
        })
        .unwrap();
    thread::sleep(Duration::from_millis(380));

    // 4. Hang up and inspect black-box telemetry JSON + recorded audio.
    eng_1001
        .send_command(EngineCommand::Hangup {
            call_id: call_id_1001.clone(),
        })
        .unwrap();

    let bb_1001 = match wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    })
    .expect("CallTerminated 1001")
    {
        EngineEvent::CallTerminated { black_box_json, .. } => black_box_json,
        _ => unreachable!(),
    };

    let bb_1002 = match wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    })
    .expect("CallTerminated 1002")
    {
        EngineEvent::CallTerminated { black_box_json, .. } => black_box_json,
        _ => unreachable!(),
    };

    for json in [&bb_1001, &bb_1002] {
        assert!(json.contains("\"call_id\""));
        assert!(json.contains("\"rtp_packets_sent\""));
        assert!(json.contains("\"rtp_packets_received\""));
        assert!(json.contains("\"events\""));
    }

    let recorded_1002 = handle_1002.recorded_wav();
    assert!(
        recorded_1002.rms_energy() > 1000,
        "expected recorded RMS > 1000 on 1002, got {}",
        recorded_1002.rms_energy()
    );

    // 5. Exercise Suspend / Resume lifecycle on 1001.
    eng_1001.send_command(EngineCommand::Suspend).unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(3), |e| matches!(
            e,
            EngineEvent::Suspended
        ))
        .is_some()
    );

    eng_1001.send_command(EngineCommand::Resume).unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(3), |e| matches!(
            e,
            EngineEvent::Resumed { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some()
    );

    // 6. Cleanly unregister and shut down both engines.
    eng_1001.send_command(EngineCommand::Unregister).unwrap();
    eng_1002.send_command(EngineCommand::Unregister).unwrap();
    let _ = wait_for_engine_event(&eng_1001, Duration::from_secs(4), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
        )
    });
    let _ = wait_for_engine_event(&eng_1002, Duration::from_secs(4), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
        )
    });

    eng_1001.send_command(EngineCommand::Shutdown).unwrap();
    eng_1002.send_command(EngineCommand::Shutdown).unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(3), |e| matches!(
            e,
            EngineEvent::Stopped
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(3), |e| matches!(
            e,
            EngineEvent::Stopped
        ))
        .is_some()
    );

    eng_1001.shutdown().unwrap();
    eng_1002.shutdown().unwrap();
}

#[test]
fn live_asterisk_opus_48khz_libopus_echo_and_two_engine_call() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let asterisk_addr = resolve_asterisk();
    let registrar = SipUri::parse("sip:asterisk:5060").unwrap();

    let mut ua_cfg = UaConfig::new("1001", "secret1001", "asterisk", registrar, "0.0.0.0", 0);
    ua_cfg.supported_codecs = vec![
        RtpCodec::opus(),
        RtpCodec::pcmu(),
        RtpCodec::pcma(),
        RtpCodec::telephone_event(101),
    ];

    let tone_48k = WavPcm16::generate_sine_wave(48_000, 400, 1200, 12_000);
    let (port, handle) = WavAudioPort::new(tone_48k, true);
    let engine = SipEngine::spawn(
        EngineConfig::new(ua_cfg, asterisk_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port),
    )
    .unwrap();

    engine.send_command(EngineCommand::Register).unwrap();
    assert!(
        wait_for_engine_event(&engine, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some()
    );

    engine
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:601@asterisk:5060").unwrap(),
        })
        .unwrap();

    let call_id = match wait_for_engine_event(&engine, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };

    let established_codec = match wait_for_engine_event(&engine, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::CallEstablished { .. })
    })
    .expect("CallEstablished")
    {
        EngineEvent::CallEstablished { codec, .. } => codec,
        _ => unreachable!(),
    };
    assert_eq!(established_codec, "OPUS");

    thread::sleep(Duration::from_millis(450));

    engine
        .send_command(EngineCommand::Hangup { call_id })
        .unwrap();
    assert!(
        wait_for_engine_event(&engine, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );

    engine.send_command(EngineCommand::Unregister).unwrap();
    let _ = wait_for_engine_event(&engine, Duration::from_secs(4), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
        )
    });
    engine.shutdown().unwrap();

    let recorded = handle.recorded_wav();
    assert_eq!(recorded.sample_rate, 48_000);
    assert!(
        recorded.rms_energy() > 2000,
        "expected echoed 48 kHz Opus WAV RMS > 2000, got {}",
        recorded.rms_energy()
    );
}
