use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bmsip_core::dialog::{CallState, RegistrationState, UaConfig, UaEvent, UserAgent};
use bmsip_core::sdp::{RtpCodec, SrtpMode};
use bmsip_core::sip::{SipTransport, SipUri};
use bmsip_engine::{
    EngineCommand, EngineConfig, EngineError, EngineEvent, SipEngine, TlsConfig, WavAudioPort,
};
use bmsip_media::{
    AudioCodecDescriptor, AudioCodecPlugin, DtmfDigit, FnCodecFactory, G711Kind,
    JitterBufferConfig, MediaError, MediaSession, PlayoutFrame, WavPcm16,
};

static ASTERISK_TEST_MUTEX: Mutex<()> = Mutex::new(());

fn resolve_server(host: &str) -> SocketAddr {
    (host, 5060)
        .to_socket_addrs()
        .expect("resolve server:5060")
        .next()
        .expect("at least one address for server:5060")
}

fn resolve_asterisk() -> SocketAddr {
    resolve_server("asterisk")
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

fn run_echo_opus_server_check(server_host: &str) {
    let server_addr = resolve_server(server_host);
    let registrar = SipUri::parse(&format!("sip:{server_host}:5060")).unwrap();
    let mut ua_cfg = UaConfig::new("1001", "secret1001", server_host, registrar, "0.0.0.0", 0);
    ua_cfg.supported_codecs = vec![
        RtpCodec::opus(),
        RtpCodec::pcmu(),
        RtpCodec::pcma(),
        RtpCodec::telephone_event(101),
    ];

    let tone_48k = WavPcm16::generate_sine_wave(48_000, 440, 1200, 12_000);
    let (port, handle) = WavAudioPort::new(tone_48k, true);
    let engine = SipEngine::spawn(
        EngineConfig::new(ua_cfg, server_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port),
    )
    .unwrap();

    engine.send_command(EngineCommand::Register).unwrap();
    assert!(
        wait_for_engine_event(&engine, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some(),
        "1001 failed to register on {server_host}"
    );

    engine
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:601@{server_host}:5060")).unwrap(),
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
    .unwrap_or_else(|| panic!("CallEstablished timed out on {server_host}"))
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
    assert!(
        recorded.rms_energy() > 2000,
        "expected {server_host} echoed 48 kHz Opus WAV RMS > 2000, got {}",
        recorded.rms_energy()
    );
}

#[test]
fn live_freeswitch_and_kamailio_multi_server_interop() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // 1. FreeSWITCH (Sofia-SIP, 407 Proxy-Auth, mod_opus Echo 601).
    run_echo_opus_server_check("freeswitch");

    // 2. Kamailio (RFC 3261 Proxy/Registrar, Record-Route/Route, dual Via, direct P2P RTP/DTMF).
    let kam_addr = resolve_server("kamailio");
    let registrar = SipUri::parse("sip:kamailio:5060").unwrap();

    let mut cfg_1001 = UaConfig::new(
        "1001",
        "secret1001",
        "kamailio",
        registrar.clone(),
        "0.0.0.0",
        0,
    );
    cfg_1001.supported_codecs = vec![
        RtpCodec::opus(),
        RtpCodec::pcmu(),
        RtpCodec::pcma(),
        RtpCodec::telephone_event(101),
    ];
    let tone_1001 = WavPcm16::generate_sine_wave(48_000, 440, 1200, 12_000);
    let (port_1001, _) = WavAudioPort::new(tone_1001, true);
    let eng_1001 = SipEngine::spawn(
        EngineConfig::new(cfg_1001, kam_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port_1001),
    )
    .unwrap();

    let mut cfg_1002 = UaConfig::new("1002", "secret1002", "kamailio", registrar, "0.0.0.0", 0);
    cfg_1002.supported_codecs = vec![
        RtpCodec::opus(),
        RtpCodec::pcmu(),
        RtpCodec::pcma(),
        RtpCodec::telephone_event(101),
    ];
    let silence_1002 = WavPcm16::new(48_000, vec![0; 960]);
    let (port_1002, handle_1002) = WavAudioPort::new(silence_1002, true);
    let eng_1002 = SipEngine::spawn(
        EngineConfig::new(cfg_1002, kam_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port_1002),
    )
    .unwrap();

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

    eng_1001
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:1002@kamailio:5060").unwrap(),
        })
        .unwrap();

    let call_1001 = match wait_for_engine_event(&eng_1001, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted on 1001")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };

    let call_1002 = match wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall on 1002 via Kamailio")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };

    eng_1002
        .send_command(EngineCommand::Ring {
            call_id: call_1002.clone(),
        })
        .unwrap();
    eng_1002
        .send_command(EngineCommand::Answer { call_id: call_1002 })
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

    thread::sleep(Duration::from_millis(450));

    eng_1001
        .send_command(EngineCommand::Hangup { call_id: call_1001 })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );

    for eng in [&eng_1001, &eng_1002] {
        eng.send_command(EngineCommand::Unregister).unwrap();
        let _ = wait_for_engine_event(eng, Duration::from_secs(4), |e| {
            matches!(
                e,
                EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
            )
        });
    }
    eng_1001.shutdown().unwrap();
    eng_1002.shutdown().unwrap();

    let recorded_1002 = handle_1002.recorded_wav();
    assert!(
        recorded_1002.rms_energy() > 1000,
        "expected P2P RTP RMS > 1000 through Kamailio proxy, got {}",
        recorded_1002.rms_energy()
    );
}

#[derive(Debug)]
struct CustomL16Plugin {
    descriptor: AudioCodecDescriptor,
}

impl CustomL16Plugin {
    fn descriptor_spec() -> AudioCodecDescriptor {
        AudioCodecDescriptor::new(98, "L16", 16_000, 16_000)
    }

    fn new() -> Self {
        Self {
            descriptor: Self::descriptor_spec(),
        }
    }
}

impl AudioCodecPlugin for CustomL16Plugin {
    fn descriptor(&self) -> &AudioCodecDescriptor {
        &self.descriptor
    }

    fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        let mut out = Vec::with_capacity(pcm.len() * 2);
        for &s in pcm {
            out.extend_from_slice(&s.to_be_bytes());
        }
        Ok(out)
    }

    fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
        let mut out = Vec::with_capacity(payload.len() / 2);
        for chunk in payload.as_chunks::<2>().0 {
            out.push(i16::from_be_bytes([chunk[0], chunk[1]]));
        }
        Ok(out)
    }
}

fn run_echo_g722_server_check(server_host: &str) {
    let server_addr = resolve_server(server_host);
    let registrar = SipUri::parse(&format!("sip:{server_host}:5060")).unwrap();
    let mut ua_cfg = UaConfig::new("1001", "secret1001", server_host, registrar, "0.0.0.0", 0);
    ua_cfg.supported_codecs = vec![
        RtpCodec::g722(),
        RtpCodec::pcmu(),
        RtpCodec::pcma(),
        RtpCodec::telephone_event(101),
    ];

    let tone_16k = WavPcm16::generate_sine_wave(16_000, 3_000, 1_200, 12_000);
    let (port, handle) = WavAudioPort::new(tone_16k, true);
    let engine = SipEngine::spawn(
        EngineConfig::new(ua_cfg, server_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port),
    )
    .unwrap();

    engine.send_command(EngineCommand::Register).unwrap();
    assert!(
        wait_for_engine_event(&engine, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some(),
        "1001 failed G.722 registration on {server_host}"
    );

    engine
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:601@{server_host}:5060")).unwrap(),
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
    .unwrap_or_else(|| panic!("G.722 CallEstablished timed out on {server_host}"))
    {
        EngineEvent::CallEstablished { codec, .. } => codec,
        _ => unreachable!(),
    };
    assert_eq!(established_codec, "G722");

    thread::sleep(Duration::from_millis(500));

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
    assert_eq!(recorded.sample_rate, 16_000);
    assert!(
        recorded.rms_energy() > 2000,
        "expected {server_host} echoed 16 kHz G.722 WAV RMS > 2000, got {}",
        recorded.rms_energy()
    );
}

#[test]
fn live_g722_and_custom_codec_plugin_interop() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // 1. Live G.722 16 kHz wideband echo against Asterisk and FreeSWITCH.
    run_echo_g722_server_check("asterisk");
    run_echo_g722_server_check("freeswitch");

    // 2. External custom pluggable codec (L16/16000) registered via EngineConfig over Kamailio proxy.
    let kam_addr = resolve_server("kamailio");
    let registrar = SipUri::parse("sip:kamailio:5060").unwrap();
    let factory = Arc::new(FnCodecFactory::new(
        CustomL16Plugin::descriptor_spec(),
        || Box::new(CustomL16Plugin::new()),
    ));

    let mut cfg_1001 = EngineConfig::new(
        UaConfig::new(
            "1001",
            "secret1001",
            "kamailio",
            registrar.clone(),
            "0.0.0.0",
            0,
        ),
        kam_addr,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    );
    cfg_1001.register_custom_codec(Arc::clone(&factory) as Arc<dyn bmsip_media::AudioCodecFactory>);

    let tone_1001 = WavPcm16::generate_sine_wave(16_000, 1_000, 1_200, 12_000);
    let (port_1001, _) = WavAudioPort::new(tone_1001, true);
    let eng_1001 = SipEngine::spawn(cfg_1001, Box::new(port_1001)).unwrap();

    let mut cfg_1002 = EngineConfig::new(
        UaConfig::new("1002", "secret1002", "kamailio", registrar, "0.0.0.0", 0),
        kam_addr,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    );
    cfg_1002.register_custom_codec(factory);

    let silence_1002 = WavPcm16::new(16_000, vec![0; 320]);
    let (port_1002, handle_1002) = WavAudioPort::new(silence_1002, true);
    let eng_1002 = SipEngine::spawn(cfg_1002, Box::new(port_1002)).unwrap();

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

    eng_1001
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:1002@kamailio:5060").unwrap(),
        })
        .unwrap();

    let call_1001 = match wait_for_engine_event(&eng_1001, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };
    let call_1002 = match wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    eng_1002
        .send_command(EngineCommand::Answer { call_id: call_1002 })
        .unwrap();

    let neg_codec = match wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::CallEstablished { .. })
    })
    .expect("CallEstablished")
    {
        EngineEvent::CallEstablished { codec, .. } => codec,
        _ => unreachable!(),
    };
    assert_eq!(neg_codec, "L16");
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some()
    );

    thread::sleep(Duration::from_millis(450));

    eng_1001
        .send_command(EngineCommand::Hangup { call_id: call_1001 })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );

    for eng in [&eng_1001, &eng_1002] {
        eng.send_command(EngineCommand::Unregister).unwrap();
        let _ = wait_for_engine_event(eng, Duration::from_secs(4), |e| {
            matches!(
                e,
                EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
            )
        });
    }
    eng_1001.shutdown().unwrap();
    eng_1002.shutdown().unwrap();

    let recorded_1002 = handle_1002.recorded_wav();
    assert!(
        recorded_1002.rms_energy() > 3000,
        "expected custom L16 plugin RTP RMS > 3000 over Kamailio proxy, got {}",
        recorded_1002.rms_energy()
    );
}

#[test]
fn engine_routes_direct_peer_responses_and_supports_bounded_audio_ports() {
    use bmsip_engine::{AudioPort, PcmQueueAudioPort};

    // 1. Verify WavAudioPort opt-out and bounded RX recording prevent unbounded memory growth.
    let (mut silent_rec_port, silent_handle) =
        WavAudioPort::new_with_recording(WavPcm16::new(48_000, vec![0; 960]), true, false);
    silent_rec_port.playout_20ms(&[1000i16; 960]);
    assert!(silent_handle.recorded_wav().samples.is_empty());

    let (capped_port, capped_handle) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
    let mut capped_port = capped_port.with_max_recorded_samples(Some(240));
    capped_port.playout_20ms(&[500i16; 160]);
    capped_port.playout_20ms(&[500i16; 160]);
    assert_eq!(capped_handle.recorded_wav().samples.len(), 240);

    // 2. Verify PcmQueueAudioPort supports native 48 kHz 960-sample HD frames.
    let (mut pcm48_port, pcm48_handle) = PcmQueueAudioPort::new_with_sample_rate(48_000, 8);
    assert_eq!(pcm48_port.sample_rate_hz(), 48_000);
    assert_eq!(pcm48_handle.frame_samples(), 960);
    assert!(pcm48_handle.push_captured_samples(vec![0; 160]).is_err());
    pcm48_handle
        .push_captured_samples(vec![1234; 960])
        .expect("960-sample 48 kHz frame accepted");
    assert_eq!(pcm48_port.capture_frame_20ms(), vec![1234; 960]);

    // 3. Verify SipEngine routes server responses back to the exact UDP peer source (RFC 3581),
    //    even when the peer address differs from `registrar_addr`.
    let dummy_registrar = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
    let ua_cfg = UaConfig::new(
        "peer1",
        "pw",
        "127.0.0.1",
        SipUri::parse("sip:127.0.0.1:1").unwrap(),
        "127.0.0.1",
        0,
    );
    let eng_cfg = EngineConfig::new(ua_cfg, dummy_registrar, IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let (audio_port, _) =
        WavAudioPort::new_with_recording(WavPcm16::new(8_000, vec![0; 160]), true, false);
    let engine = SipEngine::spawn(eng_cfg, Box::new(audio_port)).unwrap();
    let eng_addr = engine.local_sip_addr();

    let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    peer_sock
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let peer_addr = peer_sock.local_addr().unwrap();

    let options = format!(
        "OPTIONS sip:peer1@{eng_addr} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer_addr};branch=z9hG4bK-direct-opt-1;rport\r\n\
         From: <sip:tester@127.0.0.1>;tag=t1\r\n\
         To: <sip:peer1@127.0.0.1>\r\n\
         Call-ID: direct-opt-1\r\n\
         CSeq: 1 OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    );
    peer_sock.send_to(options.as_bytes(), eng_addr).unwrap();

    let mut buf = [0u8; 2048];
    let (len, from_addr) = peer_sock
        .recv_from(&mut buf)
        .expect("expected 200 OK routed directly to peer_sock");
    assert_eq!(from_addr, eng_addr);
    let text = std::str::from_utf8(&buf[..len]).unwrap();
    assert!(
        text.starts_with("SIP/2.0 200 OK"),
        "unexpected response: {text}"
    );

    engine.shutdown().unwrap();
}

#[test]
fn live_asterisk_call_hold_and_resume_mutes_and_restores_audio() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let asterisk_addr = resolve_asterisk();
    let registrar = SipUri::parse("sip:asterisk:5060").unwrap();

    let tone_1001 = WavPcm16::generate_sine_wave(8000, 440, 1500, 12000);
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

    thread::sleep(Duration::from_millis(200));

    // Place call on hold via re-INVITE (a=sendonly) and wait for negotiation completion.
    eng_1001
        .send_command(EngineCommand::Hold {
            call_id: call_id_1001.clone(),
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallHoldChanged {
                local_hold: true,
                remote_hold: false,
                ..
            }
        ))
        .is_some(),
        "expected CallHoldChanged(local_hold=true)"
    );
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallMediaUpdated { .. }
        ))
        .is_some(),
        "expected CallMediaUpdated after hold re-INVITE 200 OK"
    );

    thread::sleep(Duration::from_millis(250));

    // Resume call via re-INVITE (a=sendrecv) and verify RTP audio flows again.
    eng_1001
        .send_command(EngineCommand::ResumeCall {
            call_id: call_id_1001.clone(),
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallHoldChanged {
                local_hold: false,
                remote_hold: false,
                ..
            }
        ))
        .is_some(),
        "expected CallHoldChanged(local_hold=false)"
    );
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallMediaUpdated { .. }
        ))
        .is_some(),
        "expected CallMediaUpdated after resume re-INVITE 200 OK"
    );

    thread::sleep(Duration::from_millis(350));

    eng_1001
        .send_command(EngineCommand::Hangup {
            call_id: call_id_1001,
        })
        .unwrap();

    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );

    let recorded_1002 = handle_1002.recorded_wav();
    assert!(
        recorded_1002.rms_energy() > 1000,
        "expected resumed call RMS > 1000 on 1002, got {}",
        recorded_1002.rms_energy()
    );

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

    eng_1001.shutdown().unwrap();
    eng_1002.shutdown().unwrap();
}

#[test]
fn live_early_media_183_audio_and_sip_info_dtmf_exchange() {
    let dummy_registrar = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

    let bob_tone = WavPcm16::generate_sine_wave(8_000, 440, 1_500, 12_000);
    let (bob_port, _) = WavAudioPort::new_with_recording(bob_tone, true, false);
    let bob_ua = UaConfig::new(
        "bob",
        "pw",
        "127.0.0.1",
        SipUri::parse("sip:127.0.0.1:1").unwrap(),
        "127.0.0.1",
        0,
    );
    let eng_bob = SipEngine::spawn(
        EngineConfig::new(bob_ua, dummy_registrar, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(bob_port),
    )
    .unwrap();
    let bob_addr = eng_bob.local_sip_addr();

    let alice_silence = WavPcm16::new(8_000, vec![0; 160]);
    let (alice_port, alice_handle) = WavAudioPort::new(alice_silence, true);
    let alice_ua = UaConfig::new(
        "alice",
        "pw",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{bob_addr}")).unwrap(),
        "127.0.0.1",
        0,
    );
    let eng_alice = SipEngine::spawn(
        EngineConfig::new(alice_ua, bob_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(alice_port),
    )
    .unwrap();

    eng_alice
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:bob@{bob_addr}")).unwrap(),
        })
        .unwrap();

    let call_alice = match wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };

    let call_bob = match wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall on bob")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };

    // Bob replies with 183 Session Progress early-media SDP (no 200 OK yet).
    eng_bob
        .send_command(EngineCommand::RingEarlyMedia {
            call_id: call_bob.clone(),
        })
        .unwrap();

    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::EarlyMediaStarted { .. }
        ))
        .is_some(),
        "expected EarlyMediaStarted on bob"
    );
    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallRinging {
                status_code: 183,
                ..
            }
        ))
        .is_some(),
        "expected 183 CallRinging on alice"
    );
    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::EarlyMediaStarted { .. }
        ))
        .is_some(),
        "expected EarlyMediaStarted on alice"
    );

    // Let early-media RTP stream while still in early Ringing state, then verify INFO DTMF.
    thread::sleep(Duration::from_millis(320));
    let early_rms = alice_handle.recorded_wav().rms_energy();
    assert!(
        early_rms > 1000,
        "expected early-media 183 audio RMS > 1000 before 200 OK, got {early_rms}"
    );

    eng_alice
        .send_command(EngineCommand::SendInfoDtmf {
            call_id: call_alice.clone(),
            digit: DtmfDigit::Star,
            duration_ms: 180,
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::DtmfReceived {
                digit: DtmfDigit::Star,
                ..
            }
        ))
        .is_some(),
        "expected DtmfReceived('*') on bob via SIP INFO"
    );

    // Now transition smoothly from early media into established 200 OK reusing the same RTP socket.
    eng_bob
        .send_command(EngineCommand::Answer { call_id: call_bob })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some(),
        "expected CallEstablished on alice"
    );
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some(),
        "expected CallEstablished on bob"
    );

    eng_alice
        .send_command(EngineCommand::Hangup {
            call_id: call_alice,
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );

    eng_alice.shutdown().unwrap();
    eng_bob.shutdown().unwrap();
}

#[test]
fn live_sip_over_tcp_and_tls_asterisk_and_freeswitch_echo_calls() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let scenarios = [
        (
            "Asterisk-TCP",
            "asterisk",
            5060u16,
            SipTransport::Tcp,
            TlsConfig::default(),
            "sip:601@asterisk:5060;transport=tcp",
        ),
        (
            "Asterisk-TLS",
            "asterisk",
            5061u16,
            SipTransport::Tls,
            TlsConfig::new()
                .with_server_name("asterisk")
                .with_accept_invalid_certs(true),
            "sip:601@asterisk:5061;transport=tls",
        ),
        (
            "FreeSWITCH-TCP",
            "freeswitch",
            5060u16,
            SipTransport::Tcp,
            TlsConfig::default(),
            "sip:601@freeswitch:5060;transport=tcp",
        ),
    ];

    for (label, host, port, transport, tls_cfg, target_str) in scenarios {
        let server_addr = (host, port)
            .to_socket_addrs()
            .expect("resolve SIP server")
            .next()
            .expect("resolved socket addr");
        let registrar_uri =
            SipUri::parse(&format!("sip:{host}:{port};transport={transport}")).unwrap();

        let tone = WavPcm16::generate_sine_wave(8_000, 440, 1_200, 12_000);
        let (audio_port, handle) = WavAudioPort::new(tone, true);
        let ua_cfg = UaConfig::new("1001", "secret1001", host, registrar_uri, "0.0.0.0", 0)
            .with_transport(transport);
        let eng_cfg = EngineConfig::new(ua_cfg, server_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            .with_tls_config(tls_cfg);
        let engine = SipEngine::spawn(eng_cfg, Box::new(audio_port)).unwrap();

        engine.send_command(EngineCommand::Register).unwrap();
        assert!(
            wait_for_engine_event(&engine, Duration::from_secs(10), |e| matches!(
                e,
                EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
            ))
            .is_some(),
            "{label}: REGISTER did not succeed"
        );

        engine
            .send_command(EngineCommand::Dial {
                target_uri: SipUri::parse(target_str).unwrap(),
            })
            .unwrap();
        let mut call_id: Option<String> = None;
        let mut established = false;
        let dl = Instant::now() + Duration::from_secs(10);
        while Instant::now() < dl {
            if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(50)) {
                match ev {
                    EngineEvent::OutboundCallStarted { call_id: cid } => call_id = Some(cid),
                    EngineEvent::CallEstablished { .. } => {
                        established = true;
                        break;
                    }
                    EngineEvent::CallTerminated { reason, .. } => {
                        panic!("{label}: call terminated prematurely: {reason}");
                    }
                    _ => {}
                }
            }
        }
        assert!(established, "{label}: INVITE echo call did not establish");

        thread::sleep(Duration::from_millis(450));

        engine
            .send_command(EngineCommand::Hangup {
                call_id: call_id.expect("call_id"),
            })
            .unwrap();
        assert!(
            wait_for_engine_event(&engine, Duration::from_secs(6), |e| matches!(
                e,
                EngineEvent::CallTerminated { .. }
            ))
            .is_some(),
            "{label}: call did not terminate cleanly after BYE"
        );

        engine.send_command(EngineCommand::Unregister).unwrap();
        assert!(
            wait_for_engine_event(&engine, Duration::from_secs(4), |e| matches!(
                e,
                EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
            ))
            .is_some(),
            "{label}: clean Unregister did not complete"
        );

        engine.shutdown().unwrap();

        let recorded = handle.recorded_wav();
        assert!(
            recorded.rms_energy() > 1000,
            "{label}: expected echoed RTP RMS > 1000, got {}",
            recorded.rms_energy()
        );
    }
}

#[test]
fn live_p2p_tls_verified_ca_mtls_and_untrusted_rejection() {
    // Generate a private root CA, server certificate, client mTLS certificate, and an unrelated untrusted CA.
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    let srv_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let srv_key = rcgen::KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let cli_params = rcgen::CertificateParams::new(vec!["alice.local".to_string()]).unwrap();
    let cli_key = rcgen::KeyPair::generate().unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

    let mut other_ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    other_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let other_ca_key = rcgen::KeyPair::generate().unwrap();
    let other_ca_cert = other_ca_params.self_signed(&other_ca_key).unwrap();

    let dummy_registrar = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

    // 1. Spawn Bob as a strict mTLS TLS-server peer.
    let bob_tls = TlsConfig::new()
        .with_ca_cert_pem(ca_pem.clone())
        .with_server_identity(srv_cert.pem(), srv_key.serialize_pem());
    let bob_ua = UaConfig::new(
        "bob",
        "pw",
        "localhost",
        SipUri::parse("sip:127.0.0.1:1;transport=tls").unwrap(),
        "127.0.0.1",
        0,
    )
    .with_transport(SipTransport::Tls);
    let (bob_port, bob_handle) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
    let eng_bob = SipEngine::spawn(
        EngineConfig::new(bob_ua, dummy_registrar, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .with_tls_config(bob_tls),
        Box::new(bob_port),
    )
    .unwrap();
    let bob_addr = eng_bob.local_sip_addr();

    // 2. Spawn Alice as a pure TLS client (no server cert) with verified CA + mTLS client identity.
    let alice_tls = TlsConfig::new()
        .with_server_name("localhost")
        .with_ca_cert_pem(ca_pem)
        .with_client_identity(cli_cert.pem(), cli_key.serialize_pem());
    let alice_ua = UaConfig::new(
        "alice",
        "pw",
        "localhost",
        SipUri::parse(&format!("sip:{bob_addr};transport=tls")).unwrap(),
        "127.0.0.1",
        0,
    )
    .with_transport(SipTransport::Tls);
    let tone = WavPcm16::generate_sine_wave(8_000, 600, 1_000, 12_000);
    let (alice_port, _) = WavAudioPort::new(tone, true);
    let eng_alice = SipEngine::spawn(
        EngineConfig::new(alice_ua, bob_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .with_tls_config(alice_tls),
        Box::new(alice_port),
    )
    .unwrap();

    eng_alice
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:bob@{bob_addr};transport=tls")).unwrap(),
        })
        .unwrap();

    let call_bob = match wait_for_engine_event(&eng_bob, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall over mTLS on bob")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    eng_bob
        .send_command(EngineCommand::Answer {
            call_id: call_bob.clone(),
        })
        .unwrap();

    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some(),
        "expected mTLS CallEstablished on alice"
    );
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some(),
        "expected mTLS CallEstablished on bob"
    );

    thread::sleep(Duration::from_millis(350));

    // Bob (server) hangs up -> must reuse Alice's inbound TLS connection (RFC 5923) even though Alice has no server cert.
    eng_bob
        .send_command(EngineCommand::Hangup { call_id: call_bob })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some(),
        "expected BYE over reused TLS connection on alice"
    );
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::CallTerminated { .. }
        ))
        .is_some()
    );

    assert!(
        bob_handle.recorded_wav().rms_energy() > 1000,
        "expected mTLS RTP RMS > 1000 on bob, got {}",
        bob_handle.recorded_wav().rms_energy()
    );

    // 3. Spawn an untrusted client (different CA, strict verification) and confirm TLS handshake is rejected.
    let bad_tls = TlsConfig::new()
        .with_server_name("localhost")
        .with_ca_cert_pem(other_ca_cert.pem());
    let bad_ua = UaConfig::new(
        "mallory",
        "pw",
        "localhost",
        SipUri::parse(&format!("sip:{bob_addr};transport=tls")).unwrap(),
        "127.0.0.1",
        0,
    )
    .with_transport(SipTransport::Tls);
    let (bad_port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
    let eng_bad = SipEngine::spawn(
        EngineConfig::new(bad_ua, bob_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .with_tls_config(bad_tls),
        Box::new(bad_port),
    )
    .unwrap();

    eng_bad
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:bob@{bob_addr};transport=tls")).unwrap(),
        })
        .unwrap();

    let got_tls_warning = wait_for_engine_event(
        &eng_bad,
        Duration::from_secs(5),
        |e| matches!(e, EngineEvent::Warning(msg) if msg.contains("TLS")),
    );
    assert!(
        got_tls_warning.is_some(),
        "expected strict rustls TLS verification warning against untrusted CA"
    );

    eng_bad.shutdown().unwrap();
    eng_alice.shutdown().unwrap();
    eng_bob.shutdown().unwrap();
}

#[test]
fn live_asterisk_tls_plus_sdes_srtp_encrypted_echo_call() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let asterisk_tls_addr = ("asterisk", 5061u16)
        .to_socket_addrs()
        .expect("resolve asterisk:5061")
        .next()
        .expect("asterisk:5061 socket addr");
    let registrar_uri = SipUri::parse("sip:asterisk:5061;transport=tls").unwrap();

    // Endpoint 1004 on Asterisk is configured with `media_encryption=sdes` (`res_srtp.so`).
    let tone = WavPcm16::generate_sine_wave(8_000, 440, 1_200, 12_000);
    let (audio_port, handle) = WavAudioPort::new(tone, true);
    let ua_cfg = UaConfig::new(
        "1004",
        "secret1004",
        "asterisk",
        registrar_uri,
        "0.0.0.0",
        0,
    )
    .with_transport(SipTransport::Tls)
    .with_srtp_mode(SrtpMode::SdesRequired);
    let tls_cfg = TlsConfig::new()
        .with_server_name("asterisk")
        .with_accept_invalid_certs(true);
    let eng_cfg = EngineConfig::new(
        ua_cfg,
        asterisk_tls_addr,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    )
    .with_tls_config(tls_cfg);

    let engine = SipEngine::spawn(eng_cfg, Box::new(audio_port)).unwrap();
    engine.send_command(EngineCommand::Register).unwrap();
    assert!(
        wait_for_engine_event(&engine, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some(),
        "1004 failed to register over TLS"
    );

    engine
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:601@asterisk:5061;transport=tls").unwrap(),
        })
        .unwrap();

    let mut call_id: Option<String> = None;
    let mut established = false;
    let dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < dl {
        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(50)) {
            match ev {
                EngineEvent::OutboundCallStarted { call_id: cid } => call_id = Some(cid),
                EngineEvent::CallEstablished { .. } => {
                    established = true;
                    break;
                }
                EngineEvent::CallTerminated { reason, .. } => {
                    panic!("Asterisk TLS+SDES-SRTP call terminated early: {reason}");
                }
                _ => {}
            }
        }
    }
    assert!(established, "Asterisk TLS+SDES-SRTP call did not establish");

    thread::sleep(Duration::from_millis(450));

    engine
        .send_command(EngineCommand::Hangup {
            call_id: call_id.expect("call_id"),
        })
        .unwrap();
    let term_ev = wait_for_engine_event(&engine, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    })
    .expect("CallTerminated after TLS+SRTP call");
    if let EngineEvent::CallTerminated { black_box_json, .. } = term_ev {
        assert!(
            black_box_json.contains("SRTP (SDES) enabled"),
            "expected Black-Box JSON to record SRTP (SDES) activation: {black_box_json}"
        );
    }

    engine.send_command(EngineCommand::Unregister).unwrap();
    let _ = wait_for_engine_event(&engine, Duration::from_secs(4), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
        )
    });
    engine.shutdown().unwrap();

    let recorded = handle.recorded_wav();
    assert!(
        recorded.rms_energy() > 1000,
        "expected decrypted SDES-SRTP audio from Asterisk res_srtp RMS > 1000, got {}",
        recorded.rms_energy()
    );
}

#[test]
fn enforces_sdes_requires_tls_nonblocking_tcp_connect_and_p2p_tls_sdes_hold_call() {
    let dummy_registrar = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

    // 1. SdesRequired over unencrypted UDP or TCP must be rejected by default (RFC 4568 §8).
    for insecure_transport in [SipTransport::Udp, SipTransport::Tcp] {
        let ua = UaConfig::new(
            "alice",
            "pw",
            "127.0.0.1",
            SipUri::parse("sip:127.0.0.1:1").unwrap(),
            "127.0.0.1",
            0,
        )
        .with_transport(insecure_transport)
        .with_srtp_mode(SrtpMode::SdesRequired);
        let (port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
        let err = SipEngine::spawn(
            EngineConfig::new(ua, dummy_registrar, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Box::new(port),
        )
        .err()
        .expect("SdesRequired without TLS must fail to spawn");
        assert!(
            matches!(err, EngineError::InvalidConfig(_)),
            "expected InvalidConfig for SdesRequired over {insecure_transport}, got {err:?}"
        );
    }

    // 2. Non-blocking TCP connect: dialing an unreachable blackhole IP (RFC 5737 TEST-NET-1)
    //    must NEVER freeze the engine worker thread during the 3 s TCP connect timeout.
    let blackhole_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 5060);
    let nb_ua = UaConfig::new(
        "alice",
        "pw",
        "192.0.2.1",
        SipUri::parse("sip:192.0.2.1:5060;transport=tcp").unwrap(),
        "127.0.0.1",
        0,
    )
    .with_transport(SipTransport::Tcp);
    let (nb_port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
    let nb_eng = SipEngine::spawn(
        EngineConfig::new(nb_ua, blackhole_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(nb_port),
    )
    .unwrap();
    let t_start = Instant::now();
    nb_eng.send_command(EngineCommand::Register).unwrap();
    nb_eng
        .send_command(EngineCommand::ExportTelemetry { call_id: None })
        .unwrap();
    let telem = wait_for_engine_event(&nb_eng, Duration::from_millis(800), |e| {
        matches!(e, EngineEvent::TelemetryExported { .. })
    });
    assert!(
        telem.is_some(),
        "engine worker must stay responsive while TCP connect is pending"
    );
    assert!(
        t_start.elapsed() < Duration::from_millis(800),
        "non-blocking TCP connect stalled worker for {:?}",
        t_start.elapsed()
    );
    nb_eng.shutdown().unwrap();

    // 3. Live P2P verified TLS + SDES-SRTP (`SdesRequired`) call with DTMF + mid-call Hold/Resume re-INVITE.
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    let srv_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let srv_key = rcgen::KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let bob_tls = TlsConfig::new().with_server_identity(srv_cert.pem(), srv_key.serialize_pem());
    let bob_ua = UaConfig::new(
        "bob",
        "pw",
        "localhost",
        SipUri::parse("sip:127.0.0.1:1;transport=tls").unwrap(),
        "127.0.0.1",
        0,
    )
    .with_transport(SipTransport::Tls)
    .with_srtp_mode(SrtpMode::SdesRequired);
    let (bob_port, bob_handle) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
    let eng_bob = SipEngine::spawn(
        EngineConfig::new(bob_ua, dummy_registrar, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .with_tls_config(bob_tls),
        Box::new(bob_port),
    )
    .unwrap();
    let bob_addr = eng_bob.local_sip_addr();

    let alice_tls = TlsConfig::new()
        .with_server_name("localhost")
        .with_ca_cert_pem(ca_pem);
    let alice_ua = UaConfig::new(
        "alice",
        "pw",
        "localhost",
        SipUri::parse(&format!("sip:{bob_addr};transport=tls")).unwrap(),
        "127.0.0.1",
        0,
    )
    .with_transport(SipTransport::Tls)
    .with_srtp_mode(SrtpMode::SdesRequired);
    let tone = WavPcm16::generate_sine_wave(8_000, 500, 1_500, 12_000);
    let (alice_port, _) = WavAudioPort::new(tone, true);
    let eng_alice = SipEngine::spawn(
        EngineConfig::new(alice_ua, bob_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .with_tls_config(alice_tls),
        Box::new(alice_port),
    )
    .unwrap();

    eng_alice
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:bob@{bob_addr};transport=tls")).unwrap(),
        })
        .unwrap();

    let call_alice = match wait_for_engine_event(&eng_alice, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted on alice")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };

    let call_bob = match wait_for_engine_event(&eng_bob, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall on bob")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    eng_bob
        .send_command(EngineCommand::Answer {
            call_id: call_bob.clone(),
        })
        .unwrap();

    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some()
    );
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(6), |e| matches!(
            e,
            EngineEvent::CallEstablished { .. }
        ))
        .is_some()
    );

    // Exchange encrypted SRTP audio + DTMF, then exercise mid-call Hold & Resume over TLS + SDES-SRTP.
    thread::sleep(Duration::from_millis(160));
    eng_alice
        .send_command(EngineCommand::Hold {
            call_id: call_alice.clone(),
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallHoldChanged {
                remote_hold: true,
                ..
            }
        ))
        .is_some(),
        "expected remote_hold=true on bob"
    );
    assert!(
        wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallMediaUpdated { .. }
        ))
        .is_some(),
        "expected hold re-INVITE 200 OK completion on alice"
    );

    eng_alice
        .send_command(EngineCommand::ResumeCall {
            call_id: call_alice.clone(),
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::CallHoldChanged {
                remote_hold: false,
                ..
            }
        ))
        .is_some(),
        "expected remote_hold=false on bob after resume"
    );

    eng_alice
        .send_command(EngineCommand::SendDtmf {
            call_id: call_alice.clone(),
            digit: DtmfDigit::D7,
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| matches!(
            e,
            EngineEvent::DtmfReceived {
                digit: DtmfDigit::D7,
                ..
            }
        ))
        .is_some(),
        "expected encrypted RFC 4733 DTMF '7' over TLS+SDES-SRTP on bob after hold/resume"
    );
    thread::sleep(Duration::from_millis(200));

    eng_alice
        .send_command(EngineCommand::Hangup {
            call_id: call_alice,
        })
        .unwrap();
    let term_alice = wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    })
    .expect("alice CallTerminated");
    if let EngineEvent::CallTerminated { black_box_json, .. } = term_alice {
        assert!(
            black_box_json.contains("SRTP (SDES) enabled"),
            "expected SDES-SRTP telemetry entry in black_box_json: {black_box_json}"
        );
    }
    let _ = wait_for_engine_event(&eng_bob, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    });

    assert!(
        bob_handle.recorded_wav().rms_energy() > 1000,
        "expected decrypted SDES-SRTP audio RMS > 1000 on bob, got {}",
        bob_handle.recorded_wav().rms_energy()
    );

    eng_alice.shutdown().unwrap();
    eng_bob.shutdown().unwrap();
}

fn goertzel_power(samples: &[i16], sample_rate_hz: f64, target_freq_hz: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let omega = 2.0 * std::f64::consts::PI * target_freq_hz / sample_rate_hz;
    let coeff = 2.0 * omega.cos();
    let mut s_prev = 0.0f64;
    let mut s_prev2 = 0.0f64;
    for &sample in samples {
        let s = f64::from(sample) + coeff * s_prev - s_prev2;
        s_prev2 = s_prev;
        s_prev = s;
    }
    let real = s_prev - s_prev2 * omega.cos();
    let imag = s_prev2 * omega.sin();
    (real * real + imag * imag) / ((samples.len() as f64) * (samples.len() as f64))
}

#[test]
fn p0_g722_5500hz_transcodes_through_freeswitch_to_opus_48khz() {
    let _guard = ASTERISK_TEST_MUTEX
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let fs_addr = resolve_server("freeswitch");
    let registrar = SipUri::parse("sip:freeswitch:5060").unwrap();

    // Caller 1001 forces G.722 (16 kHz) with a high-band 5500 Hz sine wave (testing QMF upper band).
    let mut cfg_1001 = UaConfig::new(
        "1001",
        "secret1001",
        "freeswitch",
        registrar.clone(),
        "0.0.0.0",
        0,
    );
    cfg_1001.supported_codecs = vec![RtpCodec::g722(), RtpCodec::telephone_event(101)];
    let tone_5500 = WavPcm16::generate_sine_wave(16_000, 5_500, 2_200, 12_000);
    let (port_1001, _) = WavAudioPort::new(tone_5500, true);
    let eng_1001 = SipEngine::spawn(
        EngineConfig::new(cfg_1001, fs_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port_1001),
    )
    .unwrap();

    // Callee 1002 forces native Opus (48 kHz) so FreeSWITCH bridges & transcodes G.722 <-> Opus.
    let mut cfg_1002 = UaConfig::new("1002", "secret1002", "freeswitch", registrar, "0.0.0.0", 0);
    cfg_1002.supported_codecs = vec![RtpCodec::opus(), RtpCodec::telephone_event_48k(102)];
    let (port_1002, handle_1002) = WavAudioPort::new(WavPcm16::new(48_000, vec![0; 960]), true);
    let eng_1002 = SipEngine::spawn(
        EngineConfig::new(cfg_1002, fs_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        Box::new(port_1002),
    )
    .unwrap();

    eng_1001.send_command(EngineCommand::Register).unwrap();
    eng_1002.send_command(EngineCommand::Register).unwrap();
    assert!(
        wait_for_engine_event(&eng_1001, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some(),
        "1001 G.722 registration failed on freeswitch"
    );
    assert!(
        wait_for_engine_event(&eng_1002, Duration::from_secs(10), |e| matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        ))
        .is_some(),
        "1002 Opus registration failed on freeswitch"
    );

    eng_1001
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:1002@freeswitch:5060").unwrap(),
        })
        .unwrap();

    let call_1001 = match wait_for_engine_event(&eng_1001, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    })
    .expect("OutboundCallStarted on 1001")
    {
        EngineEvent::OutboundCallStarted { call_id } => call_id,
        _ => unreachable!(),
    };

    let call_1002 = match wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("IncomingCall on 1002")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    eng_1002
        .send_command(EngineCommand::Answer { call_id: call_1002 })
        .unwrap();

    let mut est_1001: Option<String> = None;
    let mut seen_1001 = Vec::new();
    let dl1 = Instant::now() + Duration::from_secs(8);
    while Instant::now() < dl1 {
        if let Some(ev) = eng_1001.recv_event_timeout(Duration::from_millis(50)) {
            if let EngineEvent::CallEstablished { codec, .. } = &ev {
                est_1001 = Some(codec.clone());
                break;
            }
            let done = matches!(ev, EngineEvent::CallTerminated { .. });
            seen_1001.push(ev);
            if done {
                break;
            }
        }
    }
    let est_1001 = est_1001.unwrap_or_else(|| {
        let mut seen_1002 = Vec::new();
        while let Some(ev) = eng_1002.try_recv_event() {
            seen_1002.push(ev);
        }
        panic!("CallEstablished on 1001 failed; evs1={seen_1001:?}, evs2={seen_1002:?}");
    });
    assert_eq!(est_1001, "G722");

    let est_1002 = match wait_for_engine_event(&eng_1002, Duration::from_secs(8), |e| {
        matches!(e, EngineEvent::CallEstablished { .. })
    })
    .expect("CallEstablished on 1002")
    {
        EngineEvent::CallEstablished { codec, .. } => codec,
        _ => unreachable!(),
    };
    assert_eq!(est_1002, "OPUS");

    thread::sleep(Duration::from_millis(800));

    eng_1001
        .send_command(EngineCommand::Hangup { call_id: call_1001 })
        .unwrap();
    let _ = wait_for_engine_event(&eng_1001, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    });
    let _ = wait_for_engine_event(&eng_1002, Duration::from_secs(6), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    });

    for eng in [&eng_1001, &eng_1002] {
        eng.send_command(EngineCommand::Unregister).unwrap();
        let _ = wait_for_engine_event(eng, Duration::from_secs(4), |e| {
            matches!(
                e,
                EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
            )
        });
    }
    eng_1001.shutdown().unwrap();
    eng_1002.shutdown().unwrap();

    let recorded = handle_1002.recorded_wav();
    assert_eq!(recorded.sample_rate, 48_000);
    assert!(
        recorded.rms_energy() > 1500,
        "expected G.722->Asterisk->Opus audio RMS > 1500, got {}",
        recorded.rms_energy()
    );
    let half = recorded.samples.len() / 2;
    let steady = &recorded.samples[half..];
    let p_5500 = goertzel_power(steady, 48_000.0, 5_500.0);
    let p_2500 = goertzel_power(steady, 48_000.0, 2_500.0);
    let p_1000 = goertzel_power(steady, 48_000.0, 1_000.0);
    assert!(
        p_5500 > p_2500 * 5.0 && p_5500 > p_1000 * 5.0,
        "expected strong 5500 Hz high-band tone after G.722 QMF -> spandsp -> Opus, got p5500={p_5500:.1}, p2500={p_2500:.1}, p1000={p_1000:.1}"
    );
}

#[test]
fn p0_multi_call_hold_focus_and_spoofed_rtp_rejection() {
    use bmsip_engine::PcmQueueAudioPort;
    use bmsip_media::{DtmfEventPayload, RtpPacketizer};

    let dummy_reg = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

    // 1. Hub endpoint with PcmQueueAudioPort handles Call A (held) then Call B (active).
    let (hub_port, hub_audio) = PcmQueueAudioPort::new(64);
    let hub_ua = UaConfig::new(
        "hub",
        "pw",
        "127.0.0.1",
        SipUri::parse("sip:127.0.0.1:1").unwrap(),
        "127.0.0.1",
        0,
    );
    let eng_hub = SipEngine::spawn(
        EngineConfig::new(hub_ua, dummy_reg, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(hub_port),
    )
    .unwrap();
    let hub_addr = eng_hub.local_sip_addr();

    let alice_ua = UaConfig::new(
        "alice",
        "pw",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{hub_addr}")).unwrap(),
        "127.0.0.1",
        0,
    );
    let (alice_port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), true);
    let eng_alice = SipEngine::spawn(
        EngineConfig::new(alice_ua, hub_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(alice_port),
    )
    .unwrap();

    eng_alice
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:hub@{hub_addr}")).unwrap(),
        })
        .unwrap();
    let call_a_hub = match wait_for_engine_event(&eng_hub, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("hub IncomingCall A")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    eng_hub
        .send_command(EngineCommand::Answer {
            call_id: call_a_hub.clone(),
        })
        .unwrap();
    let alice_remote_rtp = match wait_for_engine_event(&eng_alice, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::CallEstablished { .. })
    })
    .expect("alice CallEstablished")
    {
        EngineEvent::CallEstablished { remote_rtp, .. } => remote_rtp,
        _ => unreachable!(),
    };
    assert!(
        wait_for_engine_event(&eng_hub, Duration::from_secs(5), |e| {
            matches!(e, EngineEvent::CallEstablished { .. })
        })
        .is_some()
    );

    // Wait briefly so hub latches Alice's real RTP source port, then inject spoofed DTMF '9' packets.
    thread::sleep(Duration::from_millis(120));
    let mut fake_pkt = RtpPacketizer::new(0xDEAD_BEEF, 101, 500, 1600);
    let dtmf9 = DtmfEventPayload {
        digit: DtmfDigit::D9,
        end_of_event: true,
        volume: 10,
        duration: 1600,
    }
    .to_bytes();
    let forged = fake_pkt.build_custom_packet_bytes(101, 1600, true, &dtmf9);
    // Test both different loopback IP (127.0.0.2) and different port on 127.0.0.1.
    for bind_addr in ["127.0.0.2:0", "127.0.0.1:0"] {
        let spoofer = UdpSocket::bind(bind_addr).unwrap();
        for _ in 0..3 {
            let _ = spoofer.send_to(&forged, alice_remote_rtp);
        }
    }
    thread::sleep(Duration::from_millis(120));
    while let Some(ev) = eng_hub.try_recv_event() {
        assert!(
            !matches!(ev, EngineEvent::DtmfReceived { .. }),
            "spoofed RTP DTMF packet must be rejected: {ev:?}"
        );
    }

    // Put Call A on Hold and start Call B with Carol.
    eng_hub
        .send_command(EngineCommand::Hold {
            call_id: call_a_hub.clone(),
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_hub, Duration::from_secs(5), |e| {
            matches!(
                e,
                EngineEvent::CallHoldChanged {
                    local_hold: true,
                    ..
                }
            )
        })
        .is_some()
    );

    while hub_audio.pop_playout_frame().is_some() {}

    let carol_ua = UaConfig::new(
        "carol",
        "pw",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{hub_addr}")).unwrap(),
        "127.0.0.1",
        0,
    );
    let (carol_port, _) = WavAudioPort::new(
        WavPcm16::generate_sine_wave(8_000, 1_000, 1_500, 12_000),
        true,
    );
    let eng_carol = SipEngine::spawn(
        EngineConfig::new(carol_ua, hub_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(carol_port),
    )
    .unwrap();
    eng_carol
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse(&format!("sip:hub@{hub_addr}")).unwrap(),
        })
        .unwrap();

    let call_b_hub = match wait_for_engine_event(&eng_hub, Duration::from_secs(5), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("hub IncomingCall B")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    eng_hub
        .send_command(EngineCommand::Answer {
            call_id: call_b_hub.clone(),
        })
        .unwrap();
    assert!(
        wait_for_engine_event(&eng_hub, Duration::from_secs(5), |e| {
            matches!(e, EngineEvent::CallEstablished { .. })
        })
        .is_some()
    );

    thread::sleep(Duration::from_millis(280));
    let mut call_b_samples = Vec::new();
    while let Some(frame) = hub_audio.pop_playout_frame() {
        call_b_samples.extend_from_slice(&frame);
    }
    let rms_b = WavPcm16::new(8_000, call_b_samples).rms_energy();
    assert!(
        rms_b > 1500,
        "expected active Call B audio focus while Call A is held (RMS > 1500), got {rms_b}"
    );

    // Explicitly switch active audio focus back via SetActiveCall after resuming Call A.
    eng_hub
        .send_command(EngineCommand::ResumeCall {
            call_id: call_a_hub.clone(),
        })
        .unwrap();
    let _ = wait_for_engine_event(&eng_hub, Duration::from_secs(5), |e| {
        matches!(
            e,
            EngineEvent::CallHoldChanged {
                local_hold: false,
                ..
            }
        )
    });
    eng_hub
        .send_command(EngineCommand::SetActiveCall {
            call_id: call_a_hub.clone(),
        })
        .unwrap();
    thread::sleep(Duration::from_millis(60));
    while hub_audio.pop_playout_frame().is_some() {}
    thread::sleep(Duration::from_millis(160));
    let mut call_a_samples = Vec::new();
    while let Some(frame) = hub_audio.pop_playout_frame() {
        call_a_samples.extend_from_slice(&frame);
    }
    let rms_a = WavPcm16::new(8_000, call_a_samples).rms_energy();
    assert!(
        rms_a < 300,
        "expected SetActiveCall to switch hub audio focus back to silent Call A (RMS < 300), got {rms_a}"
    );

    eng_hub
        .send_command(EngineCommand::Hangup {
            call_id: call_a_hub,
        })
        .unwrap();
    eng_hub
        .send_command(EngineCommand::Hangup {
            call_id: call_b_hub,
        })
        .unwrap();
    let _ = wait_for_engine_event(&eng_hub, Duration::from_secs(4), |e| {
        matches!(e, EngineEvent::CallTerminated { .. })
    });
    eng_alice.shutdown().unwrap();
    eng_carol.shutdown().unwrap();
    eng_hub.shutdown().unwrap();
}

#[test]
fn p1_network_changed_same_sip_port_rebind_and_pending_rtp_succeeds() {
    let ua_cfg = UaConfig::new(
        "nettest",
        "pw",
        "127.0.0.1",
        SipUri::parse("sip:127.0.0.1:59997").unwrap(),
        "127.0.0.1",
        0,
    );
    let (port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0i16; 1_600]), true);
    let engine = SipEngine::spawn(
        EngineConfig::new(
            ua_cfg,
            "127.0.0.1:59997".parse().unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ),
        Box::new(port),
    )
    .unwrap();
    let initial_addr = engine.local_sip_addr();
    assert_ne!(initial_addr.port(), 0);

    // Dial creates a pending_rtp_sockets entry before handover.
    engine
        .send_command(EngineCommand::Dial {
            target_uri: SipUri::parse("sip:bob@127.0.0.1:59997").unwrap(),
        })
        .unwrap();
    let _ = wait_for_engine_event(&engine, Duration::from_secs(2), |e| {
        matches!(e, EngineEvent::OutboundCallStarted { .. })
    });

    // Same SIP port handover must release old sockets first (no EADDRINUSE) and rebind pending RTP sockets.
    engine
        .send_command(EngineCommand::NetworkChanged {
            new_bind_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            new_sip_port: initial_addr.port(),
        })
        .unwrap();

    let updated = wait_for_engine_event(&engine, Duration::from_secs(3), |e| {
        matches!(
            e,
            EngineEvent::NetworkUpdated { .. } | EngineEvent::Warning(_)
        )
    });
    match updated {
        Some(EngineEvent::NetworkUpdated { local_sip_addr }) => {
            assert_eq!(local_sip_addr.port(), initial_addr.port());
        }
        other => panic!("expected NetworkUpdated on same-port handover, got {other:?}"),
    }
    engine.shutdown().unwrap();
}

#[test]
fn p2_worker_panic_is_caught_emits_stopped_and_closes_command_channel() {
    struct PanickingAudioPort;
    impl bmsip_engine::AudioPort for PanickingAudioPort {
        fn capture_20ms(&mut self) -> [i16; 160] {
            panic!("simulated audio port panic");
        }
        fn playout_20ms(&mut self, _samples: &[i16]) {}
    }

    let uas_cfg = UaConfig::new(
        "callee",
        "pw",
        "127.0.0.1",
        SipUri::parse("sip:127.0.0.1:5060").unwrap(),
        "127.0.0.1",
        0,
    );
    let (uas_port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0i16; 1_600]), true);
    let uas = SipEngine::spawn(
        EngineConfig::new(
            uas_cfg,
            "127.0.0.1:5060".parse().unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        ),
        Box::new(uas_port),
    )
    .unwrap();
    let uas_addr = uas.local_sip_addr();

    let uac_cfg = UaConfig::new(
        "caller",
        "pw",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{uas_addr}")).unwrap(),
        "127.0.0.1",
        0,
    );
    let uac = SipEngine::spawn(
        EngineConfig::new(uac_cfg, uas_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(PanickingAudioPort),
    )
    .unwrap();

    uac.send_command(EngineCommand::Dial {
        target_uri: SipUri::parse(&format!("sip:callee@{uas_addr}")).unwrap(),
    })
    .unwrap();

    let incoming_cid = match wait_for_engine_event(&uas, Duration::from_secs(3), |e| {
        matches!(e, EngineEvent::IncomingCall { .. })
    })
    .expect("expected IncomingCall")
    {
        EngineEvent::IncomingCall { call_id, .. } => call_id,
        _ => unreachable!(),
    };
    uas.send_command(EngineCommand::Answer {
        call_id: incoming_cid,
    })
    .unwrap();

    let stopped = wait_for_engine_event(&uac, Duration::from_secs(4), |e| {
        matches!(e, EngineEvent::Stopped)
    });
    assert!(
        matches!(stopped, Some(EngineEvent::Stopped)),
        "expected worker panic to emit EngineEvent::Stopped, got {stopped:?}"
    );
    assert!(matches!(
        uac.send_command(EngineCommand::Unregister),
        Err(EngineError::ChannelClosed)
    ));
    let _ = uac.shutdown();
    uas.shutdown().unwrap();
}

#[test]
fn p2_shutdown_flushes_bye_unregister_and_suspend_pauses_timers() {
    let mock_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
    mock_srv
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let srv_addr = mock_srv.local_addr().unwrap();

    // 1. Verify Suspend pauses active TransactionManager retransmits until Resume.
    let mut cfg = UaConfig::new(
        "alice",
        "pw",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{srv_addr}")).unwrap(),
        "127.0.0.1",
        0,
    );
    cfg.session_expires_secs = None;
    let (port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0i16; 1_600]), true);
    let eng = SipEngine::spawn(
        EngineConfig::new(cfg, srv_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Box::new(port),
    )
    .unwrap();

    let recv_request = |sock: &UdpSocket,
                        buf: &mut [u8],
                        expected: bmsip_core::sip::Method,
                        timeout: Duration|
     -> (bmsip_core::sip::SipRequest, SocketAddr) {
        let dl = Instant::now() + timeout;
        loop {
            match sock.recv_from(buf) {
                Ok((len, src)) => {
                    if let Ok(bmsip_core::sip::SipMessage::Request(req)) =
                        bmsip_core::sip::SipMessage::parse(&buf[..len])
                    {
                        if req.method == expected {
                            return (req, src);
                        }
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && Instant::now() < dl =>
                {
                    continue;
                }
                Err(err) => panic!("mock_srv recv_from failed within {timeout:?}: {err}"),
            }
            assert!(
                Instant::now() < dl,
                "timed out waiting for {expected} on mock_srv"
            );
        }
    };

    eng.send_command(EngineCommand::Register).unwrap();
    let mut buf = [0u8; 4096];
    let (_reg_req, from_addr) = recv_request(
        &mock_srv,
        &mut buf,
        bmsip_core::sip::Method::Register,
        Duration::from_secs(2),
    );

    // Suspend BEFORE answering REGISTER so UDP NICT Timer E would fire at 500 ms if awake.
    eng.send_command(EngineCommand::Suspend).unwrap();
    assert!(wait_for_engine_event(&eng, Duration::from_secs(2), |e| {
        matches!(e, EngineEvent::Suspended)
    })
    .is_some());

    // Drain any single in-flight retransmit, then assert silence for 700 ms while suspended.
    thread::sleep(Duration::from_millis(100));
    while mock_srv.recv_from(&mut buf).is_ok() {}
    thread::sleep(Duration::from_millis(700));
    assert!(
        mock_srv.recv_from(&mut buf).is_err(),
        "suspended engine should not emit timer retransmissions"
    );

    // Resume and answer REGISTER 200 OK.
    eng.send_command(EngineCommand::Resume).unwrap();
    assert!(wait_for_engine_event(&eng, Duration::from_secs(2), |e| {
        matches!(e, EngineEvent::Resumed { .. })
    })
    .is_some());
    let (reg2, _) = recv_request(
        &mock_srv,
        &mut buf,
        bmsip_core::sip::Method::Register,
        Duration::from_secs(2),
    );
    let mut r200 = reg2.create_response(200, "OK").unwrap();
    r200.headers.set("Expires", "300");
    r200.headers.set("To", "<sip:alice@127.0.0.1>;tag=srv-r1");
    mock_srv.send_to(&r200.to_bytes(), from_addr).unwrap();
    assert!(wait_for_engine_event(&eng, Duration::from_secs(2), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        )
    })
    .is_some());

    // Dial an outbound call and establish it so Shutdown has an active call + registration to clean up.
    eng.send_command(EngineCommand::Dial {
        target_uri: SipUri::parse(&format!("sip:bob@{srv_addr}")).unwrap(),
    })
    .unwrap();
    let (inv, inv_from) = recv_request(
        &mock_srv,
        &mut buf,
        bmsip_core::sip::Method::Invite,
        Duration::from_secs(2),
    );
    let mut inv200 = inv.create_response(200, "OK").unwrap().with_body(
        "application/sdp",
        bmsip_core::sdp::SdpSession::new("bob", "1", "127.0.0.1", 49000, vec![RtpCodec::pcmu()])
            .to_string()
            .into_bytes(),
    );
    inv200.headers.set("To", "<sip:bob@127.0.0.1>;tag=bob-t1");
    inv200
        .headers
        .set("Contact", format!("<sip:bob@{srv_addr}>"));
    mock_srv.send_to(&inv200.to_bytes(), inv_from).unwrap();
    assert!(wait_for_engine_event(&eng, Duration::from_secs(2), |e| {
        matches!(e, EngineEvent::CallEstablished { .. })
    })
    .is_some());

    // Drain ACK.
    while mock_srv.recv_from(&mut buf).is_ok() {}

    // 2. Shutdown MUST flush both BYE for the active call and REGISTER Expires: 0.
    eng.shutdown().unwrap();

    let mut saw_bye = false;
    let mut saw_unreg = false;
    let dl = Instant::now() + Duration::from_secs(2);
    while Instant::now() < dl && !(saw_bye && saw_unreg) {
        if let Ok((n, _)) = mock_srv.recv_from(&mut buf) {
            if let Ok(bmsip_core::sip::SipMessage::Request(req)) =
                bmsip_core::sip::SipMessage::parse(&buf[..n])
            {
                if req.method == bmsip_core::sip::Method::Bye {
                    saw_bye = true;
                } else if req.method == bmsip_core::sip::Method::Register
                    && req.headers.get("Expires") == Some("0")
                {
                    saw_unreg = true;
                }
            }
        }
    }
    assert!(saw_bye, "expected graceful Shutdown to flush BYE");
    assert!(
        saw_unreg,
        "expected graceful Shutdown to flush REGISTER Expires: 0"
    );
}

#[test]
fn udp_crlf_keepalive_refreshes_nat_binding_while_registered_and_replies_pong() {
    let mock_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
    mock_srv
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    let srv_addr = mock_srv.local_addr().unwrap();

    let ua_cfg = UaConfig::new(
        "alice",
        "secret",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{srv_addr}")).unwrap(),
        "127.0.0.1",
        0,
    );
    let eng_cfg = EngineConfig::new(ua_cfg, srv_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_udp_keepalive_secs(1);
    let (audio_port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0; 160]), false);
    let eng = SipEngine::spawn(eng_cfg, Box::new(audio_port)).unwrap();
    let eng_addr = eng.local_sip_addr();

    let mut buf = [0u8; 4096];
    let recv_request = |sock: &UdpSocket,
                        buf: &mut [u8],
                        expected: bmsip_core::sip::Method,
                        timeout: Duration|
     -> (bmsip_core::sip::SipRequest, SocketAddr) {
        let dl = Instant::now() + timeout;
        while Instant::now() < dl {
            if let Ok((n, src)) = sock.recv_from(buf) {
                if let Ok(bmsip_core::sip::SipMessage::Request(req)) =
                    bmsip_core::sip::SipMessage::parse(&buf[..n])
                {
                    if req.method == expected {
                        return (req, src);
                    }
                }
            }
        }
        panic!("timed out waiting for SIP {expected}");
    };

    // 1. Register and answer 200 OK.
    eng.send_command(EngineCommand::Register).unwrap();
    let (reg, from_addr) = recv_request(
        &mock_srv,
        &mut buf,
        bmsip_core::sip::Method::Register,
        Duration::from_secs(2),
    );
    let mut r200 = reg.create_response(200, "OK").unwrap();
    r200.headers.set("Expires", "300");
    r200.headers.set("To", "<sip:alice@127.0.0.1>;tag=srv-ka1");
    mock_srv.send_to(&r200.to_bytes(), from_addr).unwrap();
    assert!(wait_for_engine_event(&eng, Duration::from_secs(2), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        )
    })
    .is_some());

    // 2. Within ~1.5s of outbound inactivity, engine MUST emit a 4-byte RFC 5626 `\r\n\r\n` ping over UDP.
    let mut saw_ping = false;
    let dl = Instant::now() + Duration::from_millis(1600);
    while Instant::now() < dl {
        if let Ok((n, src)) = mock_srv.recv_from(&mut buf) {
            if &buf[..n] == b"\r\n\r\n" {
                assert_eq!(src, eng_addr);
                saw_ping = true;
                // Reply with RFC 5626 `\r\n` pong; engine must absorb it cleanly without warnings.
                mock_srv.send_to(b"\r\n", src).unwrap();
                break;
            }
        }
    }
    assert!(
        saw_ping,
        "expected outbound UDP `\\r\\n\\r\\n` keep-alive ping while registered"
    );

    // 3. Server-initiated `\r\n\r\n` ping to client MUST receive `\r\n` pong immediately.
    mock_srv.send_to(b"\r\n\r\n", eng_addr).unwrap();
    let mut saw_pong = false;
    let dl = Instant::now() + Duration::from_millis(800);
    while Instant::now() < dl {
        if let Ok((n, src)) = mock_srv.recv_from(&mut buf) {
            if &buf[..n] == b"\r\n" && src == eng_addr {
                saw_pong = true;
                break;
            }
        }
    }
    assert!(
        saw_pong,
        "expected `\\r\\n` pong reply to inbound UDP `\\r\\n\\r\\n` ping"
    );
    assert!(
        wait_for_engine_event(&eng, Duration::from_millis(100), |e| matches!(
            e,
            EngineEvent::Warning(_)
        ))
        .is_none(),
        "CRLF keep-alive traffic must not trigger EngineEvent::Warning"
    );

    // 4. Unregistering stops periodic UDP keep-alives.
    eng.send_command(EngineCommand::Unregister).unwrap();
    let (unreg, unreg_from) = recv_request(
        &mock_srv,
        &mut buf,
        bmsip_core::sip::Method::Register,
        Duration::from_secs(2),
    );
    let mut u200 = unreg.create_response(200, "OK").unwrap();
    u200.headers.set("Expires", "0");
    u200.headers.set("To", "<sip:alice@127.0.0.1>;tag=srv-ka2");
    mock_srv.send_to(&u200.to_bytes(), unreg_from).unwrap();
    assert!(wait_for_engine_event(&eng, Duration::from_secs(2), |e| {
        matches!(
            e,
            EngineEvent::RegistrationChanged(RegistrationState::Unregistered)
        )
    })
    .is_some());

    while mock_srv.recv_from(&mut buf).is_ok() {}
    let dl = Instant::now() + Duration::from_millis(1300);
    while Instant::now() < dl {
        if let Ok((n, _)) = mock_srv.recv_from(&mut buf) {
            assert_ne!(
                &buf[..n],
                b"\r\n\r\n",
                "unregistered engine must not emit UDP keep-alive pings"
            );
        }
    }

    eng.shutdown().unwrap();
}

fn find_sip_header(msg: &str, name: &str) -> Option<String> {
    let target = name.to_ascii_lowercase();
    for line in msg.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.trim().eq_ignore_ascii_case(&target) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

#[test]
fn udp_engine_mwi_subscribe_and_notify_emits_voicemail_updated() {
    let mock_srv = UdpSocket::bind("127.0.0.1:0").expect("bind mock mwi server");
    let srv_addr = mock_srv.local_addr().expect("srv addr");
    mock_srv
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set timeout");

    let ua_cfg = UaConfig::new(
        "1001",
        "pw",
        "127.0.0.1",
        SipUri::parse(&format!("sip:{srv_addr}")).unwrap(),
        "127.0.0.1",
        0,
    )
    .with_mwi_mode(bmsip_core::dialog::MwiMode::Auto);

    let eng_cfg = EngineConfig::new(ua_cfg, srv_addr, IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        .with_udp_keepalive_secs(0);

    let (port, _) = WavAudioPort::new(WavPcm16::new(8_000, vec![0i16; 1_600]), true);
    let eng = SipEngine::spawn(eng_cfg, Box::new(port)).expect("spawn engine");
    eng.send_command(EngineCommand::Register).unwrap();

    let mut buf = [0u8; 4096];
    let dl = Instant::now() + Duration::from_secs(3);
    let mut registered = false;
    while Instant::now() < dl {
        if let Ok((n, src)) = mock_srv.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            if text.starts_with("REGISTER ") {
                let via = find_sip_header(&text, "Via").expect("Via");
                let from = find_sip_header(&text, "From").expect("From");
                let to = find_sip_header(&text, "To").expect("To");
                let call_id = find_sip_header(&text, "Call-ID").expect("Call-ID");
                let cseq = find_sip_header(&text, "CSeq").expect("CSeq");
                let contact = find_sip_header(&text, "Contact").expect("Contact");
                let rsp = format!(
                    "SIP/2.0 200 OK\r\n\
                     Via: {via}\r\n\
                     From: {from}\r\n\
                     To: {to};tag=mwi-reg-1\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq}\r\n\
                     Contact: {contact}\r\n\
                     Expires: 120\r\n\
                     Content-Length: 0\r\n\r\n"
                );
                mock_srv.send_to(rsp.as_bytes(), src).unwrap();
                registered = true;
                break;
            }
        }
    }
    assert!(registered, "engine must send REGISTER");

    wait_for_engine_event(&eng, Duration::from_secs(2), |ev| {
        matches!(
            ev,
            EngineEvent::RegistrationChanged(RegistrationState::Registered { .. })
        )
    })
    .expect("must reach Registered state");

    eng.send_command(EngineCommand::RefreshVoicemail).unwrap();

    let sub_dl = Instant::now() + Duration::from_secs(3);
    let mut sub_handled = false;
    while Instant::now() < sub_dl {
        if let Ok((n, src)) = mock_srv.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            if text.starts_with("SUBSCRIBE ") {
                assert_eq!(
                    find_sip_header(&text, "Event").as_deref(),
                    Some("message-summary")
                );
                let via = find_sip_header(&text, "Via").expect("Via");
                let from = find_sip_header(&text, "From").expect("From");
                let to = find_sip_header(&text, "To").expect("To");
                let call_id = find_sip_header(&text, "Call-ID").expect("Call-ID");
                let cseq = find_sip_header(&text, "CSeq").expect("CSeq");
                let contact = find_sip_header(&text, "Contact").expect("Contact");
                let accept = format!(
                    "SIP/2.0 202 Accepted\r\n\
                     Via: {via}\r\n\
                     From: {from}\r\n\
                     To: {to};tag=mwi-sub-1\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: {cseq}\r\n\
                     Contact: <sip:1001@{srv_addr}>\r\n\
                     Expires: 3600\r\n\
                     Content-Length: 0\r\n\r\n"
                );
                mock_srv.send_to(accept.as_bytes(), src).unwrap();

                let body = "Messages-Waiting: yes\r\n\
                            Message-Account: sip:vm@127.0.0.1\r\n\
                            Voice-Message: 2/4 (1/0)\r\n";
                let req_uri = contact
                    .split('>')
                    .next()
                    .unwrap_or(&contact)
                    .trim_start_matches('<')
                    .trim();
                let notify = format!(
                    "NOTIFY {req_uri} SIP/2.0\r\n\
                     Via: SIP/2.0/UDP {srv_addr};branch=z9hG4bKmwi01\r\n\
                     From: {to};tag=mwi-sub-1\r\n\
                     To: {from}\r\n\
                     Call-ID: {call_id}\r\n\
                     CSeq: 1 NOTIFY\r\n\
                     Event: message-summary\r\n\
                     Subscription-State: active;expires=3600\r\n\
                     Content-Type: application/simple-message-summary\r\n\
                     Content-Length: {}\r\n\r\n\
                     {body}",
                    body.len()
                );
                mock_srv.send_to(notify.as_bytes(), src).unwrap();
                sub_handled = true;
                break;
            }
        }
    }
    assert!(
        sub_handled,
        "engine must send SUBSCRIBE for message-summary"
    );

    let ev = wait_for_engine_event(&eng, Duration::from_secs(2), |ev| {
        matches!(ev, EngineEvent::VoicemailUpdated { .. })
    })
    .expect("must emit EngineEvent::VoicemailUpdated");
    assert_eq!(
        ev,
        EngineEvent::VoicemailUpdated {
            messages_waiting: true,
            message_account: Some("sip:vm@127.0.0.1".to_string()),
            new_messages: 2,
            old_messages: 4,
            urgent_new: 1,
            urgent_old: 0,
        }
    );

    let notify_ok_dl = Instant::now() + Duration::from_secs(2);
    let mut got_200 = false;
    while Instant::now() < notify_ok_dl {
        if let Ok((n, _)) = mock_srv.recv_from(&mut buf) {
            let text = String::from_utf8_lossy(&buf[..n]);
            if text.starts_with("SIP/2.0 200 OK")
                && find_sip_header(&text, "CSeq").as_deref() == Some("1 NOTIFY")
            {
                got_200 = true;
                break;
            }
        }
    }
    assert!(got_200, "engine must reply 200 OK to MWI NOTIFY");

    eng.shutdown().unwrap();
}
