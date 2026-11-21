use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use bmsip_ffi::bmsip_engine::bmsip_media::WavPcm16;
use bmsip_ffi::{
    bmsip_client_attended_transfer, bmsip_client_audio_sample_rate_hz, bmsip_client_dial,
    bmsip_client_free, bmsip_client_hangup, bmsip_client_hold, bmsip_client_new,
    bmsip_client_new_ex, bmsip_client_new_secure, bmsip_client_new_transport,
    bmsip_client_poll_event_json, bmsip_client_pop_pcm, bmsip_client_push_pcm,
    bmsip_client_register, bmsip_client_resume_call, bmsip_client_ring_early_media,
    bmsip_client_send_info_dtmf, bmsip_client_transfer, bmsip_client_unregister, bmsip_string_free,
    BmsipClient, FfiConfig, FfiEvent, FfiEventKind, FfiSrtpMode, FfiTransport,
};

#[test]
fn udl_schema_matches_rust_sdk_surface() {
    let udl = include_str!("../src/bmsip.udl");
    for required in [
        "namespace bmsip",
        "enum FfiError",
        "enum FfiTransport",
        "enum FfiSrtpMode",
        "dictionary FfiConfig",
        "enum FfiEventKind",
        "dictionary FfiEvent",
        "interface BmsipClient",
        "with_sample_rate",
        "with_transport",
        "with_security",
        "audio_sample_rate_hz()",
        "register_account()",
        "unregister_account()",
        "dial(string target_uri)",
        "ring(string call_id)",
        "ring_early_media(string call_id)",
        "answer(string call_id)",
        "hangup(string call_id)",
        "hold(string call_id)",
        "resume_call(string call_id)",
        "transfer(string call_id, string target_uri)",
        "attended_transfer(string call_id, string target_call_id)",
        "set_active_call(string call_id)",
        "send_dtmf(string call_id, string digit)",
        "send_info_dtmf(string call_id, string digit, u32 duration_ms)",
        "notify_network_changed(string bind_ip, u16 sip_port)",
        "suspend()",
        "resume()",
        "request_telemetry(string? call_id)",
        "push_captured_pcm(sequence<i16> samples)",
        "pop_playout_pcm()",
        "poll_event(u32 timeout_ms)",
        "local_sip_address()",
        "shutdown()",
    ] {
        assert!(udl.contains(required), "UDL missing '{required}'");
    }

    let kinds = [
        FfiEventKind::RegistrationChanged,
        FfiEventKind::OutboundCallStarted,
        FfiEventKind::IncomingCall,
        FfiEventKind::CallRinging,
        FfiEventKind::EarlyMediaStarted,
        FfiEventKind::CallEstablished,
        FfiEventKind::CallMediaUpdated,
        FfiEventKind::CallHoldChanged,
        FfiEventKind::CallTransferRequested,
        FfiEventKind::TransferStatus,
        FfiEventKind::DtmfReceived,
        FfiEventKind::CallTerminated,
        FfiEventKind::Suspended,
        FfiEventKind::Resumed,
        FfiEventKind::NetworkUpdated,
        FfiEventKind::TelemetryExported,
        FfiEventKind::Warning,
        FfiEventKind::Stopped,
    ];
    for k in kinds {
        assert!(
            udl.contains(k.as_str()),
            "UDL missing variant {}",
            k.as_str()
        );
        let ev = FfiEvent {
            kind: k,
            call_id: Some("cid".to_string()),
            detail: Some("ok".to_string()),
            status_code: Some(200),
            black_box_json: None,
        };
        assert!(ev.to_json().contains(k.as_str()));
    }
}

#[test]
fn c_header_compiles_cleanly_with_gcc_c99() {
    let header_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("include")
        .join("bmsip.h");
    assert!(header_path.exists());

    let output = Command::new("gcc")
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-x",
            "c",
        ])
        .arg(&header_path)
        .output()
        .expect("run gcc syntax check on bmsip.h");

    assert!(
        output.status.success(),
        "gcc failed on bmsip.h:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn c_minimal_phone_example_compiles_with_gcc_c99() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("include");
    let example_c = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .join("bindings")
        .join("c")
        .join("minimal_phone.c");
    assert!(example_c.exists(), "missing {:?}", example_c);

    let output = Command::new("gcc")
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsyntax-only",
            "-I",
        ])
        .arg(&include_dir)
        .arg(&example_c)
        .output()
        .expect("run gcc syntax check on minimal_phone.c");

    assert!(
        output.status.success(),
        "gcc failed on minimal_phone.c:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sdk_and_c_api_live_asterisk_call_pcm_bridge_and_telemetry() {
    // 1. Safe Rust / UniFFI BmsipClient against live Asterisk Echo (exten 601).
    let client = BmsipClient::new(FfiConfig {
        username: "1003".to_string(),
        password: "secret1003".to_string(),
        domain: "asterisk".to_string(),
        registrar_addr: "asterisk:5060".to_string(),
        bind_ip: "0.0.0.0".to_string(),
        sip_port: 0,
        enable_opus: true,
    })
    .unwrap();
    assert!(!client.local_sip_address().is_empty());

    client.register_account().unwrap();
    let mut registered = false;
    let reg_dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < reg_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::RegistrationChanged
                && ev
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("Registered"))
            {
                registered = true;
                break;
            }
        }
    }
    assert!(registered, "BmsipClient 1003 failed to register");

    client.dial("sip:601@asterisk:5060".to_string()).unwrap();
    let mut call_id: Option<String> = None;
    let mut established = false;
    let call_dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < call_dl {
        if let Some(ev) = client.poll_event(50) {
            match ev.kind {
                FfiEventKind::OutboundCallStarted => call_id = ev.call_id,
                FfiEventKind::CallEstablished => {
                    established = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(established, "BmsipClient call to 601 did not establish");
    let cid = call_id.unwrap();

    // Push 20 x 20 ms PCM frames of a 400 Hz tone via PcmAudioHandle.
    let tone = WavPcm16::generate_sine_wave(8000, 400, 500, 12000);
    for frame in tone.samples.as_chunks::<160>().0 {
        client.push_captured_pcm(frame.to_vec()).unwrap();
        thread::sleep(Duration::from_millis(18));
    }
    thread::sleep(Duration::from_millis(120));

    let mut rx_pcm = Vec::new();
    while let Some(frame) = client.pop_playout_pcm() {
        rx_pcm.extend_from_slice(&frame);
    }
    let rx_wav = WavPcm16::new(8000, rx_pcm);
    assert!(
        rx_wav.rms_energy() > 1000,
        "expected echoed FFI PCM RMS > 1000, got {}",
        rx_wav.rms_energy()
    );

    client.hold(cid.clone()).unwrap();
    let mut got_hold_true = false;
    let hold_dl = Instant::now() + Duration::from_secs(6);
    while Instant::now() < hold_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::CallHoldChanged
                && ev.detail.as_deref() == Some("local_hold=true, remote_hold=false")
            {
                got_hold_true = true;
                break;
            }
        }
    }
    assert!(
        got_hold_true,
        "BmsipClient::hold did not emit CallHoldChanged"
    );
    thread::sleep(Duration::from_millis(200));

    client.resume_call(cid.clone()).unwrap();
    let mut got_hold_false = false;
    let resume_dl = Instant::now() + Duration::from_secs(6);
    while Instant::now() < resume_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::CallHoldChanged
                && ev.detail.as_deref() == Some("local_hold=false, remote_hold=false")
            {
                got_hold_false = true;
                break;
            }
        }
    }
    assert!(
        got_hold_false,
        "BmsipClient::resume_call did not emit CallHoldChanged"
    );

    client.hangup(cid.clone()).unwrap();
    let mut got_black_box = false;
    let bye_dl = Instant::now() + Duration::from_secs(6);
    while Instant::now() < bye_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::CallTerminated && ev.black_box_json.is_some() {
                got_black_box = true;
                break;
            }
        }
    }
    assert!(got_black_box);

    client.unregister_account().unwrap();
    thread::sleep(Duration::from_millis(100));
    client.shutdown();

    // 2. C99 ABI (`bmsip_client_*`) safety and live Asterisk call test.
    unsafe {
        assert_eq!(bmsip_client_register(ptr::null()), -1);
        assert_eq!(bmsip_client_ring_early_media(ptr::null(), ptr::null()), -1);
        assert_eq!(
            bmsip_client_send_info_dtmf(ptr::null(), ptr::null(), b'5' as _, 160),
            -1
        );
        assert_eq!(bmsip_client_hold(ptr::null(), ptr::null()), -1);
        assert_eq!(bmsip_client_resume_call(ptr::null(), ptr::null()), -1);
        assert_eq!(
            bmsip_client_transfer(ptr::null(), ptr::null(), ptr::null()),
            -1
        );
        assert_eq!(
            bmsip_client_attended_transfer(ptr::null(), ptr::null(), ptr::null()),
            -1
        );
        bmsip_client_free(ptr::null_mut());

        let u = CString::new("1003").unwrap();
        let p = CString::new("secret1003").unwrap();
        let d = CString::new("asterisk").unwrap();
        let r = CString::new("asterisk:5060").unwrap();
        let b = CString::new("0.0.0.0").unwrap();
        let handle = bmsip_client_new(
            u.as_ptr(),
            p.as_ptr(),
            d.as_ptr(),
            r.as_ptr(),
            b.as_ptr(),
            0,
        );
        assert!(!handle.is_null());
        assert_eq!(bmsip_client_register(handle), 0);

        let mut c_registered = false;
        let c_reg_dl = Instant::now() + Duration::from_secs(10);
        while Instant::now() < c_reg_dl {
            let json_ptr = bmsip_client_poll_event_json(handle, 50);
            if !json_ptr.is_null() {
                let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
                bmsip_string_free(json_ptr);
                if json.contains("\"RegistrationChanged\"") && json.contains("Registered") {
                    c_registered = true;
                    break;
                }
            }
        }
        assert!(c_registered, "C-API failed to register");

        let target = CString::new("sip:601@asterisk:5060").unwrap();
        assert_eq!(bmsip_client_dial(handle, target.as_ptr()), 0);

        let mut c_established = false;
        let mut c_call_id = String::new();
        let c_call_dl = Instant::now() + Duration::from_secs(10);
        while Instant::now() < c_call_dl {
            let json_ptr = bmsip_client_poll_event_json(handle, 50);
            if !json_ptr.is_null() {
                let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
                bmsip_string_free(json_ptr);
                if let Some(rest) = json.split("\"call_id\":\"").nth(1) {
                    if let Some((cid_parsed, _)) = rest.split_once('"') {
                        c_call_id = cid_parsed.to_string();
                    }
                }
                if json.contains("\"CallEstablished\"") {
                    c_established = true;
                    break;
                }
            }
        }
        assert!(c_established && !c_call_id.is_empty());

        for frame in tone.samples.as_chunks::<160>().0.iter().take(18) {
            assert_eq!(
                bmsip_client_push_pcm(handle, frame.as_ptr(), frame.len()),
                0
            );
            thread::sleep(Duration::from_millis(18));
        }
        thread::sleep(Duration::from_millis(120));

        let mut out_frame = [0i16; 160];
        let mut total_samples = Vec::new();
        loop {
            let n = bmsip_client_pop_pcm(handle, out_frame.as_mut_ptr(), out_frame.len());
            if n <= 0 {
                break;
            }
            total_samples.extend_from_slice(&out_frame[..n as usize]);
        }
        assert!(
            WavPcm16::new(8000, total_samples).rms_energy() > 1000,
            "C-API echoed audio RMS too low"
        );

        let c_cid = CString::new(c_call_id).unwrap();
        assert_eq!(bmsip_client_hold(handle, c_cid.as_ptr()), 0);
        let mut c_held = false;
        let c_hold_dl = Instant::now() + Duration::from_secs(6);
        while Instant::now() < c_hold_dl {
            let json_ptr = bmsip_client_poll_event_json(handle, 50);
            if !json_ptr.is_null() {
                let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
                bmsip_string_free(json_ptr);
                if json.contains("\"CallHoldChanged\"") && json.contains("local_hold=true") {
                    c_held = true;
                    break;
                }
            }
        }
        assert!(
            c_held,
            "C-API bmsip_client_hold did not emit CallHoldChanged"
        );
        thread::sleep(Duration::from_millis(150));

        assert_eq!(bmsip_client_resume_call(handle, c_cid.as_ptr()), 0);
        let mut c_resumed = false;
        let c_resume_dl = Instant::now() + Duration::from_secs(6);
        while Instant::now() < c_resume_dl {
            let json_ptr = bmsip_client_poll_event_json(handle, 50);
            if !json_ptr.is_null() {
                let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
                bmsip_string_free(json_ptr);
                if json.contains("\"CallHoldChanged\"") && json.contains("local_hold=false") {
                    c_resumed = true;
                    break;
                }
            }
        }
        assert!(
            c_resumed,
            "C-API bmsip_client_resume_call did not emit CallHoldChanged"
        );

        assert_eq!(bmsip_client_hangup(handle, c_cid.as_ptr()), 0);
        thread::sleep(Duration::from_millis(150));
        assert_eq!(bmsip_client_unregister(handle), 0);
        thread::sleep(Duration::from_millis(150));
        bmsip_client_free(handle);
    }
}

#[test]
fn ffi_and_c_api_wideband_48khz_opus_live_asterisk_call() {
    // 1. Safe Rust / UniFFI BmsipClient running natively at 48 kHz (960 samples/20 ms) with Opus.
    let client = BmsipClient::new_with_sample_rate(
        FfiConfig {
            username: "1003".to_string(),
            password: "secret1003".to_string(),
            domain: "asterisk".to_string(),
            registrar_addr: "asterisk:5060".to_string(),
            bind_ip: "0.0.0.0".to_string(),
            sip_port: 0,
            enable_opus: true,
        },
        48_000,
    )
    .unwrap();
    assert_eq!(client.audio_sample_rate_hz(), 48_000);
    // Narrowband 160-sample frame must be rejected on a 48 kHz bridge.
    assert!(client.push_captured_pcm(vec![0; 160]).is_err());

    client.register_account().unwrap();
    let mut registered = false;
    let reg_dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < reg_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::RegistrationChanged
                && ev
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("Registered"))
            {
                registered = true;
                break;
            }
        }
    }
    assert!(registered, "48 kHz BmsipClient failed to register");

    client.dial("sip:601@asterisk:5060".to_string()).unwrap();
    let mut call_id: Option<String> = None;
    let mut established_detail: Option<String> = None;
    let call_dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < call_dl {
        if let Some(ev) = client.poll_event(50) {
            match ev.kind {
                FfiEventKind::OutboundCallStarted => call_id = ev.call_id,
                FfiEventKind::CallEstablished => {
                    established_detail = ev.detail;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(
        established_detail
            .as_deref()
            .is_some_and(|d| d.contains("codec=OPUS")),
        "expected OPUS codec on 48 kHz FFI call, got {:?}",
        established_detail
    );

    let tone_48k = WavPcm16::generate_sine_wave(48_000, 1_000, 500, 12_000);
    for frame in tone_48k.samples.as_chunks::<960>().0 {
        client.push_captured_pcm(frame.to_vec()).unwrap();
        thread::sleep(Duration::from_millis(18));
    }
    thread::sleep(Duration::from_millis(120));

    let mut rx_pcm = Vec::new();
    let mut frame_lens = Vec::new();
    while let Some(frame) = client.pop_playout_pcm() {
        frame_lens.push(frame.len());
        rx_pcm.extend_from_slice(&frame);
    }
    assert!(
        !frame_lens.is_empty() && frame_lens.iter().all(|&n| n == 960),
        "expected 960-sample 48 kHz playout frames, got {:?}",
        frame_lens
    );
    assert!(WavPcm16::new(48_000, rx_pcm).rms_energy() > 1000);

    client.hangup(call_id.unwrap()).unwrap();
    thread::sleep(Duration::from_millis(150));
    client.unregister_account().unwrap();
    thread::sleep(Duration::from_millis(100));
    client.shutdown();

    // 2. C99 extended constructor `bmsip_client_new_ex` with Opus enabled at 16 kHz.
    unsafe {
        let u = CString::new("1003").unwrap();
        let p = CString::new("secret1003").unwrap();
        let d = CString::new("asterisk").unwrap();
        let r = CString::new("asterisk:5060").unwrap();
        let b = CString::new("0.0.0.0").unwrap();
        let handle = bmsip_client_new_ex(
            u.as_ptr(),
            p.as_ptr(),
            d.as_ptr(),
            r.as_ptr(),
            b.as_ptr(),
            0,
            1,
            16_000,
        );
        assert!(!handle.is_null());
        assert_eq!(bmsip_client_audio_sample_rate_hz(handle), 16_000);
        let frame_16k = [0i16; 320];
        assert_eq!(
            bmsip_client_push_pcm(handle, frame_16k.as_ptr(), frame_16k.len()),
            0
        );
        bmsip_client_free(handle);
    }
}

#[test]
fn ffi_and_c_api_tls_transport_live_asterisk_call() {
    // 1. Safe Rust / UniFFI BmsipClient over TLS against Asterisk 5061/tls.
    let client = BmsipClient::new_with_transport(
        FfiConfig {
            username: "1003".to_string(),
            password: "secret1003".to_string(),
            domain: "asterisk".to_string(),
            registrar_addr: "asterisk:5061".to_string(),
            bind_ip: "0.0.0.0".to_string(),
            sip_port: 0,
            enable_opus: true,
        },
        8_000,
        FfiTransport::Tls,
        None,
        true,
    )
    .unwrap();

    client.register_account().unwrap();
    let mut registered = false;
    let reg_dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < reg_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::RegistrationChanged
                && ev
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("Registered"))
            {
                registered = true;
                break;
            }
        }
    }
    assert!(registered, "TLS BmsipClient 1003 failed to register");

    client
        .dial("sip:601@asterisk:5061;transport=tls".to_string())
        .unwrap();
    let mut call_id: Option<String> = None;
    let mut established = false;
    let call_dl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < call_dl {
        if let Some(ev) = client.poll_event(50) {
            match ev.kind {
                FfiEventKind::OutboundCallStarted => call_id = ev.call_id,
                FfiEventKind::CallEstablished => {
                    established = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(established, "TLS BmsipClient call to 601 did not establish");

    let tone = WavPcm16::generate_sine_wave(8_000, 440, 400, 12_000);
    for frame in tone.samples.as_chunks::<160>().0 {
        client.push_captured_pcm(frame.to_vec()).unwrap();
        thread::sleep(Duration::from_millis(18));
    }
    thread::sleep(Duration::from_millis(120));

    let mut rx_pcm = Vec::new();
    while let Some(frame) = client.pop_playout_pcm() {
        rx_pcm.extend_from_slice(&frame);
    }
    assert!(
        WavPcm16::new(8_000, rx_pcm).rms_energy() > 1000,
        "expected echoed TLS FFI PCM RMS > 1000"
    );

    client.hangup(call_id.unwrap()).unwrap();
    let bye_dl = Instant::now() + Duration::from_secs(6);
    while Instant::now() < bye_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::CallTerminated {
                break;
            }
        }
    }
    client.unregister_account().unwrap();
    let unreg_dl = Instant::now() + Duration::from_secs(4);
    while Instant::now() < unreg_dl {
        if let Some(ev) = client.poll_event(50) {
            if ev.kind == FfiEventKind::RegistrationChanged
                && ev.detail.as_deref() == Some("Unregistered")
            {
                break;
            }
        }
    }
    client.shutdown();

    // 2. C99 ABI `bmsip_client_new_transport` rejects unknown transport and accepts `"tcp"` / `"tls"`.
    unsafe {
        let u = CString::new("1003").unwrap();
        let p = CString::new("secret1003").unwrap();
        let d = CString::new("asterisk").unwrap();
        let r_tcp = CString::new("asterisk:5060").unwrap();
        let b = CString::new("0.0.0.0").unwrap();
        let bad_t = CString::new("sctp").unwrap();
        assert!(bmsip_client_new_transport(
            u.as_ptr(),
            p.as_ptr(),
            d.as_ptr(),
            r_tcp.as_ptr(),
            b.as_ptr(),
            0,
            1,
            8_000,
            bad_t.as_ptr(),
            ptr::null(),
            0,
        )
        .is_null());

        let tcp_t = CString::new("tcp").unwrap();
        let handle = bmsip_client_new_transport(
            u.as_ptr(),
            p.as_ptr(),
            d.as_ptr(),
            r_tcp.as_ptr(),
            b.as_ptr(),
            0,
            1,
            8_000,
            tcp_t.as_ptr(),
            ptr::null(),
            0,
        );
        assert!(!handle.is_null());
        assert_eq!(bmsip_client_register(handle), 0);
        let mut reg_ok = false;
        let dl = Instant::now() + Duration::from_secs(10);
        while Instant::now() < dl {
            let json_ptr = bmsip_client_poll_event_json(handle, 50);
            if !json_ptr.is_null() {
                let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
                bmsip_string_free(json_ptr);
                if json.contains("\"RegistrationChanged\"") && json.contains("Registered") {
                    reg_ok = true;
                    break;
                }
            }
        }
        assert!(reg_ok, "C-API TCP registration failed");
        assert_eq!(bmsip_client_unregister(handle), 0);
        let udl = Instant::now() + Duration::from_secs(4);
        while Instant::now() < udl {
            let json_ptr = bmsip_client_poll_event_json(handle, 50);
            if !json_ptr.is_null() {
                let json = CStr::from_ptr(json_ptr).to_string_lossy().into_owned();
                bmsip_string_free(json_ptr);
                if json.contains("\"RegistrationChanged\"") && json.contains("Unregistered") {
                    break;
                }
            }
        }
        bmsip_client_free(handle);

        // 3. C99 ABI `bmsip_client_new_secure` with TLS + SDES-SRTP on Asterisk endpoint 1004,
        //    verifying unsupported `"dtls"` and cleartext `"udp"`+`"sdes"` combinations are rejected.
        let u4 = CString::new("1004").unwrap();
        let p4 = CString::new("secret1004").unwrap();
        let r_tls = CString::new("asterisk:5061").unwrap();
        let tls_t = CString::new("tls").unwrap();
        let udp_t = CString::new("udp").unwrap();
        let srtp_sdes = CString::new("sdes").unwrap();
        let dtls_srtp = CString::new("dtls").unwrap();
        let bad_srtp = CString::new("unknown_srtp").unwrap();
        assert!(bmsip_client_new_secure(
            u4.as_ptr(),
            p4.as_ptr(),
            d.as_ptr(),
            r_tls.as_ptr(),
            b.as_ptr(),
            0,
            1,
            8_000,
            tls_t.as_ptr(),
            bad_srtp.as_ptr(),
            ptr::null(),
            1,
        )
        .is_null());
        assert!(bmsip_client_new_secure(
            u4.as_ptr(),
            p4.as_ptr(),
            d.as_ptr(),
            r_tls.as_ptr(),
            b.as_ptr(),
            0,
            1,
            8_000,
            tls_t.as_ptr(),
            dtls_srtp.as_ptr(),
            ptr::null(),
            1,
        )
        .is_null());
        assert!(bmsip_client_new_secure(
            u4.as_ptr(),
            p4.as_ptr(),
            d.as_ptr(),
            r_tls.as_ptr(),
            b.as_ptr(),
            0,
            1,
            8_000,
            udp_t.as_ptr(),
            srtp_sdes.as_ptr(),
            ptr::null(),
            1,
        )
        .is_null());

        let sec_handle = bmsip_client_new_secure(
            u4.as_ptr(),
            p4.as_ptr(),
            d.as_ptr(),
            r_tls.as_ptr(),
            b.as_ptr(),
            0,
            1,
            8_000,
            tls_t.as_ptr(),
            srtp_sdes.as_ptr(),
            ptr::null(),
            1,
        );
        assert!(!sec_handle.is_null());
        bmsip_client_free(sec_handle);
    }

    // 4. Safe Rust / UniFFI `BmsipClient::new_with_security` (TLS + SDES-SRTP) against Asterisk 1004 -> 601 Echo.
    let srtp_client = BmsipClient::new_with_security(
        FfiConfig {
            username: "1004".to_string(),
            password: "secret1004".to_string(),
            domain: "asterisk".to_string(),
            registrar_addr: "asterisk:5061".to_string(),
            bind_ip: "0.0.0.0".to_string(),
            sip_port: 0,
            enable_opus: true,
        },
        8_000,
        FfiTransport::Tls,
        FfiSrtpMode::SdesRequired,
        None,
        true,
    )
    .unwrap();
    srtp_client.register_account().unwrap();
    let mut srtp_reg = false;
    let sdl = Instant::now() + Duration::from_secs(10);
    while Instant::now() < sdl {
        if let Some(ev) = srtp_client.poll_event(50) {
            if ev.kind == FfiEventKind::RegistrationChanged
                && ev
                    .detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("Registered"))
            {
                srtp_reg = true;
                break;
            }
        }
    }
    assert!(srtp_reg, "BmsipClient 1004 TLS+SRTP failed to register");
    srtp_client.unregister_account().unwrap();
    let udl = Instant::now() + Duration::from_secs(4);
    while Instant::now() < udl {
        if let Some(ev) = srtp_client.poll_event(50) {
            if ev.kind == FfiEventKind::RegistrationChanged
                && ev.detail.as_deref() == Some("Unregistered")
            {
                break;
            }
        }
    }
    srtp_client.shutdown();
}

#[test]
fn p0_ffi_poll_event_does_not_block_concurrent_commands() {
    use std::sync::Arc;

    let client = Arc::new(
        BmsipClient::with_security(
            FfiConfig {
                username: "1001".to_string(),
                password: "pw".to_string(),
                domain: "127.0.0.1".to_string(),
                registrar_addr: "127.0.0.1:59999".to_string(),
                bind_ip: "127.0.0.1".to_string(),
                sip_port: 0,
                enable_opus: false,
            },
            8_000,
            FfiTransport::Udp,
            FfiSrtpMode::Disabled,
            None,
            false,
        )
        .unwrap(),
    );

    let poller = Arc::clone(&client);
    let poll_thread = thread::spawn(move || {
        let _ = poller.poll_event(800);
    });

    // Give the background thread time to enter `poll_event(800)`.
    thread::sleep(Duration::from_millis(40));

    let t0 = Instant::now();
    let local = client.local_sip_address();
    assert!(!local.is_empty());
    client.request_telemetry(None).unwrap();
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(100),
        "concurrent API calls blocked behind poll_event(800): elapsed={elapsed:?}"
    );

    client.shutdown();
    poll_thread.join().unwrap();
}

#[test]
fn c_api_bounds_check_pcm_and_expose_addr_and_telemetry() {
    use bmsip_ffi::{
        bmsip_client_free, bmsip_client_local_sip_addr, bmsip_client_new_ex,
        bmsip_client_poll_event_json, bmsip_client_pop_pcm, bmsip_client_push_pcm,
        bmsip_client_request_telemetry, bmsip_string_free,
    };
    use std::ffi::{CStr, CString};

    let user = CString::new("1001").unwrap();
    let pass = CString::new("pw").unwrap();
    let domain = CString::new("127.0.0.1").unwrap();
    let reg = CString::new("127.0.0.1:59998").unwrap();
    let bind = CString::new("127.0.0.1").unwrap();

    // SAFETY: all pointers are valid NUL-terminated C strings.
    let handle = unsafe {
        bmsip_client_new_ex(
            user.as_ptr(),
            pass.as_ptr(),
            domain.as_ptr(),
            reg.as_ptr(),
            bind.as_ptr(),
            0,
            0,
            8_000,
        )
    };
    assert!(!handle.is_null());

    // SAFETY: valid handle; mismatched PCM lengths/capacities must fail with -1.
    unsafe {
        let short_samples = [0i16; 159];
        let valid_samples = [0i16; 160];
        let long_samples = [0i16; 161];
        assert_eq!(
            bmsip_client_push_pcm(handle, short_samples.as_ptr(), short_samples.len()),
            -1
        );
        assert_eq!(
            bmsip_client_push_pcm(handle, long_samples.as_ptr(), long_samples.len()),
            -1
        );
        assert_eq!(
            bmsip_client_push_pcm(handle, valid_samples.as_ptr(), valid_samples.len()),
            0
        );

        let mut out = [0i16; 160];
        assert_eq!(bmsip_client_pop_pcm(handle, out.as_mut_ptr(), 159), -1);
        assert_eq!(bmsip_client_pop_pcm(handle, out.as_mut_ptr(), 160), 0);

        let addr_ptr = bmsip_client_local_sip_addr(handle);
        assert!(!addr_ptr.is_null());
        let addr_str = CStr::from_ptr(addr_ptr).to_str().unwrap();
        assert!(addr_str.starts_with("127.0.0.1:"));
        bmsip_string_free(addr_ptr);

        assert_eq!(bmsip_client_request_telemetry(handle, std::ptr::null()), 0);
        let mut saw_telemetry = false;
        let dl = Instant::now() + Duration::from_secs(2);
        while Instant::now() < dl {
            let ev_ptr = bmsip_client_poll_event_json(handle, 50);
            if !ev_ptr.is_null() {
                let ev_json = CStr::from_ptr(ev_ptr).to_str().unwrap().to_string();
                bmsip_string_free(ev_ptr);
                if ev_json.contains("\"TelemetryExported\"") {
                    saw_telemetry = true;
                    break;
                }
            }
        }
        assert!(saw_telemetry);
        bmsip_client_free(handle);
    }
}

#[test]
fn p2_ffi_ipv6_resolution_and_set_active_call() {
    use bmsip_ffi::bmsip_client_set_active_call;
    use std::ffi::CString;

    assert_eq!(
        unsafe { bmsip_client_set_active_call(ptr::null(), ptr::null()) },
        -1
    );

    // Bracketed and bare IPv6 registrar addresses must parse and bind cleanly.
    for (reg_addr, bind_ip) in [("::1", "::1"), ("[::1]:5060", "::1")] {
        let client = BmsipClient::new(FfiConfig {
            username: "1001".to_string(),
            password: "pw".to_string(),
            domain: "localhost".to_string(),
            registrar_addr: reg_addr.to_string(),
            bind_ip: bind_ip.to_string(),
            sip_port: 0,
            enable_opus: false,
        })
        .unwrap();
        let addr = client.local_sip_address();
        assert!(
            addr.starts_with("[::1]:") || addr.starts_with("::1:"),
            "unexpected IPv6 local_sip_address '{addr}'"
        );
        client.set_active_call("call-1".to_string()).unwrap();
        client.shutdown();
    }

    let user = CString::new("1001").unwrap();
    let pass = CString::new("pw").unwrap();
    let domain = CString::new("127.0.0.1").unwrap();
    let reg = CString::new("127.0.0.1:59999").unwrap();
    let bind = CString::new("127.0.0.1").unwrap();
    let cid = CString::new("call-1").unwrap();
    let handle = unsafe {
        bmsip_client_new(
            user.as_ptr(),
            pass.as_ptr(),
            domain.as_ptr(),
            reg.as_ptr(),
            bind.as_ptr(),
            0,
        )
    };
    assert!(!handle.is_null());
    assert_eq!(
        unsafe { bmsip_client_set_active_call(handle, cid.as_ptr()) },
        0
    );
    unsafe { bmsip_client_free(handle) };
}
