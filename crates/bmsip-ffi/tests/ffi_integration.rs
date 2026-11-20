use std::ffi::{CStr, CString};
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use bmsip_ffi::bmsip_engine::bmsip_media::WavPcm16;
use bmsip_ffi::{
    bmsip_client_dial, bmsip_client_free, bmsip_client_hangup, bmsip_client_new,
    bmsip_client_poll_event_json, bmsip_client_pop_pcm, bmsip_client_push_pcm,
    bmsip_client_register, bmsip_client_unregister, bmsip_string_free, BmsipClient, FfiConfig,
    FfiEvent, FfiEventKind,
};

#[test]
fn udl_schema_matches_rust_sdk_surface() {
    let udl = include_str!("../src/bmsip.udl");
    for required in [
        "namespace bmsip",
        "enum FfiError",
        "dictionary FfiConfig",
        "enum FfiEventKind",
        "dictionary FfiEvent",
        "interface BmsipClient",
        "register_account()",
        "unregister_account()",
        "dial(string target_uri)",
        "ring(string call_id)",
        "answer(string call_id)",
        "hangup(string call_id)",
        "send_dtmf(string call_id, string digit)",
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
        FfiEventKind::CallEstablished,
        FfiEventKind::CallMediaUpdated,
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
        assert_eq!(bmsip_client_hangup(handle, c_cid.as_ptr()), 0);
        thread::sleep(Duration::from_millis(150));
        assert_eq!(bmsip_client_unregister(handle), 0);
        thread::sleep(Duration::from_millis(150));
        bmsip_client_free(handle);
    }
}
