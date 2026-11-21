# bmsip SDK Integration Guide

This guide covers embedding `bmsip` across **Rust**, **C99/C++**, **iOS (Swift)**, and **Android (Kotlin)**, handling mobile network/background lifecycle transitions, and consuming per-call Black-Box telemetry.

---

## 1. Choosing an Integration Layer

| Target Environment | Recommended Crate / Boundary | Transport & Audio Ownership |
|---|---|---|
| Native Rust apps & services | `bmsip-engine` | Managed UDP/TCP/TLS (`rustls`) & timer loop; pluggable `AudioPort` trait (`8`/`16`/`48` kHz) |
| Custom event loops / simulators / async hosts | `bmsip-core` + `bmsip-media` | 100% Sans-I/O; host injects `Instant` and UDP datagrams directly |
| C / C++ / Go / Python | `bmsip-ffi` via [`bmsip.h`](../crates/bmsip-ffi/include/bmsip.h) | Non-blocking `BmsipClientHandle`, 20 ms PCM queue, JSON event polling |
| iOS (`Swift`) & Android (`Kotlin`) | `bmsip-ffi` via UniFFI [`bmsip.udl`](../crates/bmsip-ffi/src/bmsip.udl) | Typed `BmsipClient` + `FfiConfig`/`FfiEvent`; pairs with native AEC |

---

## 2. Rust Embedding (`bmsip-engine`)

### 2.1 Configuration (`UaConfig` & `EngineConfig`)

`UaConfig` ([`crates/bmsip-core/src/dialog/mod.rs`](../crates/bmsip-core/src/dialog/mod.rs)) configures SIP identity, Digest credentials, advertised SDP codecs, and RFC 3261 timers:

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use bmsip_engine::bmsip_core::dialog::UaConfig;
use bmsip_engine::bmsip_core::sdp::RtpCodec;
use bmsip_engine::bmsip_core::sip::SipUri;
use bmsip_engine::EngineConfig;

let registrar_addr: SocketAddr = "10.0.0.10:5060".parse()?;
let registrar_uri = SipUri::parse("sip:10.0.0.10:5060")?;

let mut ua_cfg = UaConfig::new(
    "1001",
    "secret1001",
    "pbx.example.com",
    registrar_uri,
    "0.0.0.0", // Updated automatically by SipEngine to reachable interface IP
    0,         // Ephemeral UDP SIP port
);
ua_cfg.supported_codecs = vec![
    RtpCodec::opus(),
    RtpCodec::g722(),
    RtpCodec::pcmu(),
    RtpCodec::pcma(),
    RtpCodec::telephone_event_48k(102),
    RtpCodec::telephone_event(101),
];

let mut engine_cfg = EngineConfig::new(
    ua_cfg,
    registrar_addr,
    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    0,
);
engine_cfg.telemetry_capacity = 512; // Bounded global ring size (minimum 16)
```

Optional transport (`UDP`/`TCP`/`TLS`), RFC 4028 Session-Timers, and RFC 3323/3325 Caller-ID builders on `UaConfig` and `EngineConfig`:

```rust
use bmsip_engine::bmsip_core::sip::SipTransport;
use bmsip_engine::TlsConfig;

let ua_cfg = ua_cfg
    .with_transport(SipTransport::Tls) // SipTransport::Udp (default), Tcp, or Tls
    .with_session_timers(Some(1800), 90) // Session-Expires (s), Min-SE (s); pass None to disable
    .with_caller_identity(
        Some(NameAddr::parse("\"Alice\" <sip:+15550100@pbx.example.com>")?),
        Some("none".to_string()),
    );

let tls_cfg = TlsConfig::new()
    .with_server_name("pbx.example.com")
    .with_ca_cert_pem(custom_ca_pem); // Optional: add private CA; also supports .with_client_identity(...) for mTLS
let engine_cfg = engine_cfg.with_tls_config(tls_cfg);
```

### 2.2 Non-Blocking Commands & Events (`SipEngine`)

`SipEngine::spawn(config, audio_port)` starts a dedicated worker thread (`"bmsip-engine"`). Multiple `SipEngine` instances can run simultaneously in the same process without shared mutable globals.

#### Outbound `EngineCommand` Variants

| Command | Behavior |
|---|---|
| `Register` / `Unregister` | Starts or terminates RFC 3261 `REGISTER` with automatic 401/407 Digest retry and 80%-expiry refresh |
| `Dial { target_uri }` | Binds an ephemeral RTP UDP socket and sends `INVITE` with negotiated SDP offer |
| `Ring { call_id }` | Sends `180 Ringing` on an inbound call |
| `RingEarlyMedia { call_id }` | Sends `183 Session Progress` with negotiated SDP and starts early RTP TX/RX before `200 OK` |
| `Answer { call_id }` | Binds (or reuses early-media) RTP socket and replies `200 OK` with intersected SDP answer |
| `Hangup { call_id }` | Sends `CANCEL` (deferred until `1xx` per RFC 3261 §9.1) or `BYE` on established dialogs |
| `Hold { call_id }` / `ResumeCall { call_id }` | Sends in-dialog `re-INVITE` toggling `a=sendonly`/`a=inactive` (hold, muting outbound RTP TX) and `a=sendrecv` (resume) |
| `Transfer { call_id, target_uri }` | Initiates a blind transfer (`REFER`, RFC 3515) to `target_uri` |
| `AttendedTransfer { call_id, target_call_id }` | Initiates an attended transfer (`REFER` with `?Replaces=...`, RFC 3891) bridging `call_id` to `target_call_id` |
| `SendDtmf { call_id, digit }` | Enqueues an RFC 4733 `telephone-event` digit (`0`–`9`, `*`, `#`, `A`–`D`), paced 1 packet per 20 ms tick |
| `SendInfoDtmf { call_id, digit, duration_ms }` | Sends a legacy RFC 2976 SIP `INFO` (`application/dtmf-relay`) DTMF request (`40`–`5000` ms) |
| `NetworkChanged { new_bind_ip, new_sip_port }` | Rebinds SIP and active RTP/RTCP sockets, updates `local_sip_addr`, refreshes `REGISTER`, and sends in-dialog `re-INVITE` with updated IP/RTP ports |
| `Suspend` / `Resume` | Pauses active RTP TX/RX when backgrounded; re-registers on foreground wakeup if previously registered |
| `ExportTelemetry { call_id }` | Emits `EngineEvent::TelemetryExported` with global or per-call JSON trace |
| `Shutdown` | Cleanly terminates the worker thread and emits `EngineEvent::Stopped` |

#### Inbound `EngineEvent` Variants

Drain events with `engine.try_recv_event()` or `engine.recv_event_timeout(timeout)`:

- `RegistrationChanged(RegistrationState)`
- `OutboundCallStarted { call_id }`
- `IncomingCall { call_id, from, to }`
- `CallRinging { call_id, status_code }`
- `EarlyMediaStarted { call_id, codec, remote_rtp }`
- `CallEstablished { call_id, codec, remote_rtp }`
- `CallMediaUpdated { call_id, remote_rtp }`
- `CallHoldChanged { call_id, local_hold, remote_hold }`
- `CallTransferRequested { call_id, refer_to }`
- `TransferStatus { call_id, status_code, reason, terminated }`
- `DtmfReceived { call_id, digit }`
- `CallTerminated { call_id, status_code, reason, black_box_json }`
- `Suspended`, `Resumed { local_sip_addr }`, `NetworkUpdated { local_sip_addr }`
- `TelemetryExported { call_id, json }`
- `Warning(String)`
- `Stopped`

### 2.3 Using Sans-I/O `bmsip-core` Directly

When integrating into custom async runtimes or deterministic simulators:

1. Instantiate `UserAgent::new(ua_config)`.
2. Call `ua.register(now)`, `ua.dial(uri, rtp_port, now)`, `ua.answer(&call_id, rtp_port, now)`, etc.
3. Drain outbound UDP payloads with `ua.poll_transmit()` after every call.
4. Feed inbound UDP datagrams with `ua.receive_datagram(&bytes, now)`.
5. Check `ua.poll_timeout() -> Option<Instant>` and invoke `ua.handle_timeout(now)` when expired.

---

## 3. Cross-Platform FFI (`bmsip-ffi`)

`bmsip-ffi` wraps `SipEngine` and `PcmQueueAudioPort` inside `BmsipClient` ([`crates/bmsip-ffi/src/client.rs`](../crates/bmsip-ffi/src/client.rs), `#![forbid(unsafe_code)]`) and exposes both UniFFI and C99 APIs.

### 3.1 UniFFI Interface (`bmsip.udl` — Swift & Kotlin)

Defined in [`crates/bmsip-ffi/src/bmsip.udl`](../crates/bmsip-ffi/src/bmsip.udl):

- **Configuration (`FfiConfig`):** `username`, `password`, `domain`, `registrar_addr`, `bind_ip`, `sip_port`, `enable_opus`.
  When `enable_opus` is `true`, `BmsipClient` offers `[Opus, G722, PCMU, PCMA, CN, telephone-event/48000, telephone-event/8000]`; when `false`, it offers `[G722, PCMU, PCMA, CN, telephone-event/8000]`.
- **Sample Rate & Transport Selection:** Default `BmsipClient(config)` uses UDP with an `8000` Hz (`160` samples/20 ms) bridge; use `BmsipClient.with_sample_rate(config, 16000 | 48000)` for wideband/fullband PCM or `BmsipClient.with_transport(config, sample_rate_hz, FfiTransport.Tls, tls_ca_pem, tls_insecure)` to enable TCP or TLS 1.2–1.3 signaling (`Udp`/`Tcp`/`Tls`), and inspect the active rate via `audio_sample_rate_hz()`.
- **Audio Exchange:**
  - `push_captured_pcm(samples)` — pushes one 20 ms (`160` @ 8 kHz, `320` @ 16 kHz, or `960` @ 48 kHz) mono PCM frame captured from OS audio.
  - `pop_playout_pcm() -> sequence<i16>?` — pops the next decoded 20 ms frame sized for `audio_sample_rate_hz()`.
- **Event Polling:** `poll_event(timeout_ms) -> FfiEvent?` returns structured `FfiEventKind`, `call_id`, `detail`, `status_code`, and `black_box_json`.
- **Call Control Methods:** `ring_early_media(call_id)`, `hold(call_id)`, `resume_call(call_id)`, `transfer(call_id, target_uri)`, `attended_transfer(call_id, target_call_id)`, and `send_info_dtmf(call_id, digit, duration_ms)` map directly to `EngineCommand` and report state updates via `FfiEventKind::{EarlyMediaStarted, CallHoldChanged, CallTransferRequested, TransferStatus, DtmfReceived}`.
- **Errors (`FfiError`):** `"InvalidArgument"`, `"RuntimeError"`, `"Closed"`.

### 3.2 iOS Swift Reference (`BmsipIosAudioBridge.swift`)

[`bindings/ios/BmsipIosAudioBridge.swift`](../bindings/ios/BmsipIosAudioBridge.swift) demonstrates production iOS integration:

- Configures `AVAudioSession` (`.playAndRecord`, `.voiceChat`, `20 ms` IO buffer) and enables Apple hardware AEC via `audioEngine.inputNode.setVoiceProcessingEnabled(true)`.
- Uses `AVAudioEngine` input tap + `AVAudioSourceNode` render callback calling `pushCapturedPcm` / `popPlayoutPcm`.
- Integrates `CXProvider` (`CallKit`) and monitors interface switches (`Wi-Fi <-> 5G/LTE`) via `NWPathMonitor`, forwarding transitions to `client.notifyNetworkChanged(...)`.

### 3.3 Android Kotlin Reference (`BmsipAndroidAudioBridge.kt`)

[`bindings/android/BmsipAndroidAudioBridge.kt`](../bindings/android/BmsipAndroidAudioBridge.kt) demonstrates production Android integration:

- Captures with `MediaRecorder.AudioSource.VOICE_COMMUNICATION` and attaches hardware `AcousticEchoCanceler`.
- Plays back via `AudioTrack` (`MODE_STREAM`, `USAGE_VOICE_COMMUNICATION`).
- Registers `ConnectivityManager.NetworkCallback` to trigger `client.notifyNetworkChanged(...)` on active network switches.

### 3.4 C99 / C++ ABI (`include/bmsip.h`)

[`crates/bmsip-ffi/include/bmsip.h`](../crates/bmsip-ffi/include/bmsip.h) provides an opaque pointer ABI (`BmsipClientHandle *`):

- **Constructors:** `bmsip_client_new(...)` creates an 8 kHz UDP client (G.722/PCMU/PCMA); `bmsip_client_new_ex(..., enable_opus, sample_rate_hz)` enables Opus (`enable_opus != 0`) and selects `8000`, `16000`, or `48000` Hz PCM framing (queryable via `bmsip_client_audio_sample_rate_hz`); `bmsip_client_new_transport(..., transport, tls_ca_pem, tls_insecure)` additionally selects `"udp"`, `"tcp"`, or `"tls"` with optional PEM CA trust bundle.
- **Return Convention:** Action functions (`bmsip_client_register`, `bmsip_client_dial`, `bmsip_client_ring_early_media`, `bmsip_client_answer`, `bmsip_client_hangup`, `bmsip_client_hold`, `bmsip_client_resume_call`, `bmsip_client_transfer`, `bmsip_client_attended_transfer`, `bmsip_client_send_dtmf`, `bmsip_client_send_info_dtmf`, etc.) return `0` on success or `-1` on error.
- **PCM Functions:**
  - `bmsip_client_push_pcm(client, samples, len)` returns `0` on success (`-1` if `len` does not match the 20 ms frame length for the configured sample rate: `160`, `320`, or `960`).
  - `bmsip_client_pop_pcm(client, out_samples, capacity)` returns the number of copied samples (`160`/`320`/`960`), `0` if empty, or `-1` on error.
- **Memory Management:** Strings returned by `bmsip_client_poll_event_json` must be freed via `bmsip_string_free(s)`. Clients must be released with `bmsip_client_free(client)`.
- See [`bindings/c/minimal_phone.c`](../bindings/c/minimal_phone.c) for a complete runnable C99 example (`gcc -std=c99 -Wall -Wextra -Werror`).

---

## 4. Mobile Lifecycle Primitives

### 4.1 Network Handover (`NetworkChanged`)

When the device moves between networks (e.g., Wi-Fi to LTE):

1. Application issues `EngineCommand::NetworkChanged { new_bind_ip, new_sip_port }` (or `BmsipClient::notify_network_changed`).
2. `SipEngine` rebinds the SIP transport socket (dropping any stale TCP/TLS connections immediately) and probes the updated reachable local IP.
3. `UserAgent::notify_network_changed` updates advertised `Contact` / SDP IP, triggers an immediate `REGISTER` refresh if registered, and sends an in-dialog `re-INVITE` on active `Established` calls with the updated SDP.

### 4.2 Background Suspend & Push Wakeup (`Suspend` / `Resume`)

When backgrounded on iOS or Android:

1. `Suspend` halts active media pumping while preserving dialog state and registration status.
2. On PushKit/FCM wakeup, sending `Resume` restores media activity and re-issues `REGISTER` if the endpoint was registered prior to suspend.

---

## 5. Black-Box Flight Recorder Telemetry

`FlightRecorder` ([`crates/bmsip-engine/src/telemetry.rs`](../crates/bmsip-engine/src/telemetry.rs)) captures timestamped diagnostics into a bounded global ring buffer and per-call trace without ever recording plaintext passwords:

- **Categories (`TelemetryCategory`):** `sip_rx`, `sip_tx`, `dialog_fsm`, `registration_fsm`, `rtp_stats`, `lifecycle`, `warning`.
- **Automatic Export:** Every `EngineEvent::CallTerminated` carries `black_box_json`.
- **On-Demand Export:** Issue `EngineCommand::ExportTelemetry { call_id: Some(cid) }` (or `None` for the full global ring).

#### `CallBlackBoxSnapshot` JSON Schema

```json
{
  "call_id": "bmsip-call-1",
  "direction": "outbound",
  "final_state": "terminated (OK)",
  "rtp_packets_sent": 50,
  "rtp_packets_received": 48,
  "rtp_packets_lost": 0,
  "rtp_jitter_samples": 12,
  "dtmf_digits_received": ["5"],
  "events": [
    {
      "seq": 4,
      "elapsed_ms": 18,
      "category": "dialog_fsm",
      "call_id": "bmsip-call-1",
      "summary": "call established codec=G722 remote_rtp=172.20.0.3:10014"
    }
  ]
}
```
