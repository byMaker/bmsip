# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-11-20

### Added
- Multi-server SIP interoperability environment in `docker-compose.yml`:
  - `.devcontainer/freeswitch/` running FreeSWITCH 1.10 (`mod_sofia` + `mod_opus`, `407 Proxy-Authenticate`, `Echo` `601`, extensions `1001`–`1003`).
  - `.devcontainer/kamailio/` running Kamailio 5.8 RFC 3261 SIP Proxy & Registrar (`Record-Route`/`Route` loose routing, dual `Via`, direct P2P RTP relay).
- RFC 3261 §12.1.1 `Record-Route` preservation in `SipRequest::create_response` and `RtpCodec::telephone_event_48k` matching `48000 Hz` Opus RTP clocks (`bmsip-core`).
- Paced 20 ms RFC 4733 DTMF transmission (`MediaSession::pop_dtmf_packet` and `SipEngine::pump_media_tick`) for strict FreeSWITCH `mod_sofia` interoperability (`bmsip-media`, `bmsip-engine`).
- `bmsip-cli` DSP audio quality analyzer (`analyze`), 5-case PBX echo `selftest`, and unified 9-scenario multi-server `interop` command across Asterisk, FreeSWITCH, and Kamailio.
- Smooth boundary crossfade on concealed/recovered frames in `AdaptiveJitterBuffer` (`bmsip-media`).
- Live multi-server integration test `live_freeswitch_and_kamailio_multi_server_interop` in `crates/bmsip-engine/tests/asterisk_integration.rs`.

## [0.7.0] - 2026-11-20

### Added
- Native 48 kHz `libopus` FFI backend (`LibOpusCodec` in `crates/bmsip-engine/src/opus_native.rs`) with automatic `libopus` linking (`crates/bmsip-engine/build.rs`) and `libopus-dev` in `.devcontainer/Dockerfile`.
- End-to-end 48 kHz `AudioPort` support (`sample_rate_hz`, `capture_frame_20ms`) across `bmsip-engine`, `WavAudioPort`, and `LiveLinuxAudioPort`.
- Microphone DSP conditioning (`condition_mic_frame` in `bmsip-media::opus`): continuous soft noise gate, fixed-point gain scaling, and rational soft-knee peak limiting.
- Pre-roll buffering (2 frames TX, 3 frames RX) and decayed TX underrun concealment in `LiveLinuxAudioPort` eliminating live audio underrun clicks.
- CLI flags `--codec <opus|pcmu|pcma>` (default: `opus`) and `--mic-gain <mult>` (default: `4.0`) in `bmsip-cli` for both `call` and `listen`.
- Asterisk `allow=opus,ulaw,alaw` on PJSIP endpoints `[1001]`–`[1003]` and live 48 kHz `libopus` echo integration test (`live_asterisk_opus_48khz_libopus_echo_and_two_engine_call`).

### Changed
- Upgraded `OpusCodecBackend` and `MediaSession` to support both 48 kHz (`960` samples/20 ms) and 8 kHz (`160` samples/20 ms) frames with pluggable backend injection (`with_opus_backend`) and scaled adaptive jitter depth calculation.

## [0.6.0] - 2026-11-20

### Added
- Host PipeWire/PulseAudio and ALSA passthrough in `.devcontainer/Dockerfile` and `docker-compose.yml`.
- `LiveLinuxAudioPort` (`crates/bmsip-cli/src/live_audio.rs`, `#![forbid(unsafe_code)]`) streaming 8 kHz mono PCM16 frames via `pacat` / ALSA with non-blocking queues.
- `bmsip-cli` `--live-audio` option for `call` and new `listen` subcommand for inbound call answering.
- Reference platform integration adapters in `bindings/`:
  - iOS Swift bridge (`bindings/ios/BmsipIosAudioBridge.swift`) using `AVAudioEngine` (VoiceProcessingIO AEC), `CallKit`, and `NWPathMonitor`.
  - Android Kotlin bridge (`bindings/android/BmsipAndroidAudioBridge.kt`) using `AudioRecord`/`AcousticEchoCanceler`, `AudioTrack`, and `ConnectivityManager`.
  - C99 example (`bindings/c/minimal_phone.c`) verified with `gcc -std=c99 -Wall -Wextra -Werror`.
- Future Roadmap / `TODO` section in `ARCHITECTURE.md` covering native `libopus` C FFI integration and TCP/TLS + SRTP transport encryption.

## [0.5.0] - 2026-11-20

### Added
- `bmsip-media::opus` RFC 6716 Opus TOC framing, RFC 7587 `fmtp` parser, 8 kHz <-> 48 kHz resampling helpers, `OpusCodecBackend` trait, `BuiltInOpusCodec`, and 48 kHz `SessionCodec::Opus` support in `MediaSession` and `SipEngine`.
- `bmsip-ffi` cross-platform SDK boundary (`cdylib`, `staticlib`, `rlib`):
  - Authoritative UniFFI IDL contract (`crates/bmsip-ffi/src/bmsip.udl`) for Swift (iOS) and Kotlin (Android).
  - Safe `BmsipClient` SDK wrapper (`crates/bmsip-ffi/src/client.rs`, `#![forbid(unsafe_code)]`) over `SipEngine` and `PcmQueueAudioPort`.
  - C99/C++-compatible `extern "C"` ABI (`crates/bmsip-ffi/src/c_api.rs`) and header (`crates/bmsip-ffi/include/bmsip.h`).
- FFI schema validation, `gcc -std=c99 -Werror` header check, and live Asterisk `BmsipClient` + C-API integration test (`crates/bmsip-ffi/tests/ffi_integration.rs`).

## [0.4.0] - 2026-11-20

### Added
- `bmsip-engine` lock-safe, multi-instance SIP runtime (`#![forbid(unsafe_code)]`):
  - Non-blocking `EngineCommand` / `EngineEvent` runtime (`SipEngine`) wiring `bmsip-core::dialog::UserAgent` and `bmsip-media::MediaSession` over UDP SIP and RTP sockets with 20 ms audio pacing.
  - Hardware-agnostic `AudioPort` trait with `NullAudioPort`, `WavAudioPort`/`WavAudioHandle`, and `PcmQueueAudioPort`/`PcmAudioHandle`.
  - Mobile lifecycle primitives (`NetworkChanged`, `Suspend`, `Resume`).
  - Bounded `FlightRecorder` ("black box") capturing sanitized SIP wire summaries, FSM transitions, DTMF digits, and RTP statistics with dependency-free JSON export on call termination or `ExportTelemetry`.
- `bmsip-cli` Linux CLI SIP softphone supporting `call` execution with tone/WAV TX, RX WAV recording, DTMF sending, and black-box JSON telemetry output.
- Live Asterisk multi-engine integration test (`live_asterisk_two_engines_call_audio_dtmf_lifecycle_and_blackbox`).

## [0.3.0] - 2026-11-20

### Added
- `bmsip-media` hardware-agnostic RTP/RTCP, codec, and jitter buffer crate (`#![forbid(unsafe_code)]`):
  - RFC 3550 RTP parser/serializer with CSRC, extension headers, padding validation, and `RtpPacketizer`.
  - RFC 3550 RTCP compound packet parser/serializer (`SR`, `RR`, `BYE`) and `RtpStreamStats` loss/wraparound/jitter tracker.
  - Pure-Rust ITU-T G.711 `PCMU` (μ-law, PT 0) and `PCMA` (A-law, PT 8) codecs.
  - RFC 4733 `telephone-event` DTMF packet generator (`DtmfSender`) and deduplicating detector (`DtmfDetector`).
  - `AdaptiveJitterBuffer` with 16-bit sequence wraparound reordering, jitter-driven depth adaptation, and decayed PLC.
  - In-memory RIFF/WAVE 16-bit mono PCM codec (`WavPcm16`) and unified `MediaSession` pipeline.
- Live Asterisk `Echo()` RTP/G.711 audio echo and WAV round-trip integration test (`live_asterisk_rtp_g711_audio_echo_and_wav_roundtrip`).

## [0.2.0] - 2026-11-20

### Added
- `bmsip-core::dialog` Sans-I/O User Agent (`UserAgent`), Registration FSM (RFC 3261 §10), and Invite Dialog FSM (RFC 3261 §9, §12–15):
  - `REGISTER` / `unregister` with `401`/`407` Digest challenge retry and automatic 80%-interval registration refresh.
  - `dial`, `ring`, `answer`, `hangup`, `reinvite`, and `notify_network_changed` (`Wi-Fi <-> LTE` handover triggering registration refresh and in-dialog `re-INVITE`).
  - RFC 3261 §9.1 deferred `CANCEL` ordering (queues `CANCEL` if called prior to `1xx`) and `200 OK` vs `CANCEL` race handling (`ACK` + `BYE`).
  - UAS `200 OK` retransmission timer until `ACK` arrives (RFC 3261 §13.3.1.4) and automatic `200 OK` responses to `OPTIONS` keepalives.
- Deterministic multi-party dialog simulation test suite (`crates/bmsip-core/tests/dialog_simulation.rs`).
- Docker Compose `asterisk` (Asterisk 22 `chan_pjsip`) test PBX service in `.devcontainer/asterisk/` and live UDP integration test (`crates/bmsip-engine/tests/asterisk_integration.rs`).

## [0.1.0] - 2026-11-20

### Added
- Five-crate Cargo workspace (`bmsip-core`, `bmsip-media`, `bmsip-engine`, `bmsip-ffi`, `bmsip-cli`) with Docker Compose Dev Container toolchain (`rust:1-bookworm`).
- `bmsip-core` dependency-free Sans-I/O protocol core (`#![forbid(unsafe_code)]`):
  - SIP/2.0 parser and serializer with compact headers, folded headers, IPv6 URI support, `Via` `rport`/`received`, `NameAddr`, and `CSeq`.
  - SDP audio parser/serializer (RFC 4566) and Offer/Answer codec/direction negotiation (RFC 3264).
  - Pure-Rust MD5 (RFC 1321) and SHA-256 (FIPS 180-4) Digest Authentication (`MD5`, `MD5-sess`, `SHA-256`, `SHA-256-sess`, `qop=auth` and legacy modes).
  - RFC 3261 Section 17 transaction state machines (`ClientInviteTransaction`, `ClientNonInviteTransaction`, `ServerInviteTransaction`, `ServerNonInviteTransaction`) with Timers A–K and auto-`ACK` on `3xx–6xx`.
  - Deterministic Sans-I/O `VirtualNetwork` simulator and integration tests covering packet loss, duplication, Digest auth, `486 Busy Here`, `200 OK` + SDP negotiation, and timer timeouts.

