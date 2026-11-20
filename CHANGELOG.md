# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

