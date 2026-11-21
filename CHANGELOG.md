# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0] - 2026-11-21

### Added
- **Early Media `183` / `180` SDP Playout (`bmsip-core`, `bmsip-engine`, `bmsip-ffi`):**
  - Added `UserAgent::ring_early_media` (supporting optional `100rel` reliable early-media SDP responses) and `UserAgent::{negotiated_codecs, local_rtp_port, remote_sdp}` accessors; UAC provisional `1xx` handling now intersects early-media SDP codecs and reuses the early RTP socket upon `200 OK` answer.
  - Added `EngineCommand::RingEarlyMedia`, `EngineEvent::EarlyMediaStarted`, `BmsipClient::ring_early_media`, C99 `bmsip_client_ring_early_media`, and enabled RTP TX/RX pumping while in `CallState::Ringing` for active early-media sessions.
- **Legacy SIP `INFO` DTMF (`bmsip-core`, `bmsip-engine`, `bmsip-ffi`, `bmsip-cli`):**
  - Implemented RFC 2976 SIP `INFO` (`application/dtmf-relay` and `application/dtmf`) sending (`UserAgent::send_info_dtmf` with 401/407 Digest retry) and inbound validation (`415` on unsupported `Content-Type`, `400` on invalid DTMF payload, `UaEvent::DtmfReceived` -> `EngineEvent::DtmfReceived`).
  - Added `EngineCommand::SendInfoDtmf`, `BmsipClient::send_info_dtmf`, C99 `bmsip_client_send_info_dtmf`, and `--dtmf-mode rfc4733|info` in `bmsip-cli call`.
- **RFC 3389 Comfort Noise (`bmsip-core`, `bmsip-media`, `bmsip-engine`):**
  - Added SDP static payload type `13` (`RtpCodec::cn()`, `RtpCodec::is_comfort_noise()`, included in default offered codecs while still requiring a primary speech codec in `negotiate_offer_answer`).
  - Implemented `bmsip_media::cn` (`ComfortNoisePacket`, `ComfortNoiseGenerator`), `PlayoutFrame::ComfortNoise`, and SID DTX synthesis & auto-deactivation inside `MediaSession::receive_rtp` / `pop_playout_frame`.

## [0.10.0] - 2026-11-21

### Added
- **Core Call Control, Session Timers & Identity (`bmsip-core`):**
  - Implemented **Call Hold / Resume** (`UserAgent::hold`, `UserAgent::resume_call`, `UserAgent::hold_state`, `UaEvent::CallHoldChanged`) via RFC 3264 / RFC 6337 `re-INVITE` SDP direction negotiation (`a=sendonly`, `a=recvonly`, `a=inactive`, `a=sendrecv`).
  - Implemented **Blind & Attended Call Transfer** (`UserAgent::refer`, `UserAgent::attended_transfer`, `UserAgent::dial_with_replaces`, `UserAgent::notify_refer_status`) supporting RFC 3515 `REFER`, RFC 3891 `Replaces` header / `?Replaces=` URI promotion and target dialog replacement, `Referred-By`, and `NOTIFY` `message/sipfrag` progress events (`UaEvent::CallTransferRequested`, `UaEvent::TransferNotify`).
  - Implemented early/in-dialog **`UPDATE`** (RFC 3311, `UserAgent::send_update`) and **Reliable Provisional `1xx` / `PRACK`** (RFC 3262, `UserAgent::ring_reliable`, automatic `RSeq`/`RAck` `PRACK` generation and server validation).
  - Implemented **RFC 4028 Session Timers** (`UaConfig::with_session_timers`, `SessionExpires`, `Min-SE` negotiation, `422 Session Interval Too Small` automatic retry, periodic `UPDATE` refresh at half the negotiated interval, and automatic `408`-style `BYE` cleanup upon timeout expiry).
  - Added **RFC 3326 `Reason`** headers (`UserAgent::hangup_with_reason`, `ReasonHeader`, `UaEvent::CallTerminated::reason_header`) and **RFC 3323 / RFC 3325 Caller Identity** (`UaConfig::with_caller_identity`, `P-Asserted-Identity`, `P-Preferred-Identity`, `Remote-Party-ID`, `Privacy`, `CallerIdentity`, `UaEvent::IncomingCall::caller_identity`).
- **Engine, FFI & CLI Call Control (`bmsip-engine`, `bmsip-ffi`, `bmsip-cli`):**
  - Added `EngineCommand::{Hold, ResumeCall, Transfer, AttendedTransfer}` and `EngineEvent::{CallHoldChanged, CallTransferRequested, TransferStatus}`, muting outbound RTP/DTMF TX while locally held and draining mic capture cleanly.
  - Exposed `hold`, `resume_call`, `transfer`, and `attended_transfer` on `BmsipClient` (`bmsip.udl`) and `bmsip_client_{hold,resume_call,transfer,attended_transfer}` in `include/bmsip.h` alongside `FfiEventKind::{CallHoldChanged, CallTransferRequested, TransferStatus}`.
  - Added `--hold-ms <ms>` and `--transfer <sip_uri>` flags to `bmsip-cli call`.

## [0.9.2] - 2026-11-21

### Fixed
- **SIP Dialog & Auth RFC Compliance (`bmsip-core`):**
  - Removed duplicate `Record-Route` header emission in `UserAgent::answer` (`SipRequest::create_response` already copies `Record-Route` per RFC 3261 §12.1.1).
  - Handled inbound `re-INVITE` glare with `491 Request Pending` (RFC 3261 §14.2) instead of `481`, and added in-dialog `remote_cseq` ordering validation returning `500 Server Internal Error` for stale/reordered `re-INVITE` and `BYE` requests (RFC 3261 §12.2.2).
  - Added injected `UaConfig::instance_seed` (auto-seeded in `SipEngine::spawn`) so Call-IDs, tags, branches, and Digest `cnonce` values never collide across process restarts on fixed SIP ports while keeping `bmsip-core` 100% deterministic.
  - Honored Digest `stale=true` nonce rotation challenges up to 3 bounded retries across `REGISTER`, `INVITE`/`re-INVITE`, and `BYE` while failing immediately on non-stale credential rejections.
  - Sent `488 Not Acceptable Here` and cleared call state cleanly when `UserAgent::answer` fails due to a missing SDP offer or incompatible codecs instead of stranding the server transaction.
  - Added multi-`Contact` parsing (`SipRequest::contacts`, `SipResponse::contacts`) and matched the local contact binding when extracting `REGISTER` `200 OK` expiry.
- **Media DTMF, SSRC Rollover & RTCP Intervals (`bmsip-media`):**
  - Scaled RFC 4733 DTMF packet durations by the negotiated `telephone-event` RTP clock rate (`DtmfSender::queue_digit_with_clock_rate`, `MediaSession::with_dtmf_clock_rate`) so 48 kHz Opus DTMF tones last a full 100 ms (`4800` ticks) instead of `16.7 ms` (`800` ticks).
  - Detected mid-call remote `SSRC` changes in `MediaSession::receive_rtp` and seamlessly reset `RtpStreamStats`, `AdaptiveJitterBuffer`, and `DtmfDetector` to avoid sequence lockups or jitter spikes after PBX bridges/transfers.
  - Advanced RFC 3550 §6.4.1 interval loss counters (`expected_prior`/`received_prior`) in `MediaSession::build_rtcp_receiver_report(&mut self)` (preserving non-mutating `snapshot_rtcp_receiver_report(&self)`).
  - Added `MediaSession::reconfigure_codec` and `RtpPacketizer::set_payload_type` for mid-call `re-INVITE` codec updates.
- **Engine Routing, Handover & Multi-Call Determinism (`bmsip-engine`):**
  - Implemented RFC 3581 / RFC 3261 §12.2.1.1 SIP UDP destination routing (symmetric response routing to the inbound packet source, topmost `Route` proxy resolution, and direct in-dialog `Contact` routing) instead of sending every datagram exclusively to `registrar_addr`.
  - Applied negotiated codec/DTMF changes on `UaEvent::CallMediaUpdated` (`re-INVITE`) and rebound active RTP/RTCP sockets onto the new interface during `EngineCommand::NetworkChanged` (`UserAgent::notify_network_changed_with_rtp_ports`).
  - Replaced non-deterministic `HashMap` call ordering with explicit FIFO `call_order` tracking and drained secondary call jitter buffers/DTMF queues on every 20 ms tick.
  - Added opt-in/bounded RX WAV recording (`WavAudioPort::new_with_recording`, `.with_max_recorded_samples`) and multi-rate `PcmQueueAudioPort::new_with_sample_rate` (`8`/`16`/`48` kHz).
- **FFI Wideband/Fullband HD Audio & CLI Live Playout (`bmsip-ffi`, `bmsip-cli`):**
  - Added `BmsipClient::new_with_sample_rate` / `audio_sample_rate_hz` (`bmsip.udl` `[Name=with_sample_rate]`) and C99 `bmsip_client_new_ex` / `bmsip_client_audio_sample_rate_hz` (`bmsip.h`) supporting native `8`/`16`/`48` kHz PCM bridges alongside `G.722` and `telephone-event/48000` SDP negotiation.
  - Added 16 kHz -> 48 kHz playout upsampling and opt-in RX recording (`spawn_with_options`) in `LiveLinuxAudioPort` so `--live-audio` runs in constant memory when `--wav-out` is not requested.

## [0.9.1] - 2026-11-21

### Changed
- **Anti-Aliasing FIR Resamplers & Cross-Frame `StreamResampler` (`bmsip-media`):**
  - Replaced box-averaging downsamplers (`downsample_48k_to_8k`, `downsample_16k_to_8k`, `downsample_48k_to_16k`) with symmetric low-pass triangular FIR kernels for cleaner live microphone downsampling into G.711 and G.722.
  - Added stateful cross-frame `StreamResampler` in `MediaSession` so sequential 20 ms frame upsampling preserves boundary slope continuity.
- **Zero-Copy RTP Hot Path (`bmsip-media`, `bmsip-engine`):**
  - Added `RtpPacketRef::parse` borrowed validation and `RtpPacketizer::next_packet_bytes` / `build_custom_packet_bytes` direct serialization to eliminate per-packet payload `Vec` clones on every 20 ms tick.
- **Instant Command Wakeup & Adaptive Polling (`bmsip-engine`):**
  - Added `Condvar` notification in `SipEngine::send_command` for microsecond command responsiveness and scaled idle polling (`20 ms` idle / `5 ms` active call) to reduce CPU wakeups.
- **Live RTCP Socket & Periodic Receiver Reports (`bmsip-media`, `bmsip-engine`):**
  - Added best-effort companion RTCP UDP socket binding (`rtp_port + 1`), `MediaSession::receive_rtcp` for Sender Report `LSR` tracking, and periodic 5-second RTCP `RR` transmission during active calls.
- **Deterministic Wire-Parser Mutation Fuzzing (`bmsip-core`, `bmsip-media`):**
  - Added 4,000-iteration deterministic mutation stress suites covering `SipMessage`, `SdpSession`, `DigestChallenge`, `SipUri`, `UserAgent`, `RtpPacketRef`, `RtpPacket`, `RtcpPacket`, `DtmfEventPayload`, `OpusToc`/`OpusFmtp`, and `G722Codec`.

## [0.9.0] - 2026-11-21

### Added
- Universal pluggable audio codec plugin system (`crates/bmsip-media/src/plugin.rs`, `#![forbid(unsafe_code)]`):
  - `AudioCodecDescriptor`, `AudioCodecPlugin`, `AudioCodecFactory`, `FnCodecFactory`, and `CodecRegistry` supporting arbitrary sample rates (`8`/`16`/`48` kHz) via automatic 20 ms PCM resampling (`resample_pcm_20ms`).
  - `MediaSession::new_with_plugin` / `.with_codec_plugin` and `SessionCodec::Custom` in `bmsip-media`.
  - `EngineConfig::register_codec` and `EngineConfig::register_custom_codec` in `bmsip-engine` so host applications can register external codecs without modifying core crates.
- Built-in pure-Rust ITU-T G.722 (64 kbps Mode 1, 16 kHz wideband HD Voice, static payload type `9` with RFC 3551 §4.5.2 8 kHz RTP clock) in `crates/bmsip-media/src/g722.rs` (`#![forbid(unsafe_code)]`) and `RtpCodec::g722()` in `bmsip-core`.
- 16 kHz `WavAudioPort` support and `PCM_FRAME_SAMPLES_16KHZ_20MS` export in `bmsip-engine`.
- `--codec g722` flag in `bmsip-cli`, G.722 wideband echo checks in `selftest` (7 cases) and `interop` (12 scenarios).
- Enabled `g722` on Asterisk PJSIP endpoints (`allow=opus,g722,ulaw,alaw`) and loaded `mod_spandsp` with `G722` codec preferences in FreeSWITCH.
- Live integration test `live_g722_and_custom_codec_plugin_interop` verifying G.722 wideband echo against Asterisk/FreeSWITCH and an external custom `L16/16000` codec plugin routed through Kamailio proxy.

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

