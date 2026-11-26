# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.4] - 2026-11-26

### Added
- **Client-Side UDP NAT CRLF Keep-Alive (`bmsip-engine`):**
  - Added [`DEFAULT_UDP_KEEPALIVE_SECS`](crates/bmsip-engine/src/command.rs) (`25 s`), `EngineConfig::udp_keepalive_secs` (`0` disables), and `EngineConfig::with_udp_keepalive_secs(...)`, sending 4-byte RFC 5626 / RFC 3261 §7.5 `\r\n\r\n` keep-alive datagrams to `registrar_addr` after `udp_keepalive_secs` seconds of outbound silence while `Registered` (automatically reset on any outbound SIP send to `registrar_addr` and paused on `Unregistered` / `Suspend`).
  - Updated [`SipTransportDriver::poll_rx`](crates/bmsip-engine/src/transport.rs) on UDP sockets to reply `\r\n` (`RFC5626_KEEPALIVE_PONG`) to inbound `\r\n\r\n` pings and silently absorb CRLF-only keep-alive datagrams without triggering parse errors or warnings.

### Documentation
- Synchronized `Cargo.toml`, `CHANGELOG.md`, `README.md`, `ARCHITECTURE.md`, and `docs/SDK_GUIDE.md` to `0.16.4`.

## [0.16.3] - 2026-11-26

### Fixed
- **Automatic Inbound RTP `ptime` (`2.5`–`120` ms) & Sample-Rate Adaptation (`bmsip-media`, `bmsip-engine`):**
  - Added rate-explicit [`resample_pcm_by_rate`](crates/bmsip-media/src/g722.rs) and [`StreamResampler::resample_by_rate`](crates/bmsip-media/src/g722.rs) plus [`AudioCodecPlugin::decode_to_rate`](crates/bmsip-media/src/plugin.rs), replacing sample-count-based rate inference in [`MediaSession::receive_rtp`](crates/bmsip-media/src/session.rs) so `10 ms` `G.722` packets (`160` samples @ `16 kHz`, e.g., Asterisk 22 `alaw -> g722` transcoding with `use_ptime=no`) are upsampled `3x` to `48 kHz` (`480` samples) instead of being misidentified as `20 ms` @ `8 kHz` (`6x` `-1` octave pitch shift), and resetting `rx_resampler` across sequence gaps, SSRC switches, and mid-call dynamic payload-type changes.
  - Upgraded [`AdaptiveJitterBuffer`](crates/bmsip-media/src/jitter.rs) to reorder arbitrary-duration RTP packets (`5`/`10`/`20`/`30`/`40`/`60`/`120` ms and mid-call `ptime` transitions) in true 16-bit RTP sequence space while assembling exact `20 ms` (`frame_samples`) playout frames via `playout_fifo` and sample-accurate priming/excess-depth thresholds (`queued_frame_samples`), eliminating `50%` excess-depth packet drops on `10 ms` (`100` pkt/s) PBX streams while preserving zero-copy `20 ms` playout.
  - Expanded [`LibOpusCodec::decode_20ms_48khz`](crates/bmsip-engine/src/opus_native.rs) and [`OpusCodecBackend::decode_20ms_8khz`](crates/bmsip-media/src/opus.rs) to decode up to `OPUS_MAX_FRAME_SAMPLES_48KHZ` (`5760` samples = `120 ms` per RFC 6716 §3.2.5) instead of capping at `960` samples (`20 ms`).

### Documentation
- Synchronized `Cargo.toml`, `CHANGELOG.md`, `README.md`, `ARCHITECTURE.md`, and `docs/CODECS_AND_AUDIO.md` to `0.16.3`.

## [0.16.2] - 2026-11-24

### Added
- **Configurable SIP `User-Agent` Header (`bmsip-core`):**
  - Exported `DEFAULT_USER_AGENT` and added `UaConfig::user_agent`, `UaConfig::with_user_agent(...)`, and `UaConfig::effective_user_agent()` in [`dialog/mod.rs`](crates/bmsip-core/src/dialog/mod.rs), stripping CRLF characters and falling back to `bmsip/<version>` when empty.
  - Applied `effective_user_agent()` across outbound `REGISTER`, `INVITE`, `re-INVITE`, `UPDATE`, and `INFO` requests so host softphones can identify themselves in standard `Product/<ver> (bmsip/<ver>)` format.

### Documentation
- Synchronized `Cargo.toml`, `CHANGELOG.md`, `README.md`, `ARCHITECTURE.md`, and `docs/SDK_GUIDE.md` to `0.16.2`.

## [0.16.1] - 2026-11-24

### Fixed
- **Jitter Buffer Underrun Death-Spiral & `50 Hz` Robotic PLC Prevention (`bmsip-media`):**
  - Separated true missing/reordered packets (`!frames.is_empty()`, which advances `next_playout_seq`) from empty-buffer starvation / sender clock skew (`frames.is_empty()`) in [`AdaptiveJitterBuffer::pop`](crates/bmsip-media/src/jitter.rs), holding `next_playout_seq` on empty-buffer slips so slightly late packets are accepted instead of triggering cascading `4×PLC + 2×Buffering` `late_drops` every ~1 s on hardware SIP phones.
  - Replaced repeated 4-frame `50 Hz` waveform cloning on empty-buffer starvation with a single `20 ms` linear taper-to-zero slip frame followed by clean re-priming (`recovering_from_underrun` head crossfade), eliminating metallic/robotic voice modulation and step-to-zero clicks.
  - Preserved `initial_depth_frames` across cold-start `jitter = 0` packets (`SUB_INITIAL_SHRINK_PACKETS = 50`) and added an adaptive `underrun_floor_frames` (`+1` frame per underrun, decaying after `250` consecutive clean pops = `5 s`).

### Documentation
- Synchronized `Cargo.toml`, `CHANGELOG.md`, `README.md`, `ARCHITECTURE.md`, and `docs/CODECS_AND_AUDIO.md` to `0.16.1`.

## [0.16.0] - 2026-11-21

### Added
- **SDP RTCP Attributes & Multiplexing (`bmsip-core`, `bmsip-engine`):**
  - Added `SdpSession::rtcp_port`, `SdpSession::rtcp_ip`, and `SdpSession::rtcp_mux` supporting RFC 3605 `a=rtcp:<port> [IN IP4/IP6 <addr>]` and RFC 5761 `a=rtcp-mux` parsing, formatting, and offer/answer propagation.
  - Wired `resolve_remote_rtcp_addr` and multiplexed RTP/RTCP socket receive demultiplexing into [`engine.rs`](crates/bmsip-engine/src/engine.rs).
- **Delayed SDP Offer Support (`bmsip-core`):**
  - Supported bodyless inbound `INVITE` (RFC 3261 §13.2.1) and bodyless inbound `re-INVITE` (RFC 3261 §14.1): UAS includes the local SDP offer (advertising full `supported_codecs` on `re-INVITE`) in `200 OK` and completes media/SRTP negotiation from the `ACK` SDP answer (terminating cleanly with `BYE` and `Reason: SIP ;cause=488` if the `ACK` lacks a compatible SDP answer).
- **Transaction Keying, Probation & FFI Focus Parity (`bmsip-core`, `bmsip-media`, `bmsip-ffi`):**
  - Added `TransactionId::sent_by` (`TransactionId::client` / `TransactionId::server`, RFC 3261 §17.2.3) and `UserAgent::active_call_ids()`.
  - Added `SeqStatus` (`Accepted`, `Resynced`, `ProbationRejected`) in `bmsip-media` and exported `BmsipClient::set_active_call` ([`bmsip.udl`](crates/bmsip-ffi/src/bmsip.udl)) plus `bmsip_client_set_active_call` ([`bmsip.h`](crates/bmsip-ffi/include/bmsip.h)).

### Fixed
- **Strict `Content-Length`, Deterministic Seed Fallback & Transaction Matching (`bmsip-core`):**
  - Enforced strict RFC 3261 `1*DIGIT` `Content-Length` validation (rejecting leading `+` signs and conflicting duplicate headers while handling unfolded continuations consistently) across both [`framer.rs`](crates/bmsip-core/src/sip/framer.rs) and [`message.rs`](crates/bmsip-core/src/sip/message.rs).
  - Normalized `TransactionId::server` `Via sent-by` and included `sent_by` matching in inbound `CANCEL` handling ([`transaction/mod.rs`](crates/bmsip-core/src/transaction/mod.rs), [`dialog/mod.rs`](crates/bmsip-core/src/dialog/mod.rs)).
  - Added deterministic FNV-1a host/username fallback seeding (`effective_instance_seed`) so distinct `UserAgent` instances on the same port with `instance_seed == 0` generate distinct `Call-ID`, tag, branch, and `cnonce` values.
- **`100rel`, Glare Backoff Retry, `UPDATE` & `Replaces` Edge Cases (`bmsip-core`):**
  - Added RFC 3262 reliable `1xx` retransmissions starting at `T1` up to `64 * T1` (`504 Server Time-out` on PRACK timeout), blocked sending a second reliable `1xx` while one awaits `PRACK`, and validated `RAck` `CSeq` numbers in `on_inbound_prack`.
  - Implemented RFC 3261 §14.1 automatic `491 Request Pending` backoff retry (`2.1–4.0 s` Call-ID owner, `0.1–2.0 s` non-owner, up to `MAX_GLARE_RETRIES = 3`) on outbound `re-INVITE`, returned `491` on inbound `UPDATE` during pending SDP offers, and guarded `send_update` against `local_rtp_port == 0`.
  - Enforced RFC 3891 §3 `Replaces` status codes (`481` for missing/ambiguous or non-UAC-initiated early dialogs, `486 Busy Here` for confirmed dialogs with `;early-only`, and `603 Decline` for terminating/cancelling/terminated dialogs).
- **RFC 3550 Appendix A.1 Sequence & Unencrypted SSRC Probation (`bmsip-media`):**
  - Enforced `MAX_DROPOUT = 3000` / `MAX_MISORDER = 100` 2-packet `bad_seq` resynchronization (resetting `AdaptiveJitterBuffer` on `SeqStatus::Resynced`) in [`rtcp.rs`](crates/bmsip-media/src/rtcp.rs) and required 2 sequential packets before switching SSRC on unencrypted RTP streams in [`session.rs`](crates/bmsip-media/src/session.rs) (authenticated SRTP continues immediate verified SSRC switching).
- **TLS SNI, Timeouts, LRU Maps, IPv6, `Suspend` Sleep & Graceful `Shutdown` (`bmsip-engine`, `bmsip-ffi`):**
  - Fixed RFC 5922 §7.2 per-target TLS SNI/hostname resolution (`peer_tls_hosts`) and bracketed/bare IPv6 `IpAddr` handling in [`tls.rs`](crates/bmsip-engine/src/tls.rs) and [`bmsip-ffi`](crates/bmsip-ffi/src/client.rs).
  - Added `TLS_HANDSHAKE_TIMEOUT` (`10 s`), non-registrar `STREAM_IDLE_TIMEOUT` (`180 s`), `UDP_WARN_MIN_INTERVAL` (`5 s`) warning rate limiting, IPv6 socket probing in [`transport.rs`](crates/bmsip-engine/src/transport.rs), LRU eviction on engine routing/DNS tables (`60 s` positive / `5 s` negative DNS TTL), best-effort `BYE`/`CANCEL` + `REGISTER Expires: 0` flush on `EngineCommand::Shutdown`, and full `Condvar::wait_while` worker sleep while `Suspended`.

### Documentation
- Synchronized `Cargo.toml`, `CHANGELOG.md`, `README.md`, `ARCHITECTURE.md`, `docs/SDK_GUIDE.md`, `docs/CODECS_AND_AUDIO.md`, and `docs/CLI_AND_TESTING.md` to `0.16.0`.

## [0.15.1] - 2026-11-21

### Fixed
- **Panic Isolation Across Thread & C-API Boundaries (`bmsip-ffi`, `bmsip-engine`):**
  - Wrapped every `#[no_mangle] pub unsafe extern "C" fn` entrypoint in [`c_api.rs`](crates/bmsip-ffi/src/c_api.rs) with `std::panic::catch_unwind` (`ffi_guard_*`), guaranteeing Rust panics never unwind across FFI boundaries into C/C++/Swift/Kotlin hosts.
  - Wrapped `run_worker` inside `SipEngine::spawn` with `catch_unwind`; if the worker thread ever panics, it safely emits `EngineEvent::Warning` + `EngineEvent::Stopped`, wakes receivers (recovering cleanly from poisoned event mutexes), and marks the command channel closed so subsequent `SipEngine::send_command` calls return `Err(EngineError::ChannelClosed)` cleanly.
- **Debug-Safe Arithmetic & Timer Clamping (`bmsip-core`, `bmsip-media`):**
  - Replaced potential overflowing `cycles + seq` / `+ 1` arithmetic in `RtpStreamStats` ([rtcp.rs](crates/bmsip-media/src/rtcp.rs)) and `AdaptiveJitterBuffer` ([jitter.rs](crates/bmsip-media/src/jitter.rs)) with `wrapping_*` / `saturating_*` operations.
  - Clamped `RfcTimers` bounds (`safe_t1` `1 ms..=60 s`, `safe_t2` up to `300 s`) and switched `timer_b/f/h/j/l` and UAS `2xx` ACK deadlines in [transaction/mod.rs](crates/bmsip-core/src/transaction/mod.rs) and [dialog/mod.rs](crates/bmsip-core/src/dialog/mod.rs) to `.saturating_mul(64)`.

### Documentation
- Finalized [ARCHITECTURE.md](ARCHITECTURE.md) (`v0.15.0`/`v0.15.1` release history, removed resolved `TODO` markers and documented explicit PBX/SBC deployment scope), [README.md](README.md) (`0.15.1`), [docs/SDK_GUIDE.md](docs/SDK_GUIDE.md) (Production Deployment Checklist), [docs/CODECS_AND_AUDIO.md](docs/CODECS_AND_AUDIO.md) (exact `3/4` PLC decay and `32`-sample crossfade parameters), and [docs/CLI_AND_TESTING.md](docs/CLI_AND_TESTING.md) (current integration suite coverage).

## [0.15.0] - 2026-11-21

### Added
- **RFC 3966 `tel:` URI Support & Routing (`bmsip-core`, `bmsip-engine`):**
  - Added `SipScheme::Tel`, RFC 3966 `tel:<subscriber>[;params]` parsing/formatting, `NameAddr` / `CallerIdentity` `tel:` support, and automatic fallback routing to `registrar_addr` in `WorkerCtx::resolve_sip_destination`.
- **RTCP `SDES` (`CNAME`), `DLSR`, & C ABI Diagnostics (`bmsip-media`, `bmsip-engine`, `bmsip-ffi`):**
  - Added `RtcpPacket::Sdes` (`PT=202`, `SdesChunk`, `SdesItem`, `SDES_CNAME`), compound `RR + SDES(CNAME)` emission in `MediaSession::build_rtcp_receiver_report*`, and monotonic `DLSR` calculation via `receive_rtcp_at` / `build_rtcp_receiver_report_at`.
  - Exported `bmsip_client_local_sip_addr` and `bmsip_client_request_telemetry` in [`bmsip.h`](crates/bmsip-ffi/include/bmsip.h) and `bmsip-ffi::c_api`.

### Fixed
- **SIP Parser, Framing & Digest Auth (`bmsip-core`, `bmsip-engine`):**
  - Updated `split_unquoted` to respect `<...>` angle brackets outside quotes; tolerated LWS around `/` and `:` in `Via` and unquoted quoted parameter values; added `ReplacesHeader::parse_header_value`; scanned all `P-Asserted-Identity`/`Remote-Party-ID` items individually in `CallerIdentity::from_headers`.
  - Guarded `StreamFrame::KeepAlivePong` behind outstanding `note_keepalive_ping_sent()` tracking, stripped leading `\r\n` padding per RFC 3261 §7.5, handled unfolded continuation lines in `parse_stream_content_length`, and cleared only the bad frame on stream frame errors without discarding earlier queued frames.
  - Enforced `qop=auth` for `-sess` Digest algorithms, ranked `SHA-256` / `SHA-256-sess` ahead of `MD5` / `MD5-sess` across all challenge headers, and retained stacked `Proxy-Authorization` + `Authorization` across `407 -> 401` retries and `2xx` `ACK` requests.
- **Transactions, Dialog Timers & Session-Timers Interop (`bmsip-core`):**
  - Bounded `ServerNonInviteTransaction` `Trying`/`Proceeding` lifetime to `64 * T1` (`lifetime_timer`), and validated mandatory `From`, `To`, `Call-ID`, `CSeq`, and `CSeq` method match in `TransactionManager::receive_message` before allocating server transactions (sending stateless `400 Bad Request` on invalid non-`ACK` requests).
  - Enforced `To-tag` on all non-`100` UAS responses; sent `487 Request Terminated` on `inbound_invite_tx` on early-dialog `BYE`; added `cancel_deadline` (`64 * T1`) on `Cancelling` calls; added `PendingReInviteRollback` (`local_sdp`, `sdp_version`, `local_hold`, `local_rtp_port`) restored on `re-INVITE` rejection/timeout.
  - Isolated per-call `min_se_secs` on `422 Session Interval Too Small`, selected `refresher=uas` without `Require: timer` when UAC lacks `Supported: timer` (adding `Require: timer` for `refresher=uac` per RFC 4028 §9), cleared stale session timers when `Session-Expires` is absent on `2xx`, added `405`/`501` session-refresh `UPDATE` fallback to `re-INVITE`, and handled `REGISTER` `423 Interval Too Brief` (capped at `86400` s) plus `expires=0` unregistration.
- **Media Stats, DTMF, CN, Handover & FFI Bounds (`bmsip-media`, `bmsip-engine`, `bmsip-ffi`):**
  - Fixed modular 32-bit RTP timestamp wraparound in `RtpStreamStats::record_packet`, isolated DTMF/CN packets from jitter calculations via `record_non_audio_packet`, enforced strictly monotonic event timestamps in `DtmfSender` with `(ts, digit)` deduplication in `DtmfDetector`, and advanced RTP timestamp + `M=1` resume marker across CN/DTMF pauses.
  - Fixed `SipTransportDriver::rebind` to release previous sockets before rebinding (allowing same-port handovers such as `5060`), rebound `pending_rtp_sockets` and early `Ringing` calls during `NetworkChanged`, attempted up to 16 binds for even/odd RTP/RTCP ports, capped `SharedState` event queue depth (`4096`) and `pump_rtp_rx` packets per tick (`128`), and validated C-API PCM frame lengths against the configured sample rate prior to slice construction.

## [0.14.1] - 2026-11-21

### Fixed
- **SIP URI & Dialog/Transaction State Machines (`bmsip-core`):**
  - Updated `SipUri::parse` to treat `@` as the userinfo delimiter only when it precedes `?` or when no `=` appears between `?` and `@`, preserving userinfo `;` parameters (e.g., `sip:alice;day=tue@atlanta.com`, `sip:5551234;phone-context=+1-212@example.com;user=phone`) while keeping `@` inside `?` URI headers (e.g., `?Replaces=cid@10.0.0.1`) intact.
  - Added RFC 6026 `IstState::Accepted` + `Timer L` (`64 * T1`) in `ServerInviteTransaction` to absorb retransmitted `INVITE`s without spawning duplicate transactions while routing `ACK` for `2xx` to `TransactionEvent::AckFor2xx`, and surfaced `2xx` arriving in `IctState::Completed` as `TransactionEvent::Unmatched2xx`.
  - Fixed `UserAgent::hangup_with_reason` to transmit `CANCEL` immediately once any `1xx` (including `100 Trying`, tracked via `received_provisional`) has arrived; handled bodyless `200 OK` responses on `re-INVITE` and early-media `183` dialogs (or `ACK`+`BYE` when no SDP answer was ever supplied); transmitted `BYE` on `200 OK` `ACK` timeout per RFC 3261 §13.3.1.4; verified `CSeq` and `To-tag` in `on_ack_for_2xx`; and implemented `on_unmatched_2xx` to `ACK`+`BYE` forked/unmatched `2xx` legs without disturbing the primary call.
- **Wideband G.722 QMF, Jitter Buffer & Wire Opus Safety (`bmsip-media`, `bmsip-engine`):**
  - Fixed ITU-T G.722 QMF high-band filter signs (`(accb - acca) >> 14` on encode, `rx[22] = rlow + rhigh` / `rx[23] = rlow - rhigh` on decode) and 16-bit PCM scaling (`>> 11` synthesis shift), resolving high-band polarity & 6 dB level mismatch against `spandsp` / Asterisk.
  - Removed the `BuiltInOpusCodec` placeholder from `CodecRegistry::with_builtin_codecs()` and prevented `SipEngine` from falling back to `BuiltInOpusCodec` on the wire (stripping `opus` from `supported_codecs` at startup if native `LibOpusCodec` fails to initialize).
  - Updated `AdaptiveJitterBuffer` with `mark_non_audio_seq` so RFC 4733 DTMF sequence numbers skip playout cleanly without triggering false PLC frames, and added smooth excess-depth shrinking (`> target_depth_frames + 2`) to recover playout latency after jitter bursts.
- **Testbed Hardening (`.devcontainer/`):**
  - Enabled FreeSWITCH `media_mix_inbound_outbound_codecs` + `nolocal:absolute_codec_string` for live `G.722 <-> Opus` transcoding verification and enforced `max_contacts=1` (`remove_existing=yes`) in Asterisk `pjsip.conf` to prevent stale test contacts.
- **TLS Plaintext Draining, RTP Source Latching & Multi-Call Focus (`bmsip-engine`, `bmsip-ffi`):**
  - Fixed `StreamPeer::drive_io` to drain `rustls` plaintext inside the `read_tls` loop (preventing >16 KiB stalls) and always drain pending plaintext and `SipStreamFramer` frames on clean TCP/TLS EOF.
  - Added unencrypted RTP/RTCP source IP validation with symmetric port latching (`latched_rtp_source` / `latched_rtcp_source`, reset on SDP updates and `NetworkChanged`), relying on RFC 3711 HMAC-SHA1 authentication when SRTP is active.
  - Added `EngineCommand::SetActiveCall` and dynamic non-held primary media focus selection so multi-call hold / attended transfer workflows never mute the active call.
  - Added `EngineEventReceiver` so `BmsipClient::poll_event` no longer holds the engine mutex while waiting, preventing starvation of concurrent `dial`/`hangup`/`shutdown` calls, and exposed `BmsipClient::with_sample_rate`, `with_transport`, and `with_security` aliases matching `bmsip.udl`.

## [0.14.0] - 2026-11-21

### Security & Hardening
- **Cryptographically Secure SDES Key Generation (`bmsip-core`, `bmsip-engine`):**
  - Added pure-Rust `hmac_sha256` (RFC 2104 / RFC 4231) and `SdesCryptoAttr::derive_from_secret` in `bmsip-core`, backed by a dedicated 256-bit `UaConfig::crypto_seed: [u8; 32]` populated from OS CSPRNG (`ring::rand::SystemRandom`) in `SipEngine::spawn` (strictly isolated from `instance_seed` / `Call-ID` / `From` tags).
  - Enforced RFC 4568 §8 by default: `SrtpMode::SdesRequired` over unencrypted `UDP`/`TCP` is rejected with `EngineError::InvalidConfig` / `SipError::TransactionError` unless `UaConfig::allow_insecure_cleartext_sdes` is explicitly opted in for isolated lab testing, and `SdesOptional` suppresses cleartext `a=crypto:` advertisement on non-TLS transports.
  - Added `Drop` key zeroization across `SdesCryptoAttr`, `NegotiatedSrtp`, `UserAgent`, `SrtpKeyMaterial`, `DerivedSrtpKeys`, `SrtpContext`, and `MediaSession`.
- **Per-SSRC SRTP State, Lifetime Limits & Selective Re-Keying (`bmsip-media`, `bmsip-core`, `bmsip-engine`):**
  - Refactored `SrtpContext` to track `(roc, highest_seq, rtp_replay_window, srtcp_index, rtcp_replay_window)` per authenticated SSRC (bounded LRU table of 16 SSRCs; unseen SSRCs are allocated strictly after HMAC-SHA1 verification succeeds), preventing mid-call PBX SSRC switches (transfers / MOH bridges) from desynchronizing ROC and resisting forged-SSRC floods.
  - Enforced RFC 3711 §9.2 packet limits ($2^{48}-1$ SRTP packets / $2^{31}-1$ SRTCP packets) returning `MediaError::SrtpKeyExpired` instead of wrapping IV counters.
  - Rejected unsupported RFC 4568 `MKI` (`<value>:<length>`) parameters in `SdesCryptoAttr::parse` so SDP parsing automatically falls back to non-MKI lines, removed the hardcoded fallback key in `negotiate_offer_answer_with_srtp`, and wired `MediaSession::update_srtp_keys` into both `activate_or_update_media` (`183 -> 200 OK` forking) and `CallMediaUpdated` (`re-INVITE` / `UPDATE` key rotation) while preserving unchanged direction ROC state on Hold.
- **Non-Blocking TCP Connect & Registrar-Protected Peer Pool (`bmsip-engine`):**
  - Replaced synchronous `TcpStream::connect_timeout` in `SipTransportDriver` with non-blocking background connect channels (`PendingConnect`) so unreachable TCP/TLS peers never stall the 20 ms RTP media worker loop, and replaced arbitrary `HashMap` eviction with registrar-protected LRU eviction.
  - Added bounded DNS cache for `Route` header hostname resolution in `WorkerCtx`.

### Changed (Breaking Pre-1.0 API)
- **Isolated Experimental DTLS-SRTP (`bmsip-core`, `bmsip-engine`, `bmsip-ffi`, `bmsip-cli`):**
  - Removed `SrtpMode::DtlsSrtp`, `NegotiatedSrtp::Dtls`, and `FfiSrtpMode::DtlsSrtp` (`bmsip.udl` / `--srtp dtls`) from public APIs so production surfaces expose strictly standards-compliant, Asterisk/FreeSWITCH-verified SDES-SRTP (`Disabled`, `SdesOptional`, `SdesRequired`). Incoming `UDP/TLS/RTP/SAVP(F)` offers are cleanly rejected with `488 Not Acceptable Here`.
  - Gated `bmsip_engine::dtls` and `bmsip_core::sdp::{DtlsFingerprint, DtlsSetupRole}` behind the off-by-default `experimental-dtls` Cargo feature for future RFC 6347 DTLS 1.2 integration.

## [0.13.0] - 2026-11-21

### Added
- **SRTP & SRTCP (RFC 3711) with SDES (RFC 4568) & DTLS-SRTP (RFC 5763 / RFC 5764) (`bmsip-core`, `bmsip-media`, `bmsip-engine`, `bmsip-ffi`, `bmsip-cli`):**
  - Added SDP media profiles (`SdpMediaProfile`: `RTP/AVP`, `RTP/SAVP`, `UDP/TLS/RTP/SAVP`), SRTP suites (`SrtpSuite`: `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32`), RFC 4568 SDES `a=crypto:` parser/generator (`SdesCryptoAttr` with pure-Rust Base64 and deterministic SHA-256 seed derivation), RFC 4145/5763 `a=setup:` (`DtlsSetupRole`), RFC 4572/5763 `a=fingerprint:sha-256` (`DtlsFingerprint::sha256_from_der`), `SrtpMode` (`Disabled`, `SdesOptional`, `SdesRequired`, `DtlsSrtp`), and `negotiate_offer_answer_with_srtp` / `resolve_outbound_answer_srtp` in `bmsip-core::sdp`.
  - Implemented 100% pure Safe Rust (`#![forbid(unsafe_code)]`, zero external crate dependencies) RFC 3711 SRTP & SRTCP engine (`bmsip_media::srtp`: FIPS 197 AES-128 block & counter-mode cipher, FIPS 180-4 SHA-1, RFC 2104 HMAC-SHA1, RFC 3711 §4.3.1 KDF verified against RFC 3711 Appendix B.3 test vectors, 48-bit ROC estimation, 64-packet sliding replay window, constant-time tag verification, and RFC 5764 §4.2 60-byte DTLS-SRTP exporter key splitter) wired directly into `MediaSession`.
  - Implemented pure-Rust DTLS-SRTP media handshake (`bmsip_engine::dtls`: `DtlsIdentity`, `DtlsSrtpSession`, RFC 5764 §5.1.2 UDP media port demultiplexing `20..=63` vs `128..=191`, mutual X.509 certificate SHA-256 fingerprint verification against SDP `a=fingerprint:`, and RFC 5705 `"EXTRACTOR-dtls_srtp"` key derivation) in `bmsip-engine`.
  - Exposed `FfiSrtpMode` (`Disabled`, `SdesOptional`, `SdesRequired`, `DtlsSrtp`) and `BmsipClient::new_with_security` (`[Name=with_security]` in `bmsip.udl`), C99 `bmsip_client_new_secure` in `include/bmsip.h`, and `--srtp off|optional|sdes|dtls` in `bmsip-cli call` and `bmsip-cli listen`.
  - Enabled `asterisk-srtp` (`res_srtp.so`) and dedicated SDES-SRTP endpoint `1004` (`media_encryption=sdes`) in the Docker Compose `asterisk` lab container, verified with live Asterisk TLS + SDES-SRTP Echo calls and P2P DTLS-SRTP calls (including MITM fingerprint mismatch rejection).

## [0.12.0] - 2026-11-21

### Added
- **SIP over TCP & TLS 1.2–1.3 (`rustls`) Transport (`bmsip-core`, `bmsip-engine`, `bmsip-ffi`, `bmsip-cli`):**
  - Added Sans-I/O `SipTransport` (`Udp`, `Tcp`, `Tls`), `SipStreamFramer` (RFC 3261 §18.3 mandatory `Content-Length` byte-stream framing with 64 KiB Slowloris/OOM guard), `StreamWriteQueue`, and RFC 5626 §4.4.1 `\r\n\r\n` / `\r\n` keep-alive frame handling in `bmsip-core::sip::framer`.
  - Updated `TransactionManager` (RFC 3261 §17) to automatically disable unreliable retransmission timers (`Timer A`, `Timer E`, `Timer G`) and collapse absorb timers (`Timer D`, `Timer I`, `Timer K`, `Timer J` = `0`) whenever the top `Via` transport is `TCP` or `TLS`.
  - Added `UaConfig::transport` / `UaConfig::with_transport` and `UserAgent::transport()` emitting matching `Via` protocol (`UDP`/`TCP`/`TLS`) and `Contact` `;transport=` parameters across all SIP requests.
  - Added pure-Rust `rustls` 0.23 (`ring`, zero OpenSSL C dependency) TLS configuration (`TlsConfig`: WebPKI roots, custom `ca_cert_pem`, `server_name` SNI override, mTLS `client_cert_pem`/`client_key_pem`, inbound direct-peer `server_cert_pem`/`server_key_pem`, and lab-only `accept_invalid_certs`) plus `EngineConfig::with_tls_config`.
  - Implemented non-blocking `SipTransportDriver` in `bmsip-engine` supporting UDP, TCP, and TLS 1.2–1.3 without stalling the 20 ms RTP loop, with RFC 5923 in-dialog connection reuse (NAT-safe & pure-client friendly), periodic RFC 5626 CRLF keep-alive pings/pongs, and immediate stale socket teardown on `EngineCommand::NetworkChanged`.
  - Exposed `FfiTransport` (`Udp`, `Tcp`, `Tls`) and `BmsipClient::new_with_transport` (`[Name=with_transport]` in `bmsip.udl`), plus C99 `bmsip_client_new_transport` in `include/bmsip.h`.
  - Added `--transport udp|tcp|tls`, `--tls-ca <path>`, `--tls-server-name <name>`, and `--tls-insecure` flags to `bmsip-cli call` and `bmsip-cli listen`.
  - Enabled `transport-tcp` (`5060/tcp`) and `transport-tls` (`5061/tls` with generated SAN cert) on the Docker Compose `asterisk` lab container and added live Asterisk TCP/TLS, FreeSWITCH TCP, and `rcgen` P2P verified-CA + mTLS + untrusted-CA rejection integration tests.

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

