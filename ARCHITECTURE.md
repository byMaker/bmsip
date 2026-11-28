# bmsip Architecture Specification

`bmsip` is an embeddable, cross-platform SIP library written in Rust targeting **Linux**, **iOS**, and **Android**. Its architecture eliminates the systemic pain points of legacy C/C++ SIP stacks through strict layer isolation, Sans-I/O determinism, and explicit mobile lifecycle modeling.

---

## 1. Workspace Crate DAG & Layer Contracts

```text
bmsip-cli  ──┐
             ├──► bmsip-engine ──► bmsip-media ──► bmsip-core
bmsip-ffi  ──┘                 └─────────────────► bmsip-core
```

| Crate | Scope | Hard Invariants |
|---|---|---|
| `bmsip-core` | SIP message parser/serializer, URI/header types, SDP offer/answer, Digest Auth, RFC 3261 transactions, dialogs, account registration state | `#![forbid(unsafe_code)]`; empty `[dependencies]`; zero `std::net`, `std::thread`, `std::fs`, `Instant::now()`, `SystemTime::now()`, or async runtimes |
| `bmsip-media` | RTP/RTCP framing, RFC 3711 SRTP/SRTCP (`AES_CM_128_HMAC_SHA1_80`/`_32`), DTMF (RFC 4733), adaptive jitter buffer, G.711/G.722/Opus codecs, universal `CodecRegistry` plugin API, 20 ms PCM frame pipeline | `#![forbid(unsafe_code)]`; zero direct OS audio device calls (ALSA, PipeWire, CoreAudio, Oboe) |
| `bmsip-engine` | Non-blocking UDP/TCP/TLS (`rustls`) socket loop, OS CSPRNG SDES-SRTP media security, monotonic timer driver, `Command`/`Event` queues, `AudioPort` trait, call flight recorder | Zero global singletons (`static mut`); zero user callbacks invoked under held locks; multi-instance safe |
| `bmsip-ffi` | Public cross-platform SDK boundary (UniFFI for Swift/Kotlin + C-API header for Linux) | Thin translation layer over `bmsip-engine` `Command`/`Event` model |
| `bmsip-cli` | Linux CLI SIP endpoint and automated integration test runner | Consumes only `bmsip-engine` public API |

---

## 2. Sans-I/O Protocol Core Contract

```text
  External World (UDP/TCP sockets, monotonic clock, UI commands)
          │                               ▲
          │ raw bytes / Instant / Cmd     │ outbound bytes / Event / next_timeout
          ▼                               │
  ┌───────────────────────────────────────────────┐
  │                  bmsip-core                   │
  │  • sip::SipMessage (RFC 3261 + compact hdrs)  │
  │  • sdp::SdpSession (RFC 4566 / RFC 3264)      │
  │  • auth::DigestChallenge (RFC 2617 / 7616)    │
  │  • transaction::TransactionManager (Sec 17)   │
  │  • sim::VirtualNetwork (lossy UDP harness)    │
  └───────────────────────────────────────────────┘
```

### Supported RFC Matrix (Current & Planned)

| Spec | Scope | Status |
|---|---|---|
| RFC 3261 | SIP/2.0 syntax, compact headers, folding, client/server transactions (ICT, NICT, IST, NIST) | Implemented (`v0.1.0`) |
| RFC 3581 | `Via` `rport` symmetric response routing parameter | Implemented (`v0.1.0`) |
| RFC 4566 / 3264 | SDP audio parsing/generation and Offer/Answer negotiation | Implemented (`v0.1.0`) |
| RFC 2617 / 7616 | Digest authentication (`MD5`, `MD5-sess`, `SHA-256`, `SHA-256-sess`, `qop=auth`) | Implemented (`v0.1.0`) |
| RFC 3261 Sec 12–16 | Dialogs, `REGISTER` refresh, `INVITE`/`CANCEL`/`BYE`/`re-INVITE`, delayed SDP offer, `491` glare backoff retry | Implemented (`v0.2.0`, hardened `v0.16.0`) |
| RFC 3550 / 4733 / 3605 / 5761 | RTP/RTCP media transport (compound `RR + SDES CNAME`, `DLSR`, Appendix A.1 seq/SSRC probation, modular jitter wrap), `a=rtcp:`/`a=rtcp-mux`, even/odd RTP/RTCP port pairing, DTMF (`telephone-event` + monotonic same-tick TS) | Implemented (`v0.3.0`, hardened `v0.16.0`) |
| RFC 6716 / 7587 | Native `libopus` 48 kHz VoIP codec + TOC/`fmtp` + mic DSP conditioning | Implemented (`v0.7.0`) |
| ITU-T G.722 / RFC 3551 §4.5.2 | Pure-Rust 16 kHz wideband G.722 codec (PT 9) + universal pluggable `AudioCodecPlugin` / `CodecRegistry` | Implemented (`v0.9.0`, QMF fixed `v0.14.1`) |
| RFC 6337 / 3311 / 3262 | Call Hold/Resume (`a=sendonly`/`inactive`/`sendrecv`) with `re-INVITE` rollback, early/in-dialog `UPDATE` (`491` glare), reliable `1xx` / `PRACK` (`100rel` retransmits, `RAck` check, `504` timeout) | Implemented (`v0.10.0`, hardened `v0.16.0`) |
| RFC 3515 / 3891 | Blind (`REFER` + `NOTIFY message/sipfrag`) and Attended (`Replaces`, strict `481`/`486`/`603` dialog validation) Call Transfer | Implemented (`v0.10.0`, hardened `v0.16.0`) |
| RFC 3966 | `tel:` URI parsing & `CallerIdentity` / registrar routing fallback | Implemented (`v0.15.0`) |
| RFC 4028 / 3326 / 3323 / 3325 | `Session-Timers` (`Session-Expires`/`Min-SE` per-call/`Require: timer`/`405` fallback), `Reason` header, `P-Asserted-Identity` & `Privacy` | Implemented (`v0.10.0`, hardened `v0.15.0`) |
| RFC 3960 / 2976 / 3389 | Early media (`183`/`180` SDP), SIP `INFO` DTMF (`application/dtmf-relay`), Comfort Noise (`CN` PT 13) | Implemented (`v0.11.0`) |
| RFC 3261 §18 / 5626 / 5922 / 5923 | SIP over UDP, TCP & TLS 1.2–1.3 (`rustls`, mTLS), `Content-Length` stream framing, `25 s` CRLF NAT keep-alive (UDP/TCP/TLS), connection reuse | Implemented (`v0.12.0`, UDP added `v0.16.4`) |
| RFC 3711 / 4568 | Production-hardened SRTP & SRTCP (`AES_CM_128_HMAC_SHA1_80`/`_32`), per-SSRC ROC/replay, RFC 3711 §9.2 key lifetime limits, key zeroization, OS CSPRNG SDES (`a=crypto:`) enforced over TLS | Implemented (`v0.13.0`, hardened `v0.14.0`) |
| RFC 3842 / 6665 | Voicemail Message Waiting Indication (`Event: message-summary`, `application/simple-message-summary`, solicited `SUBSCRIBE`/`NOTIFY` + unsolicited `NOTIFY`, `MwiMode::{Disabled, UnsolicitedOnly, Solicited, Auto}`) | Implemented (`v0.17.0`) |

---

## 3. Concurrency, Mobile Lifecycle & Diagnostics

1. **Lock-Safe Command/Event Runtime:** Applications push `Command` values into `bmsip-engine` and drain typed `Event` values. Internal locks never span application callbacks, eliminating re-entrant callback deadlocks common in PJSIP.
2. **Mobile Lifecycle First-Class Primitives:**
   - `NetworkChanged`: triggers socket rebind, immediate `REGISTER` refresh, and media `re-INVITE` with updated SDP connection address.
   - `Suspend` / `Resume`: supports PushKit (iOS) / FCM (Android) background wakeups without tearing down state structures.
3. **Audio PCM Bridge (`AudioPort`):** `bmsip-media` exchanges 20 ms PCM buffers with the host platform so native audio stacks (`VoiceProcessingIO` AudioUnit on iOS, `Oboe`/`VOICE_COMMUNICATION` on Android, PipeWire/ALSA on Linux) provide hardware AEC and Bluetooth routing.
4. **Per-Call Flight Recorder ("Black Box"):** Ring buffer capturing timestamped SIP wire summaries, FSM state transitions, and RTP jitter/loss counters exportable as structured JSON.

---

## 4. Formal API & Schema Strategy

Because `bmsip` is an embeddable native library rather than an HTTP service, OpenAPI is not applicable to its runtime interface. Instead:
- **Public SDK Boundary (`bmsip-ffi`):** Defined via a single authoritative **UniFFI `.udl` IDL contract** (plus generated `cbindgen` C header), guaranteeing identical typed enums, structs, error variants, and `Command`/`Event` models across Swift (iOS), Kotlin (Android), and C/C++ (Linux).
- **Internal Crate Contracts:** Every module header carries machine-readable contract tags (`MODULE_CONTRACT`, `INVARIANTS`, `RFC_REFS`) enforced alongside compiler checks (`#![forbid(unsafe_code)]`, clippy `-D warnings`).

---

## 5. Versioning Policy & Staged Roadmap

All workspace crates share a synchronized **SemVer 2.0.0** version in root `Cargo.toml` (`[workspace.package]`), recorded in [CHANGELOG.md](./CHANGELOG.md).

- **`0.1.0` — Stage 1:** Workspace skeleton + `bmsip-core` Sans-I/O SIP/SDP parsers, MD5/SHA-256 Digest Auth, RFC 3261 transactions, and deterministic lossy network simulator.
- **`0.2.0` — Stage 2:** Dialog & registration FSMs (`REGISTER`, `INVITE`, `CANCEL`, `BYE`, `re-INVITE`) + live Asterisk Docker Compose integration suite.
- **`0.3.0` — Stage 3:** `bmsip-media` RTP/RTCP, adaptive jitter buffer, G.711 (`PCMU`/`PCMA`), DTMF (RFC 4733), WAV test call verification.
- **`0.4.0` — Stage 4:** `bmsip-engine` UDP/TCP transport + `bmsip-cli` Linux softphone + per-call diagnostic flight recorder.
- **`0.5.0` — Stage 5:** `bmsip-ffi` UniFFI `.udl` contract (Swift/Kotlin/C) + Opus codec integration.
- **`0.6.0` — Stage 6:** Linux live audio (`--live-audio` & `listen` in `bmsip-cli`) + reference iOS/Android/C platform adapters (`bindings/`).
- **`0.7.0` — Stage 7:** Native `libopus` 48 kHz VoIP backend (`LibOpusCodec`), Asterisk Opus negotiation, soft noise-gate/gain mic DSP (`condition_mic_frame`), and glitch-free 48 kHz live Linux audio pre-roll buffering.
- **`0.8.0` — Stage 8:** RFC 3261 `Record-Route` response copying, multi-server Docker testbed (**Asterisk** `PJSIP` + **FreeSWITCH** `Sofia-SIP` + **Kamailio** `SIP Proxy`), unified `bmsip-cli interop` benchmark, and DSP audio analyzer / jitter PLC crossfade.
- **`0.9.0` — Stage 9:** Universal pluggable audio codec registry (`AudioCodecPlugin`, `AudioCodecFactory`, `CodecRegistry`, `EngineConfig::register_custom_codec`) and built-in pure-Rust **ITU-T G.722** (16 kHz wideband HD Voice, PT `9`) verified across Asterisk, FreeSWITCH (`mod_spandsp`), and Kamailio.
- **`0.9.1` — Stage 9 Polish:** Symmetric low-pass FIR downsamplers + stateful `StreamResampler`, zero-copy `RtpPacketRef` hot path, `Condvar` instant command wakeup & adaptive idle polling, live companion RTCP (`rtp_port + 1`) reporting, and deterministic parser mutation fuzz tests.
- **`0.9.2` — Protocol, Media & FFI Hardening:** RFC 3261 `491` glare / `remote_cseq` / `stale=true` / multi-`Contact` / `488` fixes, restart-safe `instance_seed`, 48 kHz-scaled RFC 4733 DTMF durations, mid-call SSRC reset & RTCP interval loss tracking, symmetric/Route SIP routing, RTP rebind on `NetworkChanged`, deterministic multi-call focus, bounded WAV recording, and native `8`/`16`/`48` kHz FFI/C99 HD audio bridges.
- **`0.10.0` — Stage 10:** Core Call Control (Hold/Resume via `a=sendonly`/`inactive`/`sendrecv`, Blind `REFER`/`NOTIFY` & Attended `Replaces` transfer, early/in-dialog `UPDATE`, `PRACK`/`100rel`, `Session-Timers` with `422` auto-retry and `UPDATE` refresh, `Reason`, and `P-Asserted-Identity`/`Privacy`) across `bmsip-core`, `bmsip-engine`, `bmsip-ffi` (UniFFI + C99), and `bmsip-cli`.
- **`0.11.0` — Stage 11:** Early Media (`183`/`180` SDP) RTP activation before `200 OK`, Legacy SIP `INFO` DTMF (`application/dtmf-relay`, RFC 2976) with `--dtmf-mode rfc4733|info`, and RFC 3389 Comfort Noise (`CN` PT 13) SID synthesis across `bmsip-core`, `bmsip-media`, `bmsip-engine`, `bmsip-ffi`, and `bmsip-cli`.
- **`0.12.0` — Stage 12:** SIP over TCP and TLS 1.2–1.3 (`rustls`, mTLS, RFC 5922) with Sans-I/O `SipStreamFramer` (RFC 3261 §18.3), RFC 3261 §17 reliable-transport transaction timers, RFC 5626 CRLF keep-alive, and RFC 5923 connection reuse across all crates and the Docker Compose lab.
- **`0.13.0` — Stage 13:** Pure-Rust RFC 3711 SRTP & SRTCP (`AES_CM_128_HMAC_SHA1_80` / `_32`) and RFC 4568 SDES (`RTP/SAVP`, `a=crypto:`) across `bmsip-core`, `bmsip-media`, `bmsip-engine`, `bmsip-ffi`, and `bmsip-cli`.
- **`0.14.0` — Security & Production Hardening:** 256-bit OS CSPRNG (`ring::rand::SystemRandom`) + HMAC-SHA256 SDES key derivation (`UaConfig::crypto_seed`), per-SSRC SRTP ROC/replay state (authenticated before mutation), RFC 3711 §9.2 `SrtpKeyExpired` lifetime limits, key zeroization on `Drop`, RFC 4568 §8 TLS enforcement for SDES, MKI rejection, `re-INVITE`/`183->200 OK` selective SRTP re-keying, non-blocking outbound TCP connect with registrar-protected LRU peer eviction, and isolation of experimental DTLS-SRTP scaffolding behind the off-by-default `experimental-dtls` Cargo feature (public API exposes strictly standards-compliant SDES-SRTP).
- **`0.14.1` — P0 Protocol, Media & Concurrency Bugfixes:** RFC 3261 `SipUri::parse` userinfo `;` params vs `?Replaces=` headers, RFC 6026 `IstState::Accepted` + `Timer L`, immediate `CANCEL` after `100 Trying`, bodyless `200 OK` dialog transitions, `BYE` on `200 OK` `ACK` timeout, forked `2xx` `ACK+BYE`, ITU-T G.722 QMF high-band polarity & 16-bit scaling fix (`spandsp`/Opus transcoded interop), removal of `BuiltInOpusCodec` wire fallback, DTMF sequence skipping + smooth excess-depth shrinking in `AdaptiveJitterBuffer`, `rustls` >16 KiB plaintext draining + EOF deframing, RTP/RTCP source IP validation with symmetric port latching, `EngineCommand::SetActiveCall` + non-held call audio focus, and lock-free `EngineEventReceiver` for `BmsipClient::poll_event`.
- **`0.15.0` — P1 SIP/RTP Interop, Timers, `tel:` URI & FFI Hardening:** RFC 3966 `tel:` URI support + registrar fallback routing, `Via` LWS/quoted-param & raw `Replaces` header parsing, RFC 5626 `KeepAlivePong` guard, `SHA-256` challenge preference + `407 -> 401` stacked Digest auth + `ACK` credentials, NIST `64 * T1` lifetime + mandatory header `400` validation, `To-tag` on all non-`100` UAS responses, early `BYE` `487`, `CANCEL` `64 * T1` deadline, `PendingReInviteRollback`, per-call `Min-SE` / `Require: timer` / `405` `UPDATE -> re-INVITE` fallback, `REGISTER 423` & `expires=0`, modular 32-bit RTCP jitter wrap + `DLSR` + compound `RR + SDES(CNAME)`, monotonic same-tick DTMF timestamps & `(ts, digit)` deduplication, same-port `NetworkChanged` socket rebind + `pending_rtp_sockets`, even/odd RTP/RTCP allocation, bounded queues/loops, C-API PCM bounds checks, and `bmsip_client_local_sip_addr` / `bmsip_client_request_telemetry`.
- **`0.15.1` — Production FFI/Worker Panic Isolation & Arithmetic Hardening:** `std::panic::catch_unwind` across every `extern "C"` FFI boundary (`bmsip-ffi`) and the `SipEngine` worker thread (emitting `Warning` + `Stopped` and returning `EngineError::ChannelClosed` on subsequent `send_command` calls), debug-safe wrapping/saturating RTP sequence & clamped timer math (`RfcTimers`, `RtpStreamStats`, `AdaptiveJitterBuffer`), and finalized deployment/architecture documentation.
- **`0.16.0` — Complete Audit Edge-Case & Interop Closure:** Strict RFC `1*DIGIT` / duplicate `Content-Length` validation across parser & stream framer, RFC 3605 `a=rtcp:` & RFC 5761 `a=rtcp-mux`, `TransactionId::server` `Via sent-by` discrimination + FNV-1a host/user fallback seed when `instance_seed == 0`, RFC 3262 `100rel` retransmits/`RAck` check/`504` timeout, RFC 3261 §14.1 `491` `re-INVITE` backoff retries & `UPDATE` glare/port-0 guards, RFC 3891 `Replaces` `481`/`486`/`603` status enforcement, delayed SDP offers (`INVITE`/`re-INVITE`), RFC 3550 Appendix A.1 2-packet sequence & unencrypted SSRC probation (`MAX_DROPOUT=3000`, `MAX_MISORDER=100`), per-peer TLS SNI (`peer_tls_hosts`) + IPv6 support, `10 s` TLS handshake & `180 s` idle timeouts, `5 s` UDP warning rate limiting, LRU routing maps + DNS positive/negative TTL, zero-CPU `Condvar` worker sleep on `Suspend`, best-effort `BYE`/`un-REGISTER` flush on `Shutdown`, and `set_active_call` / `bmsip_client_set_active_call` FFI parity.
- **`0.16.1` — Jitter Buffer Underrun & Clock-Skew Hardening:** Separated missing-packet PLC (`!frames.is_empty()`) from empty-buffer starvation (`frames.is_empty()`) in `AdaptiveJitterBuffer::pop` so slight remote clock skew or scheduling jitter holds `next_playout_seq` instead of dropping subsequent packets as `late_drops`, replaced multi-frame `50 Hz` empty-buffer repetition with a single linear taper-to-zero slip frame + crossfaded recovery, preserved `initial_depth_frames` during cold-start priming, and added `5 s` hysteresis on `underrun_floor_frames`.
- **`0.16.2` — Configurable SIP `User-Agent`:** Added `UaConfig::user_agent`, `UaConfig::with_user_agent`, `UaConfig::effective_user_agent()`, and `DEFAULT_USER_AGENT` in `bmsip-core` with CRLF sanitization across outbound `REGISTER`, `INVITE`, `re-INVITE`, `UPDATE`, and `INFO` requests.
- **`0.16.3` — Automatic Inbound RTP `ptime` & Rate Adaptation:** Rate-explicit `StreamResampler::resample_by_rate` / `AudioCodecPlugin::decode_to_rate`, sample-accurate variable-`ptime` (`2.5`–`120` ms) packet reordering and `20 ms` playout assembly in `AdaptiveJitterBuffer`, `120 ms` (`5760`-sample) RFC 6716 Opus decode support in `LibOpusCodec`, and automatic resampler continuity resets on SSRC/sequence/payload-type transitions.
- **`0.16.4` — Client-Side UDP NAT CRLF Keep-Alive:** Configurable `25 s` RFC 5626 `\r\n\r\n` UDP NAT pinhole keep-alive while `Registered` (`EngineConfig::udp_keepalive_secs`, `with_udp_keepalive_secs`) plus automatic UDP `\r\n` pong replies and clean CRLF absorption in `SipTransportDriver`.
- **`0.17.0` — Voicemail / Message Waiting Indication (Current):** RFC 3842 `application/simple-message-summary` parser (`bmsip-core::sip::mwi`) and RFC 6665 `SUBSCRIBE`/`NOTIFY` MWI FSM (`MwiMode::{Disabled, UnsolicitedOnly, Solicited, Auto}`), automatic `Allow-Events: message-summary`, `EngineCommand::RefreshVoicemail`, `EngineEvent::VoicemailUpdated`, and UniFFI/C99/CLI exposure.

---

## 6. Scope Boundaries & Production Deployment Requirements

`bmsip` is scoped intentionally for embeddable enterprise/carrier softphone deployments behind a registrar, IP PBX, or SBC (**Asterisk**, **FreeSWITCH**, **Kamailio / OpenSIPS / `rtpengine`**):

- **Server-Assisted NAT Traversal + Client CRLF Keep-Alive:** Client-side DNS `NAPTR`/`SRV` (RFC 3263) and ICE/STUN/TURN (RFC 8445 / 5389 / 8656) are intentionally out of scope; `SipEngine` automatically maintains NAT pinholes with `25 s` RFC 5626 `\r\n\r\n` keep-alives over UDP, TCP, and TLS, pairing with server-side symmetric RTP, `force_rport`, and contact rewriting (`rtp_symmetric=yes`, `rewrite_contact=yes`, `force_rport=yes` in Asterisk `pjsip.conf` or equivalent SBC/Sofia-SIP settings).
- **20 ms `AudioPort` Bridge with Automatic Inbound `ptime` Adaptation:** Host audio bridges (`AudioPort`) exchange fixed `20 ms` PCM frames (`a=ptime:20` outbound at `8000`, `16000`, or `48000` Hz), while `MediaSession` and `AdaptiveJitterBuffer` automatically adapt inbound RTP streams of any valid packetization interval (`2.5`–`120` ms, including `10`/`30`/`40`/`60` ms PBX transcoding and mid-call `ptime` or payload-type transitions) into exact `20 ms` playout frames.
- **Media & Signaling Security:** Production deployments use SIP over TLS 1.2–1.3 (`rustls`) + RFC 3711 / RFC 4568 SDES-SRTP (`AES_CM_128_HMAC_SHA1_80` / `_32`). Unverified WebRTC-style DTLS-SRTP remains isolated behind the off-by-default `experimental-dtls` Cargo feature.
- **Out-of-Scope SIP Packages:** Office BLF (`SUBSCRIBE`/`NOTIFY`, RFC 4235), `Join` barge-in (RFC 3911), and XML conference event packages (RFC 4575) are intentionally omitted to keep the protocol core minimal.
