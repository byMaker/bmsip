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
| `bmsip-media` | RTP/RTCP framing, DTMF (RFC 4733), adaptive jitter buffer, G.711/G.722/Opus codecs, universal `CodecRegistry` plugin API, 20 ms PCM frame pipeline | `#![forbid(unsafe_code)]`; zero direct OS audio device calls (ALSA, PipeWire, CoreAudio, Oboe) |
| `bmsip-engine` | UDP/TCP socket loop, monotonic timer driver, `Command`/`Event` queues, `AudioPort` trait, call flight recorder | Zero global singletons (`static mut`); zero user callbacks invoked under held locks; multi-instance safe |
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
| RFC 3261 Sec 12–16 | Dialogs, `REGISTER` refresh, `INVITE`/`CANCEL`/`BYE`/`re-INVITE` | Implemented (`v0.2.0`) |
| RFC 3550 / 4733 | RTP/RTCP media transport and DTMF telephone-event | Implemented (`v0.3.0`) |
| RFC 6716 / 7587 | Native `libopus` 48 kHz VoIP codec + TOC/`fmtp` + mic DSP conditioning | Implemented (`v0.7.0`) |
| ITU-T G.722 / RFC 3551 §4.5.2 | Pure-Rust 16 kHz wideband G.722 codec (PT 9) + universal pluggable `AudioCodecPlugin` / `CodecRegistry` | Implemented (`v0.9.0`) |
| RFC 6337 / 3311 / 3262 | Call Hold/Resume (`a=sendonly`/`inactive`/`sendrecv`), early/in-dialog `UPDATE`, reliable `1xx` / `PRACK` (`100rel`) | Implemented (`v0.10.0`) |
| RFC 3515 / 3891 | Blind (`REFER` + `NOTIFY message/sipfrag`) and Attended (`Replaces`) Call Transfer | Implemented (`v0.10.0`) |
| RFC 4028 / 3326 / 3323 / 3325 | `Session-Timers` (`Session-Expires`/`Min-SE`/`422`), `Reason` header, `P-Asserted-Identity` & `Privacy` | Implemented (`v0.10.0`) |

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
- **`0.10.0` — Stage 10 (Current):** Core Call Control (Hold/Resume via `a=sendonly`/`inactive`/`sendrecv`, Blind `REFER`/`NOTIFY` & Attended `Replaces` transfer, early/in-dialog `UPDATE`, `PRACK`/`100rel`, `Session-Timers` with `422` auto-retry and `UPDATE` refresh, `Reason`, and `P-Asserted-Identity`/`Privacy`) across `bmsip-core`, `bmsip-engine`, `bmsip-ffi` (UniFFI + C99), and `bmsip-cli`.

---

## 6. Future Roadmap / TODO

- **TODO 1 — Transport Security & Media Encryption:**
  - SIP over TCP and TLS 1.2–1.3 (`rustls`, RFC 5922) with stream framing and persistent NAT keep-alive (RFC 5626).
  - Media encryption: **SRTP** (RFC 3711) with **SDES** key exchange (RFC 4568) and **DTLS-SRTP** for public internet traversal.
- **TODO 2 — Core Call Control (Softphone Essentials):** *Completed in `v0.10.0`.*
- **TODO 3 — Early Media, Legacy DTMF & Comfort Noise:**
  - Early media (`183 Session Progress` with SDP) — activate RTP playout prior to `200 OK`.
  - Legacy SIP `INFO` DTMF (`application/dtmf-relay`, RFC 2976) alongside RFC 4733.
  - Comfort Noise Generation (`CN`, PT 13, RFC 3389) for VAD/DTX interoperability.
- **TODO 4 — DNS Discovery & Public Internet NAT Traversal:**
  - SIP DNS server discovery (`NAPTR` / `SRV`, RFC 3263).
  - **STUN** (RFC 5389), **TURN** (RFC 8656), and **ICE** (RFC 8445) for symmetric NAT and firewall traversal.
- **Optional / Enterprise Backlog (On Demand):**
  - Event subscriptions (`SUBSCRIBE`/`NOTIFY` RFC 6665) for office BLF / Call Pickup (RFC 4235) and Voicemail MWI (RFC 3842).
  - Call barge-in (`Join` RFC 3911) and SIP conferencing event package (RFC 4575 / RFC 4353) — deferred unless explicitly needed.
