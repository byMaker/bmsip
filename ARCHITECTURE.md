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
| `bmsip-media` | RTP/RTCP framing, DTMF (RFC 4733), adaptive jitter buffer, G.711/Opus codecs, 20 ms PCM frame pipeline | `#![forbid(unsafe_code)]`; zero direct OS audio device calls (ALSA, PipeWire, CoreAudio, Oboe) |
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
- **`0.3.0` — Stage 3 (Current):** `bmsip-media` RTP/RTCP, adaptive jitter buffer, G.711 (`PCMU`/`PCMA`), DTMF (RFC 4733), WAV test call verification.
- **`0.4.0` — Stage 4:** `bmsip-engine` UDP/TCP transport + `bmsip-cli` Linux softphone + per-call diagnostic flight recorder.
- **`0.5.0` — Stage 5:** `bmsip-ffi` UniFFI `.udl` contract (Swift/Kotlin/C) + Opus codec integration.
