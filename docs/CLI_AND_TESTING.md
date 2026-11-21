# CLI Softphone & Multi-Server Interoperability Lab

`bmsip-cli` (`crates/bmsip-cli`) is both a full Linux CLI SIP endpoint (supporting PipeWire/PulseAudio/ALSA live audio and WAV streaming) and an automated DSP audio quality & multi-server interoperability test runner.

---

## 1. CLI Subcommands Reference

Invoke via Docker inside `dev` or build the native Linux release binary (`docker compose exec -T dev cargo build --release` -> `./target/release/bmsip-cli`):

### 1.1 `call` — Outbound SIP Call

```bash
bmsip-cli call \
  --server <host:port> \
  --user <username> \
  --password <password> \
  --target <sip_or_tel_uri> \
  [--transport udp|tcp|tls] \
  [--srtp off|optional|sdes] \
  [--tls-ca <path>] \
  [--tls-server-name <hostname>] \
  [--tls-insecure] \
  [--duration-ms <ms>] \
  [--tone-hz <hz>] \
  [--codec opus|g722|pcmu|pcma] \
  [--mic-gain <mult>] \
  [--live-audio] \
  [--hold-ms <ms>] \
  [--transfer <sip_uri>] \
  [--dtmf <digits>] \
  [--dtmf-mode rfc4733|info] \
  [--wav-in <path>] \
  [--wav-out <path>] \
  [--json-report <path>]
```

- `--target <sip_or_tel_uri>`: Accepts `sip:`, `sips:`, or RFC 3966 `tel:` target URIs (`tel:` routes automatically to the configured `--server` registrar).
- `--transport udp|tcp|tls`: Selects SIP signaling transport (`udp` default, `tcp`, or `tls` via pure-Rust `rustls` 1.2–1.3).
- `--srtp off|optional|sdes`: Configures SRTP media encryption (`off` default `RTP/AVP`, `optional` opportunistic SDES over TLS, or `sdes` mandatory `RTP/SAVP` RFC 4568 `a=crypto:`, which requires `--transport tls`).
- `--tls-ca <path>`, `--tls-server-name <hostname>`, `--tls-insecure`: Optional TLS trust bundle, SNI/hostname override, and lab-only certificate verification bypass.
- `--live-audio`: Captures microphone input and plays decoded RX audio at `48000 Hz` via PipeWire (`pw-cat`) / PulseAudio (`parec`/`pacat`) / ALSA (`arecord`/`aplay`).
- `--codec <name>`: Sets preferred outbound SDP offer order (all presets also advertise static Comfort Noise `CN/8000` PT `13`):
  - `opus` (default): `[opus/48000, G722/8000, PCMU, PCMA, CN, telephone-event/48000, telephone-event/8000]`
  - `g722`: `[G722/8000, PCMU, PCMA, CN, telephone-event/8000]`
  - `pcmu`: `[PCMU, PCMA, CN, telephone-event/8000]`
  - `pcma`: `[PCMA, PCMU, CN, telephone-event/8000]`
- `--mic-gain <mult>`: Microphone software gain multiplier before soft limiting (default: `4.0`).
- `--hold-ms <ms>`: Places the active call on hold via `re-INVITE` (`a=sendonly`) for `<ms>` milliseconds mid-call, then automatically resumes (`a=sendrecv`).
- `--transfer <sip_uri>`: Initiates a blind transfer (`REFER`, RFC 3515) to `<sip_uri>` once media has streamed.
- `--dtmf <digits>`: Transmits DTMF digits (e.g. `1234#`) once connected.
- `--dtmf-mode rfc4733|info`: Selects RFC 4733 RTP `telephone-event` (default) or legacy RFC 2976 SIP `INFO` (`application/dtmf-relay`).
- `--wav-out` & `--json-report`: Saves received playout PCM16 WAV and per-call Black-Box telemetry JSON. During `--live-audio` sessions, RX WAV buffering is disabled unless `--wav-out` is passed so long calls run in constant memory.

### 1.2 `listen` — Inbound Call Receiver

```bash
bmsip-cli listen \
  --server <host:port> \
  --user <username> \
  --password <password> \
  [--transport udp|tcp|tls] \
  [--srtp off|optional|sdes] \
  [--tls-ca <path>] \
  [--tls-server-name <hostname>] \
  [--tls-insecure] \
  [--duration-ms <ms>] \
  [--codec opus|g722|pcmu|pcma] \
  [--mic-gain <mult>] \
  [--live-audio] \
  [--wav-out <path>] \
  [--json-report <path>]
```

Registers with the registrar, awaits an incoming `INVITE` for up to 60 seconds, replies `180 Ringing` -> `200 OK`, streams bidirectional audio and prints received DTMF digits, then exports DSP metrics and optional WAV/JSON reports.

### 1.3 `analyze` — Standalone WAV DSP Inspector

```bash
bmsip-cli analyze --wav <path> [--tone-hz <hz>]
```

Inspects any mono 16-bit WAV file (`crates/bmsip-cli/src/analyzer.rs`) and reports:

- Sample rate, total samples, duration, and active 20 ms frame count
- Initial playout latency (first non-silent frame)
- Mid-stream dropouts (unexpected near-silent frames inside active regions; natural pauses in live speech mode when `--tone-hz` is omitted are not flagged as dropouts)
- Frame boundary phase clicks (`max_boundary_jump` exceeding adaptive discontinuity threshold)
- RMS & peak amplitude (`dBFS`), DC offset, clipped sample count (`>= 32000`)
- Detected dominant frequency via Goertzel/DFT + zero-crossing analysis and quadrature SNR (`dB`) vs `--tone-hz` (or speech-to-pause noise floor ratio when `--tone-hz` is omitted)

### 1.4 `selftest` — Single-PBX 7-Scenario Echo Benchmark

```bash
docker compose exec -T dev cargo run -q -p bmsip-cli -- selftest \
  --server asterisk:5060 --user 1001 --password secret1001
```

Executes 7 automated calls against extension `601` (`Echo()`):

1. `PCMU-8k-440Hz` (`8 kHz`, `440 Hz`)
2. `PCMA-8k-1000Hz` (`8 kHz`, `1000 Hz`)
3. `G722-16k-440Hz` (`16 kHz`, `440 Hz`)
4. `G722-16k-3000Hz-WB` (`16 kHz`, wideband `3000 Hz`)
5. `OPUS-48k-440Hz` (`48 kHz`, `440 Hz`)
6. `OPUS-48k-6000Hz-HD` (`48 kHz`, highband `6000 Hz`)
7. `OPUS-48k-Quiet` (`48 kHz`, low amplitude `1200` PCM to verify noise gate behavior)

Each case enforces zero mid-stream dropouts, frequency accuracy within 10%, and `SNR >= 12.0 dB`.

### 1.5 `interop` — Unified 3-Server Benchmark

```bash
docker compose exec -T dev cargo run -q -p bmsip-cli -- interop \
  [--asterisk asterisk:5060] \
  [--freeswitch freeswitch:5060] \
  [--kamailio kamailio:5060] \
  [--duration-ms 500]
```

Runs 12 live SIP/RTP/DTMF scenarios verifying compatibility across distinct SIP stacks (`Asterisk` PJSIP, `FreeSWITCH` Sofia-SIP, `Kamailio` stateful loose-routing proxy) and passes only when all audio metrics and two-party RFC 4733 DTMF digit `'5'` verification succeed.

---

## 2. Multi-Server Docker Compose Lab

`docker-compose.yml` provisions an isolated bridge network (`bmsip-net`) containing:

| Service      | Software & SIP Engine                                      | Port & Accounts                                                                     | Enabled Codecs & Dialplan                                                                            |
| ------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `asterisk`   | Asterisk 20 (`chan_pjsip` B2BUA + `res_srtp`)              | `5060/udp`, `5060/tcp`, `5061/tls`, users `1001`–`1003` (RTP/AVP), `1004` (`media_encryption=sdes`) | `opus, g722, ulaw, alaw`; `600` (Wait/Hangup), `601` (`Echo()`), `1001`–`1004` (P2P bridge)          |
| `freeswitch` | FreeSWITCH 1.10 (`mod_sofia` + `mod_opus` + `mod_spandsp`) | `5060/udp`, `5060/tcp`, users `1001`–`1003` (`secret1001`–`secret1003`)             | `OPUS, G722, PCMU, PCMA`; `407 Proxy-Authenticate`; `600`, `601` (`echo`), `1001`–`1003` (`bridge`)  |
| `kamailio`   | Kamailio 5.8 (`sl`/`tm`/`rr`/`registrar`/`usrloc`/`auth`)  | `5060/udp`, open registrar for test subnet (`bmsip-net`)                            | Loose routing (`Record-Route`/`Route`), dual `Via`, direct P2P RTP/DTMF between registered endpoints |
| `dev`        | Debian Bookworm + Rust toolchain + `libopus-dev` + `gcc`   | Workspace mounted at `/workspace`                                                   | Runs `cargo fmt`, `clippy`, `test`, `bmsip-cli` with optional PipeWire/ALSA host passthrough         |

---

## 3. Automated Workspace Test Suites

All verification commands run inside `dev`:

- **Unit, Simulation & Mutation Fuzz Tests (`bmsip-core`):** SIP/SDP parsers, MD5/SHA-256 Digest auth, RFC 3261 transaction timers under loss/duplication (`tests/rfc_simulation.rs`), dialog/handover/call-control FSMs (`tests/dialog_simulation.rs`), and 4,000-iteration deterministic parser mutation stress testing.
- **Media Unit & Fuzz Tests (`bmsip-media`):** G.711 zero codes, ITU-T G.722 lowband/highband unity-gain roundtrip, Opus TOC/`fmtp`/mic-conditioning, custom `CodecRegistry` resampling, RFC 4733 DTMF deduplication, RFC 3389 Comfort Noise (`CN` PT 13) SID DTX synthesis, RTCP stats, adaptive jitter PLC crossfade, and 4,000-iteration zero-copy RTP/RTCP/codec fuzzing.
- **FFI & C ABI Tests (`bmsip-ffi`):** `bmsip.udl` API parity (`udl_schema_matches_rust_sdk_surface`), C99 compilation checks with `gcc -std=c99 -Wall -Wextra -Werror` on `include/bmsip.h` and `bindings/c/minimal_phone.c`, plus live Asterisk call & hold/resume verification over `BmsipClient` and `bmsip_*` C functions (`tests/ffi_integration.rs`).
- **Live PBX, Transport, SRTP, Routing & Custom Plugin Integration Tests (`bmsip-engine`):** 17 tests in `crates/bmsip-engine/tests/asterisk_integration.rs` covering `REGISTER`/`INVITE`/`BYE`, `PCMU` Echo, `Opus 48 kHz` Echo, `Suspend`/`Resume` + Black-Box JSON, FreeSWITCH `407`/Echo + Kamailio P2P, G.722 Echo across Asterisk/FreeSWITCH, live FreeSWITCH `G.722 (5500 Hz) <-> Opus (48 kHz)` transcoded high-band QMF verification, multi-call hold focus + `SetActiveCall` + spoofed RTP source rejection, external custom `L16/16000` codec plugin calls routed via Kamailio, direct peer symmetric SIP routing + bounded/48 kHz audio ports, live Call Hold / Resume (`re-INVITE` `a=sendonly`/`a=sendrecv`), live early media `183 Session Progress` + SIP `INFO` DTMF, live SIP over TCP (`asterisk:5060`, `freeswitch:5060`) & TLS (`asterisk:5061`) Echo calls, P2P strict-CA + mTLS + untrusted-CA rejection, live Asterisk TLS + SDES-SRTP (`res_srtp.so`) encrypted Echo call, RFC 4568 §8 TLS enforcement + non-blocking TCP connect + P2P verified TLS + SDES-SRTP Hold/Resume/DTMF call, same-port `NetworkChanged` handover with `pending_rtp_sockets`, and panic-isolated worker recovery (`EngineEvent::Stopped` + `EngineError::ChannelClosed`). (`asterisk` `pjsip.conf` enforces `max_contacts=1` with `remove_existing=yes`; `freeswitch.xml` enables `media_mix_inbound_outbound_codecs` for cross-codec bridging.)
