# bmsip

**bmsip** is a modern, embeddable, cross-platform SIP & RTP telephony library written in Rust from the ground up for **Linux**, **iOS**, and **Android**, complete with a live-audio Linux CLI softphone and an automated multi-server SIP interoperability lab.

- **Current Version:** `0.16.0` ([CHANGELOG.md](./CHANGELOG.md))
- **Architecture Specification:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **Developer Guides:** [SDK Guide](./docs/SDK_GUIDE.md) · [Codecs & Audio Pipeline](./docs/CODECS_AND_AUDIO.md) · [CLI & Interop Lab](./docs/CLI_AND_TESTING.md)
- **License:** `AGPL-3.0-only` ([LICENSE](./LICENSE) · [NOTICE](./NOTICE) · commercial licensing: [bymaker.com](https://bymaker.com))

---

## Why bmsip?

Legacy C/C++ SIP stacks often suffer from hidden global state, callback re-entrancy deadlocks, entangled socket/audio I/O, and awkward mobile OS integration. `bmsip` solves these by design:

- **100% Sans-I/O Protocol Core (`bmsip-core`):** `#![forbid(unsafe_code)]`, zero external crate dependencies, zero sockets/threads/system-clock calls. All time and network I/O are injected explicitly for deterministic simulation under packet loss, reordering, and duplication.
- **Multi-Transport SIP Signaling & SRTP Media Encryption:** Pure-Rust `rustls` TLS 1.2–1.3 (`ring`, RFC 5922, mTLS), non-blocking TCP/TLS connection setup and stream framing (`SipStreamFramer`, RFC 5626 keep-alive), and 100% safe-Rust **SRTP / SRTCP** (`AES_CM_128_HMAC_SHA1_80` / `_32`, RFC 3711) with **SDES** (`RTP/SAVP`, `a=crypto:`, RFC 4568) backed by 256-bit OS CSPRNG keys, per-SSRC ROC/replay tracking, and TLS-enforced key transport.
- **Lock-Safe Command/Event Runtime (`bmsip-engine`):** Multiple independent `SipEngine` instances run safely in one process. Applications interact strictly via non-blocking `EngineCommand` / `EngineEvent` queues — zero callbacks under mutexes.
  - **Zero-Panic FFI & Thread Boundaries:** Both `SipEngine` worker loops and every `extern "C"` entrypoint in `bmsip-ffi` isolate panics cleanly via `catch_unwind`, returning `EngineError::ChannelClosed` / `-1` / `NULL` cleanly instead of unwinding across OS threads or FFI frames.
- **Built-in "Golden Trio" Audio Codecs + Pluggable Registry (`bmsip-media`):**
  - **Opus (`48 kHz` Fullband HD):** Native `libopus` C FFI integration (`LibOpusCodec`) wired cleanly into `SipEngine` (Opus is omitted from SDP offers if `libopus` is unavailable).
  - **ITU-T G.722 (`16 kHz` Wideband HD Voice):** Pure Safe Rust SB-ADPCM Mode 1 codec (payload type `9`, RFC 3551 §4.5.2) with standard QMF subband polarity & scaling for hardware IP-phone/Asterisk `spandsp` compatibility.
  - **ITU-T G.711 (`8 kHz`):** Pure Safe Rust `PCMU` (μ-law, PT `0`) and `PCMA` (A-law, PT `8`).
  - **Universal Codec Plugin System:** Register custom external codecs (`G.729`, `L16`, `AMR-WB`, `Codec2`, etc.) via `AudioCodecPlugin` + `FnCodecFactory` + `CodecRegistry` / `EngineConfig::register_custom_codec` with automatic `8`/`16`/`48` kHz PCM adaptation.
- **Adaptive Jitter Buffer & Microphone DSP:** RFC 3550 Appendix A.1 2-packet sequence/SSRC probation, 16-bit RTP sequence rollover handling, jitter-driven buffering depth, smooth zero-click PLC crossfade on recovered frames, and frame-level microphone noise gate / gain / soft limiter (`condition_mic_frame`).
- **First-Class Mobile Lifecycle & Black-Box Flight Recorder:** Built-in `NetworkChanged` (Wi-Fi <-> LTE handover with `REGISTER` refresh + `re-INVITE`), `Suspend` / `Resume` (zero-CPU `Condvar` worker pause on PushKit / FCM background wakeup), and a bounded per-call JSON flight recorder.
- **Complete Softphone Call Control:** Call Hold / Resume (`re-INVITE` `a=sendonly`/`inactive`/`sendrecv`) with automatic `491` backoff retry, delayed SDP offer (`INVITE`/`re-INVITE`), Blind (`REFER` + `NOTIFY message/sipfrag`) & Attended (`Replaces`) Transfer, early/in-dialog `UPDATE`, reliable `1xx` / `PRACK` (`100rel`) with retransmits & `504` timeout, `Session-Timers` (RFC 4028 with `422` auto-retry), `Reason` (RFC 3326), `a=rtcp:`/`a=rtcp-mux` (RFC 3605 / 5761), and `P-Asserted-Identity` / `Privacy` Caller-ID (RFC 3323 / RFC 3325).
- **Early Media, Dual-Mode DTMF & Comfort Noise:** Early-media `183`/`180` SDP RTP activation before `200 OK` (RFC 3960), paced RFC 4733 `telephone-event` + legacy SIP `INFO` (`application/dtmf-relay`, RFC 2976) DTMF, and RFC 3389 Comfort Noise (`CN` PT 13) SID DTX synthesis.
- **Cross-Platform FFI (`bmsip-ffi`):** Unified UniFFI `.udl` contract (`BmsipClient`) for **Swift (iOS)** and **Kotlin (Android)** plus a C99 `extern "C"` ABI (`bmsip.h`), with reference OS audio/AEC adapters under `bindings/`.

---

## Workspace Layout & Documentation Map

```text
bmsip/
├── crates/
│   ├── bmsip-core/     # Sans-I/O SIP/2.0 (sip:/sips:/tel:), SDP (RFC 4566/3264), MD5/SHA-256 Digest Auth, RFC 3261/6026/4028 FSMs
│   ├── bmsip-media/    # Safe-Rust RTP/RTCP (compound RR+SDES, DLSR), G.711/G.722/Opus, CodecRegistry plugins, DTMF/CN, jitter buffer, DSP
│   ├── bmsip-engine/   # Lock-safe SipEngine runtime, UDP/TCP/TLS (rustls) transport, timers, libopus FFI, AudioPort, FlightRecorder
│   ├── bmsip-ffi/      # Cross-platform BmsipClient (UniFFI bmsip.udl) & C99 ABI (include/bmsip.h)
│   └── bmsip-cli/      # CLI softphone (`call`, `listen`), DSP WAV `analyze`, PBX `selftest`, and 3-server `interop` suite
├── bindings/
│   ├── ios/            # Reference Swift AVAudioEngine (VoiceProcessingIO AEC) + CallKit + NWPathMonitor bridge
│   ├── android/        # Reference Kotlin AudioRecord/AudioTrack + AcousticEchoCanceler + ConnectivityManager bridge
│   └── c/              # Minimal C99 softphone example (`minimal_phone.c`)
├── docs/
│   ├── SDK_GUIDE.md          # Embedding guide (Rust, C99, iOS Swift, Android Kotlin), lifecycle, Flight Recorder JSON
│   ├── CODECS_AND_AUDIO.md   # Opus/G.722/G.711 details, AudioPort, DSP pipeline, custom AudioCodecPlugin authoring
│   └── CLI_AND_TESTING.md    # CLI subcommands, DSP quality analyzer, and Asterisk + FreeSWITCH + Kamailio testbed
├── .devcontainer/      # Rust dev container + Asterisk 20 (PJSIP), FreeSWITCH 1.10 (Sofia-SIP), Kamailio 5.8 (SIP Proxy)
├── ARCHITECTURE.md     # Layer invariants, crate DAG, RFC compliance matrix, and version roadmap
└── CHANGELOG.md        # Keep a Changelog release notes synchronized with workspace version
```

---

## Quickstart (Dev Container & Multi-Server Lab)

All Rust build, formatting, lint, and integration commands run inside the Docker Compose `dev` container alongside three real SIP servers (`asterisk`, `freeswitch`, `kamailio`):

```bash
# 1. Start the Rust dev container and all 3 SIP test servers
docker compose up -d --build dev asterisk freeswitch kamailio

# 2. Run formatting, strict clippy lints, and the full workspace test suite
docker compose exec -T dev cargo fmt --all -- --check
docker compose exec -T dev cargo clippy --workspace --all-targets -- -D warnings
docker compose exec -T dev cargo test --workspace
```

---

## Multi-Server Interoperability Suite (`bmsip-cli interop`)

Run the automated 12-scenario SIP/RTP/DTMF benchmark across **Asterisk** (`chan_pjsip` B2BUA), **FreeSWITCH** (`mod_sofia` + `mod_opus` + `mod_spandsp`), and **Kamailio** (`Record-Route` SIP Proxy + Registrar):

```bash
docker compose exec -T dev cargo run -q -p bmsip-cli -- interop
```

Sample output:

```text
Server      Engine     Scenario              Codec  Rate   RMS dBFS  Freq Hz  SNR dB   DTMF  STATUS
----------------------------------------------------------------------------------------------------
Asterisk    PJSIP      Echo-PCMU-8k-440Hz    PCMU   8000    -12.1 dB   440.0   38.3 dB -     PASS
Asterisk    PJSIP      Echo-G722-16k-3000Hz  G722   16000   -12.1 dB  3000.0   41.5 dB -     PASS
Asterisk    PJSIP      Echo-OPUS-48k-440Hz   OPUS   48000   -12.1 dB   440.0   48.5 dB -     PASS
Asterisk    PJSIP      Echo-OPUS-48k-6000Hz  OPUS   48000   -12.1 dB  5999.6   28.1 dB -     PASS
Asterisk    PJSIP      Call-1001->1002-DTMF  OPUS   48000   -12.5 dB   442.4   22.1 dB 5     PASS
FreeSWITCH  Sofia-SIP  Echo-PCMU-8k-440Hz    PCMU   8000    -12.5 dB   440.0   38.3 dB -     PASS
FreeSWITCH  Sofia-SIP  Echo-G722-16k-3000Hz  G722   16000   -12.7 dB  3000.5   20.9 dB -     PASS
FreeSWITCH  Sofia-SIP  Echo-OPUS-48k-440Hz   OPUS   48000   -13.1 dB   440.1   33.5 dB -     PASS
FreeSWITCH  Sofia-SIP  Echo-OPUS-48k-6000Hz  OPUS   48000   -11.7 dB  5999.7   10.6 dB -     PASS
FreeSWITCH  Sofia-SIP  Call-1001->1002-DTMF  OPUS   48000   -13.5 dB   440.7   19.4 dB 5     PASS
Kamailio    SIP-Proxy  Proxy-G722-1001->1002 G722   16000   -12.6 dB   433.8   14.7 dB 5     PASS
Kamailio    SIP-Proxy  Proxy-P2P-1001->1002  OPUS   48000   -12.5 dB   442.4   21.8 dB 5     PASS
```

For single-PBX echo testing with glitch/dropout diagnostics:

```bash
docker compose exec -T dev cargo run -q -p bmsip-cli -- selftest \
  --server asterisk:5060 --user 1001 --password secret1001
```

---

## Linux CLI Softphone (`bmsip-cli`)

Place a live microphone/speaker SIP call (`PipeWire` / `PulseAudio` / `ALSA` at `48 kHz`) using `opus` (default), wideband `g722`, `pcmu`, or `pcma`:

```bash
# Outbound call to extension 601 (Echo test) over TLS + SDES-SRTP with live mic/headset and DSP summary
docker compose exec -T dev cargo run -p bmsip-cli -- call \
  --server asterisk:5061 \
  --transport tls \
  --tls-insecure \
  --srtp sdes \
  --user 1004 \
  --password secret1004 \
  --target "sip:601@asterisk:5061;transport=tls" \
  --duration-ms 5000 \
  --codec opus \
  --mic-gain 4.0 \
  --live-audio \
  --hold-ms 500 \
  --wav-out /tmp/echo_rx.wav \
  --json-report /tmp/call_blackbox.json

# Answer an incoming call with G.722 or Opus live audio
docker compose exec -T dev cargo run -p bmsip-cli -- listen \
  --server asterisk:5060 \
  --user 1002 \
  --password secret1002 \
  --codec g722 \
  --live-audio

# Run standalone DSP quality analysis on any recorded 16-bit mono WAV
docker compose exec -T dev cargo run -p bmsip-cli -- analyze --wav /tmp/echo_rx.wav
```

See [docs/CLI_AND_TESTING.md](./docs/CLI_AND_TESTING.md) for all flags and analyzer thresholds.

---

## Embedding Quickstart

### 1. Rust Application (`bmsip-engine`)

```rust
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use bmsip_engine::bmsip_core::dialog::UaConfig;
use bmsip_engine::bmsip_core::sip::SipUri;
use bmsip_engine::{EngineCommand, EngineConfig, EngineEvent, PcmQueueAudioPort, SipEngine};

let registrar: SocketAddr = "127.0.0.1:5060".parse()?;
let ua_cfg = UaConfig::new(
    "1001",
    "secret1001",
    "pbx.example.com",
    SipUri::parse("sip:pbx.example.com:5060")?,
    "0.0.0.0",
    0,
);
let mut config = EngineConfig::new(ua_cfg, registrar, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

// Optional: register a custom external codec plugin via FnCodecFactory
// config.register_custom_codec(Arc::new(FnCodecFactory::new(descriptor, || Box::new(MyCodec::new()))));

let (audio_port, audio_handle) = PcmQueueAudioPort::new(64);
let engine = SipEngine::spawn(config, Box::new(audio_port))?;
engine.send_command(EngineCommand::Register)?;
```

### 2. C99 / C++ (`bmsip-ffi`)

Include [crates/bmsip-ffi/include/bmsip.h](./crates/bmsip-ffi/include/bmsip.h) and link against `target/release/libbmsip_ffi.so` or `libbmsip_ffi.a`:

```c
BmsipClientHandle *client = bmsip_client_new("1001", "secret1001", "asterisk", "asterisk:5060", "0.0.0.0", 0);
bmsip_client_register(client);
char *event_json = bmsip_client_poll_event_json(client, 100);
```

### 3. iOS (`Swift`) & Android (`Kotlin`)

Generate native bindings from [crates/bmsip-ffi/src/bmsip.udl](./crates/bmsip-ffi/src/bmsip.udl) and wire your audio session and connectivity callbacks using the reference adapters in [bindings/ios/BmsipIosAudioBridge.swift](./bindings/ios/BmsipIosAudioBridge.swift) and [bindings/android/BmsipAndroidAudioBridge.kt](./bindings/android/BmsipAndroidAudioBridge.kt).

See [docs/SDK_GUIDE.md](./docs/SDK_GUIDE.md) and [docs/CODECS_AND_AUDIO.md](./docs/CODECS_AND_AUDIO.md) for complete API documentation.
