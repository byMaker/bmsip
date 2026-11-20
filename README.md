# bmsip

Embeddable, cross-platform SIP library written in Rust for **Linux**, **iOS**, and **Android**.

- **Current Version:** `0.8.0` ([CHANGELOG.md](./CHANGELOG.md))
- **Architecture Specification:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **License:** `AGPL-3.0-only` ([LICENSE](./LICENSE) · [NOTICE](./NOTICE) · commercial licensing: [bymaker.com](https://bymaker.com))

## Workspace Layout

```text
crates/
├── bmsip-core/     # 100% Sans-I/O SIP, SDP, Digest Auth, RFC 3261 transactions & dialogs
├── bmsip-media/    # Hardware-agnostic RTP/RTCP, jitter buffer, G.711/Opus, DTMF, 20 ms PCM & mic DSP
├── bmsip-engine/   # Lock-safe Command/Event runtime with UDP sockets, timers, libopus & flight recorder
├── bmsip-ffi/      # Cross-platform UniFFI (Swift/Kotlin) & C-API facade + bmsip.h
└── bmsip-cli/      # Linux CLI SIP softphone (`call --live-audio --codec opus`, `listen`)
bindings/
├── ios/            # Reference Swift AVAudioEngine + CallKit + NWPathMonitor adapter
├── android/        # Reference Kotlin AudioRecord/AudioTrack + AEC + ConnectivityManager adapter
└── c/              # Minimal C99 softphone example (`minimal_phone.c`)
```

## Development Environment (Dev Container)

All Rust tooling (`rustc`, `cargo`, `rustfmt`, `clippy`) and PipeWire/ALSA audio utilities run inside the Docker Compose `dev` container.

Start the dev container and the multi-server SIP testbed (Asterisk, FreeSWITCH, Kamailio):

```bash
docker compose up -d --build dev asterisk freeswitch kamailio
```

Run formatting check, linter, and all workspace tests:

```bash
docker compose exec -T dev cargo fmt --all -- --check
docker compose exec -T dev cargo clippy --workspace --all-targets -- -D warnings
docker compose exec -T dev cargo test --workspace
```

Run the unified 9-scenario multi-server interoperability suite (`Asterisk` + `FreeSWITCH` + `Kamailio`):

```bash
docker compose exec -T dev cargo run -p bmsip-cli -- interop
```

Run a live 48 kHz Opus microphone/speaker SIP call through the Asterisk echo test (`601`):

```bash
docker compose exec -T dev cargo run -p bmsip-cli -- call --server asterisk:5060 --user 1001 --password secret1001 --target sip:601@asterisk:5060 --duration-ms 5000 --codec opus --live-audio
```

Run in inbound listening mode:

```bash
docker compose exec -T dev cargo run -p bmsip-cli -- listen --server asterisk:5060 --user 1002 --password secret1002 --codec opus --live-audio
```
