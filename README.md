# bmsip

Embeddable, cross-platform SIP library written in Rust for **Linux**, **iOS**, and **Android**.

- **Current Version:** `0.5.0` ([CHANGELOG.md](./CHANGELOG.md))
- **Architecture Specification:** [ARCHITECTURE.md](./ARCHITECTURE.md)
- **License:** `AGPL-3.0-only` ([LICENSE](./LICENSE) · [NOTICE](./NOTICE) · commercial licensing: [bymaker.com](https://bymaker.com))

## Workspace Layout

```text
crates/
├── bmsip-core/     # 100% Sans-I/O SIP, SDP, Digest Auth, RFC 3261 transactions
├── bmsip-media/    # Hardware-agnostic RTP/RTCP, jitter buffer, codecs, 20 ms PCM
├── bmsip-engine/   # Lock-safe Command/Event runtime with sockets & timers
├── bmsip-ffi/      # Cross-platform UniFFI (Swift/Kotlin) & C-API facade
└── bmsip-cli/      # Linux CLI SIP endpoint and integration harness
```

## Development Environment (Dev Container)

All Rust tooling (`rustc`, `cargo`, `rustfmt`, `clippy`) runs inside the Docker Compose `dev` container.

Start the dev container and local Asterisk test PBX:

```bash
docker compose up -d --build dev asterisk
```

Run formatting check, linter, and all workspace tests:

```bash
docker compose exec -T dev cargo fmt --all -- --check
docker compose exec -T dev cargo clippy --workspace --all-targets -- -D warnings
docker compose exec -T dev cargo test --workspace
```

