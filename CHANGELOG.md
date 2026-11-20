# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-20

### Added
- Five-crate Cargo workspace (`bmsip-core`, `bmsip-media`, `bmsip-engine`, `bmsip-ffi`, `bmsip-cli`) with Docker Compose Dev Container toolchain (`rust:1-bookworm`).
- `bmsip-core` dependency-free Sans-I/O protocol core (`#![forbid(unsafe_code)]`):
  - SIP/2.0 parser and serializer with compact headers, folded headers, IPv6 URI support, `Via` `rport`/`received`, `NameAddr`, and `CSeq`.
  - SDP audio parser/serializer (RFC 4566) and Offer/Answer codec/direction negotiation (RFC 3264).
  - Pure-Rust MD5 (RFC 1321) and SHA-256 (FIPS 180-4) Digest Authentication (`MD5`, `MD5-sess`, `SHA-256`, `SHA-256-sess`, `qop=auth` and legacy modes).
  - RFC 3261 Section 17 transaction state machines (`ClientInviteTransaction`, `ClientNonInviteTransaction`, `ServerInviteTransaction`, `ServerNonInviteTransaction`) with Timers A–K and auto-`ACK` on `3xx–6xx`.
  - Deterministic Sans-I/O `VirtualNetwork` simulator and integration tests covering packet loss, duplication, Digest auth, `486 Busy Here`, `200 OK` + SDP negotiation, and timer timeouts.
