#![forbid(unsafe_code)]

//! MODULE_CONTRACT: Dependency-free Sans-I/O SIP/SDP/Digest/Transaction protocol core (`bmsip-core`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; empty `[dependencies]`; zero `std::net`, `std::thread`, `std::fs`, `Instant::now()`, `SystemTime::now()`, or async runtimes; no `.unwrap()`/`.expect()` outside tests.
//! RFC_REFS: RFC 3261, RFC 3264, RFC 3581, RFC 4566, RFC 2617, RFC 7616.

pub mod auth;
pub mod error;
pub mod sdp;
pub mod sim;
pub mod sip;
pub mod transaction;

pub use error::SipError;

/// Returns the crate version.
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_non_empty() {
        assert!(!core_version().is_empty());
    }
}
