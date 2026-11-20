//! MODULE_CONTRACT: Typed error definitions for SIP/SDP parsing, Digest auth, and transaction state transitions.
//! INVARIANTS: All untrusted wire input failures map to `Result<_, SipError>` without panics.
//! RFC_REFS: RFC 3261 Section 8, RFC 4566, RFC 7616.

use std::fmt;

/// Errors produced by `bmsip-core` parsers, auth, SDP negotiation, and transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipError {
    /// Syntax or framing error while parsing a SIP message or header.
    ParseError(String),
    /// A mandatory SIP header was absent.
    MissingHeader(&'static str),
    /// Malformed SIP/SIPS URI.
    InvalidUri(String),
    /// Malformed SDP or incompatible media offer/answer.
    InvalidSdp(String),
    /// Digest authentication challenge or credential error.
    AuthError(String),
    /// Invalid transaction state transition or unknown transaction ID.
    TransactionError(String),
}

impl fmt::Display for SipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "SIP parse error: {msg}"),
            Self::MissingHeader(name) => write!(f, "missing mandatory SIP header: {name}"),
            Self::InvalidUri(msg) => write!(f, "invalid SIP URI: {msg}"),
            Self::InvalidSdp(msg) => write!(f, "invalid SDP: {msg}"),
            Self::AuthError(msg) => write!(f, "digest auth error: {msg}"),
            Self::TransactionError(msg) => write!(f, "transaction error: {msg}"),
        }
    }
}

impl std::error::Error for SipError {}
