//! MODULE_CONTRACT: SIP/2.0 wire-format model (methods, URIs, typed/raw headers, requests, responses).
//! INVARIANTS: Case-insensitive header lookup, compact header normalization, CRLF header folding/unfolding, panic-free parsing.
//! RFC_REFS: RFC 3261 Sections 7, 19, 20; RFC 3581.

pub mod headers;
pub mod message;
pub mod method;
pub mod uri;

pub use headers::{CSeq, Header, Headers, NameAddr, Via};
pub use message::{SipMessage, SipRequest, SipResponse};
pub use method::Method;
pub use uri::{SipScheme, SipUri, UriParam};
