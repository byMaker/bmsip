//! MODULE_CONTRACT: SIP/2.0 wire-format model (methods, URIs, typed/raw headers, requests, responses, stream framing).
//! INVARIANTS: Case-insensitive header lookup, compact header normalization, CRLF header folding/unfolding, panic-free parsing.
//! RFC_REFS: RFC 3261 Sections 7, 18, 19, 20; RFC 3262; RFC 3323; RFC 3325; RFC 3326; RFC 3581; RFC 3891; RFC 4028; RFC 5626; RFC 5922.

pub mod framer;
pub mod headers;
pub mod message;
pub mod method;
pub mod uri;

pub use framer::{
    SipStreamFramer, SipTransport, StreamFrame, StreamWriteQueue, MAX_SIP_STREAM_BUFFER,
    RFC5626_KEEPALIVE_PING, RFC5626_KEEPALIVE_PONG,
};
pub use headers::{
    CSeq, CallerIdentity, Header, Headers, NameAddr, RAck, ReasonHeader, ReplacesHeader,
    SessionExpires, SessionRefresher, Via,
};
pub use message::{SipMessage, SipRequest, SipResponse};
pub use method::Method;
pub use uri::{SipScheme, SipUri, UriParam};
