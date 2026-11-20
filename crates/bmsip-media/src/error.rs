//! MODULE_CONTRACT: Error definitions for RTP/RTCP framing, G.711 codecs, RFC 4733 DTMF, jitter buffer, and WAV parsing.
//! INVARIANTS: All malformed packet or media payload conditions return `Result<_, MediaError>` without panicking.
//! RFC_REFS: RFC 3550, RFC 4733.

use std::fmt;

/// Errors produced by `bmsip-media`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaError {
    PacketTooShort,
    UnsupportedRtpVersion(u8),
    InvalidHeader(String),
    InvalidDtmf(String),
    UnsupportedCodec(String),
    InvalidWav(String),
    BufferError(String),
}

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "media packet too short"),
            Self::UnsupportedRtpVersion(v) => write!(f, "unsupported RTP/RTCP version: {v}"),
            Self::InvalidHeader(msg) => write!(f, "invalid RTP/RTCP header: {msg}"),
            Self::InvalidDtmf(msg) => write!(f, "invalid RFC 4733 DTMF payload: {msg}"),
            Self::UnsupportedCodec(msg) => write!(f, "unsupported media codec: {msg}"),
            Self::InvalidWav(msg) => write!(f, "invalid WAV data: {msg}"),
            Self::BufferError(msg) => write!(f, "media buffer error: {msg}"),
        }
    }
}

impl std::error::Error for MediaError {}
