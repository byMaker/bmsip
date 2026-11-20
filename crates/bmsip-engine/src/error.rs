//! MODULE_CONTRACT: Typed runtime errors for `bmsip-engine`.
//! INVARIANTS: Wraps core, media, socket I/O, queue, and state errors without panicking.
//! RFC_REFS: RFC 3261, RFC 3550.

use std::fmt;

use bmsip_core::SipError;
use bmsip_media::MediaError;

/// Errors produced by [`crate::SipEngine`] setup, command dispatch, or shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    Core(SipError),
    Media(MediaError),
    Io(String),
    ChannelClosed,
    InvalidState(String),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core(e) => write!(f, "{e}"),
            Self::Media(e) => write!(f, "{e}"),
            Self::Io(msg) => write!(f, "engine I/O error: {msg}"),
            Self::ChannelClosed => write!(f, "engine command or event channel closed"),
            Self::InvalidState(msg) => write!(f, "invalid engine state: {msg}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<SipError> for EngineError {
    fn from(value: SipError) -> Self {
        Self::Core(value)
    }
}

impl From<MediaError> for EngineError {
    fn from(value: MediaError) -> Self {
        Self::Media(value)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
