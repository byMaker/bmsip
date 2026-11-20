//! MODULE_CONTRACT: SIP request method enum and RFC 3261 token validation.
//! INVARIANTS: Standard methods map to typed variants; unknown valid tokens map to `Method::Extension`.
//! RFC_REFS: RFC 3261 Section 7.1, Section 25.1 (`token` ABNF).

use std::fmt;
use std::str::FromStr;

use crate::error::SipError;

/// SIP request method (RFC 3261 and extensions).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    Register,
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Update,
    Info,
    Prack,
    Notify,
    Subscribe,
    Message,
    Refer,
    Extension(String),
}

impl Method {
    /// Parses a SIP method token.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let trimmed = input.trim();
        if trimmed.is_empty() || !is_valid_token(trimmed) {
            return Err(SipError::ParseError(format!("invalid SIP method: {input}")));
        }

        let method = match trimmed {
            "REGISTER" => Self::Register,
            "INVITE" => Self::Invite,
            "ACK" => Self::Ack,
            "BYE" => Self::Bye,
            "CANCEL" => Self::Cancel,
            "OPTIONS" => Self::Options,
            "UPDATE" => Self::Update,
            "INFO" => Self::Info,
            "PRACK" => Self::Prack,
            "NOTIFY" => Self::Notify,
            "SUBSCRIBE" => Self::Subscribe,
            "MESSAGE" => Self::Message,
            "REFER" => Self::Refer,
            other => Self::Extension(other.to_string()),
        };
        Ok(method)
    }

    /// Returns the wire string representation of the method.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Register => "REGISTER",
            Self::Invite => "INVITE",
            Self::Ack => "ACK",
            Self::Bye => "BYE",
            Self::Cancel => "CANCEL",
            Self::Options => "OPTIONS",
            Self::Update => "UPDATE",
            Self::Info => "INFO",
            Self::Prack => "PRACK",
            Self::Notify => "NOTIFY",
            Self::Subscribe => "SUBSCRIBE",
            Self::Message => "MESSAGE",
            Self::Refer => "REFER",
            Self::Extension(name) => name.as_str(),
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = SipError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Checks whether a string conforms to RFC 3261 `token` characters.
pub(crate) fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_and_extension_methods() {
        assert_eq!(Method::parse("INVITE").unwrap(), Method::Invite);
        assert_eq!(Method::parse("REGISTER").unwrap(), Method::Register);
        assert_eq!(
            Method::parse("PUBLISH").unwrap(),
            Method::Extension("PUBLISH".to_string())
        );
        assert!(Method::parse("").is_err());
        assert!(Method::parse("BAD METHOD").is_err());
    }
}
