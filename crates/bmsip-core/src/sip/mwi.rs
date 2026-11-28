//! MODULE_CONTRACT: RFC 3842 `application/simple-message-summary` parser and serializer (`MessageSummary`, `MessageCounts`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero I/O; bounded payload size (`<= 16 KiB`); panic-free CRLF/LF unfolding and count parsing.
//! RFC_REFS: RFC 3842 Sections 3, 5.

use std::fmt;

use crate::error::SipError;
use crate::sip::headers::NameAddr;
use crate::sip::uri::SipUri;

/// Standard SIP event package token for Message Waiting Indication (RFC 3842 §3.1).
pub const MWI_EVENT_PACKAGE: &str = "message-summary";

/// Standard MIME content type for Message Waiting Indication payloads (RFC 3842 §5).
pub const MWI_CONTENT_TYPE: &str = "application/simple-message-summary";

/// Upper bound enforced on incoming `application/simple-message-summary` bodies (`16 KiB`).
pub const MAX_MESSAGE_SUMMARY_BYTES: usize = 16 * 1024;

/// New/old (and optional urgent) counts parsed from an RFC 3842 summary line (`new/old (urgent_new/urgent_old)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MessageCounts {
    pub new: u32,
    pub old: u32,
    pub urgent_new: u32,
    pub urgent_old: u32,
}

impl MessageCounts {
    /// Parses `"new/old"` or `"new/old (urgent_new/urgent_old)"` per RFC 3842 §5.2.
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(SipError::ParseError("empty message counts".to_string()));
        }

        let (main_part, urgent_part) = match trimmed.find('(') {
            Some(open_idx) => {
                let close_idx = trimmed[open_idx..].find(')').ok_or_else(|| {
                    SipError::ParseError(format!("unclosed '(' in message counts '{trimmed}'"))
                })? + open_idx;
                if !trimmed[close_idx + 1..].trim().is_empty() {
                    return Err(SipError::ParseError(format!(
                        "unexpected trailing characters in message counts '{trimmed}'"
                    )));
                }
                (
                    trimmed[..open_idx].trim(),
                    Some(trimmed[open_idx + 1..close_idx].trim()),
                )
            }
            None => (trimmed, None),
        };

        let (new, old) = parse_slash_pair(main_part, trimmed)?;
        let (urgent_new, urgent_old) = match urgent_part {
            Some(u) => parse_slash_pair(u, trimmed)?,
            None => (0, 0),
        };

        Ok(Self {
            new,
            old,
            urgent_new,
            urgent_old,
        })
    }
}

fn parse_slash_pair(part: &str, full: &str) -> Result<(u32, u32), SipError> {
    let (lhs, rhs) = part
        .split_once('/')
        .ok_or_else(|| SipError::ParseError(format!("expected 'new/old' pair in '{full}'")))?;
    let a = lhs
        .trim()
        .parse::<u32>()
        .map_err(|_| SipError::ParseError(format!("invalid count '{lhs}' in '{full}'")))?;
    let b = rhs
        .trim()
        .parse::<u32>()
        .map_err(|_| SipError::ParseError(format!("invalid count '{rhs}' in '{full}'")))?;
    Ok((a, b))
}

/// Parsed RFC 3842 `application/simple-message-summary` notification payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MessageSummary {
    pub messages_waiting: bool,
    pub message_account: Option<SipUri>,
    pub voice: Option<MessageCounts>,
}

impl MessageSummary {
    /// Parses an RFC 3842 `application/simple-message-summary` body (supporting `CRLF` and `LF` endings and LWS folding).
    pub fn parse(body: &[u8]) -> Result<Self, SipError> {
        if body.len() > MAX_MESSAGE_SUMMARY_BYTES {
            return Err(SipError::ParseError(format!(
                "MWI body exceeds {MAX_MESSAGE_SUMMARY_BYTES} byte limit ({} bytes)",
                body.len()
            )));
        }

        let text = std::str::from_utf8(body)
            .map_err(|e| SipError::ParseError(format!("non-UTF-8 MWI payload: {e}")))?;

        let mut summary_lines: Vec<String> = Vec::new();
        for raw_line in text.lines() {
            let line = raw_line.trim_end_matches('\r');
            if line.trim().is_empty() {
                if summary_lines.is_empty() {
                    continue;
                }
                // RFC 3842 §5.2: optional per-message headers appear after the first blank line.
                break;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(prev) = summary_lines.last_mut() {
                    prev.push(' ');
                    prev.push_str(line.trim());
                } else {
                    return Err(SipError::ParseError(
                        "unexpected leading whitespace before MWI status line".to_string(),
                    ));
                }
            } else {
                summary_lines.push(line.to_string());
            }
        }

        let mut messages_waiting: Option<bool> = None;
        let mut message_account: Option<SipUri> = None;
        let mut voice: Option<MessageCounts> = None;

        for line in summary_lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| SipError::ParseError(format!("malformed MWI line '{line}'")))?;
            let key = name.trim().to_ascii_lowercase();
            let val = value.trim();
            match key.as_str() {
                "messages-waiting" => {
                    if val.eq_ignore_ascii_case("yes") {
                        messages_waiting = Some(true);
                    } else if val.eq_ignore_ascii_case("no") {
                        messages_waiting = Some(false);
                    } else {
                        return Err(SipError::ParseError(format!(
                            "invalid Messages-Waiting value '{val}'"
                        )));
                    }
                }
                "message-account" => {
                    if !val.is_empty() {
                        let uri = NameAddr::parse(val)
                            .map(|na| na.uri)
                            .or_else(|_| SipUri::parse(val.trim_matches(['<', '>']).trim()))?;
                        message_account = Some(uri);
                    }
                }
                "voice-message" => {
                    voice = Some(MessageCounts::parse(val)?);
                }
                _ => {
                    // Gracefully ignore Fax-Message, Text-Message, Multimedia-Message, or extension headers.
                }
            }
        }

        let messages_waiting = messages_waiting.ok_or_else(|| {
            SipError::ParseError("missing mandatory Messages-Waiting line in MWI body".to_string())
        })?;

        Ok(Self {
            messages_waiting,
            message_account,
            voice,
        })
    }

    /// Returns the new voice message count (falling back to `1` when `messages_waiting` is `true` without counts).
    pub fn new_voice_count(&self) -> u32 {
        self.voice
            .map_or(u32::from(self.messages_waiting), |v| v.new)
    }

    /// Returns the old/saved voice message count (`0` if omitted).
    pub fn old_voice_count(&self) -> u32 {
        self.voice.map_or(0, |v| v.old)
    }

    /// Returns the urgent new voice message count (`0` if omitted).
    pub fn urgent_new_voice_count(&self) -> u32 {
        self.voice.map_or(0, |v| v.urgent_new)
    }

    /// Returns the urgent old/saved voice message count (`0` if omitted).
    pub fn urgent_old_voice_count(&self) -> u32 {
        self.voice.map_or(0, |v| v.urgent_old)
    }
}

impl fmt::Display for MessageSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Messages-Waiting: {}\r\n",
            if self.messages_waiting { "yes" } else { "no" }
        )?;
        if let Some(account) = &self.message_account {
            write!(f, "Message-Account: {account}\r\n")?;
        }
        if let Some(voice) = &self.voice {
            if voice.urgent_new > 0 || voice.urgent_old > 0 {
                write!(
                    f,
                    "Voice-Message: {}/{} ({}/{})\r\n",
                    voice.new, voice.old, voice.urgent_new, voice.urgent_old
                )?;
            } else {
                write!(f, "Voice-Message: {}/{}\r\n", voice.new, voice.old)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_summary_with_urgent_counts_and_trailing_headers() {
        let raw = b"Messages-Waiting: Yes\r\nMessage-Account: <sip:*97@172.21.0.4>\r\nVoice-Message: 2/5 (1/0)\r\nFax-Message: 0/0\r\n\r\nTo: <sip:1001@172.21.0.4>\r\nSubject: Missed call\r\n";
        let summary = MessageSummary::parse(raw).unwrap();
        assert!(summary.messages_waiting);
        assert_eq!(
            summary.message_account.as_ref().map(ToString::to_string),
            Some("sip:*97@172.21.0.4".to_string())
        );
        assert_eq!(
            summary.voice,
            Some(MessageCounts {
                new: 2,
                old: 5,
                urgent_new: 1,
                urgent_old: 0,
            })
        );
        assert_eq!(summary.new_voice_count(), 2);
        assert_eq!(summary.old_voice_count(), 5);
        assert_eq!(summary.urgent_new_voice_count(), 1);
        assert_eq!(summary.urgent_old_voice_count(), 0);

        let roundtrip = MessageSummary::parse(summary.to_string().as_bytes()).unwrap();
        assert_eq!(roundtrip, summary);
    }

    #[test]
    fn parses_lf_folded_and_minimal_summary_without_counts() {
        let minimal = b"messages-waiting: yes\n";
        let parsed = MessageSummary::parse(minimal).unwrap();
        assert!(parsed.messages_waiting);
        assert_eq!(parsed.voice, None);
        assert_eq!(parsed.new_voice_count(), 1);

        let folded =
            b"Messages-Waiting: no\nMessage-Account:\n sip:*97@pbx.local\nVoice-Message: 0/3\n";
        let parsed_folded = MessageSummary::parse(folded).unwrap();
        assert!(!parsed_folded.messages_waiting);
        assert_eq!(
            parsed_folded
                .message_account
                .as_ref()
                .map(ToString::to_string),
            Some("sip:*97@pbx.local".to_string())
        );
        assert_eq!(
            parsed_folded.voice,
            Some(MessageCounts {
                new: 0,
                old: 3,
                urgent_new: 0,
                urgent_old: 0,
            })
        );
        assert_eq!(parsed_folded.new_voice_count(), 0);
        assert_eq!(parsed_folded.old_voice_count(), 3);
    }

    #[test]
    fn rejects_invalid_or_oversized_summary() {
        assert!(MessageSummary::parse(b"Voice-Message: 1/0\r\n").is_err());
        assert!(MessageSummary::parse(b"Messages-Waiting: maybe\r\n").is_err());
        assert!(MessageSummary::parse(b"Messages-Waiting: yes\r\nVoice-Message: bad\r\n").is_err());
        let oversized = vec![b'a'; MAX_MESSAGE_SUMMARY_BYTES + 1];
        assert!(MessageSummary::parse(&oversized).is_err());
    }
}
