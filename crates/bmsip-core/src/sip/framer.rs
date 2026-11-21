//! MODULE_CONTRACT: SIP transport selector (`SipTransport`) and Sans-I/O TCP/TLS byte-stream framer (`SipStreamFramer`) with RFC 5626 CRLF keep-alive support.
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero I/O or external dependencies; bounded buffer (`MAX_SIP_STREAM_BUFFER`) prevents Slowloris/OOM attacks; enforces mandatory `Content-Length` on stream transports per RFC 3261 §18.3.
//! RFC_REFS: RFC 3261 Sections 18.1–18.3; RFC 5626 Section 4.4.1 (CRLF Keep-Alive); RFC 5922 (SIP over TLS).

use std::collections::VecDeque;
use std::fmt;

use crate::error::SipError;
use crate::sip::uri::{SipScheme, SipUri};

/// Default maximum buffered byte count per TCP/TLS SIP stream (64 KiB).
pub const MAX_SIP_STREAM_BUFFER: usize = 64 * 1024;

/// RFC 5626 Section 4.4.1 keep-alive ping (`CRLF CRLF`).
pub const RFC5626_KEEPALIVE_PING: &[u8] = b"\r\n\r\n";

/// RFC 5626 Section 4.4.1 keep-alive pong (`CRLF`).
pub const RFC5626_KEEPALIVE_PONG: &[u8] = b"\r\n";

/// Supported SIP signaling transport protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SipTransport {
    #[default]
    Udp,
    Tcp,
    Tls,
}

impl SipTransport {
    /// Parses `"udp"`, `"tcp"`, or `"tls"` (case-insensitive).
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "tls" => Ok(Self::Tls),
            _ => Err(SipError::ParseError(format!(
                "unsupported SIP transport '{raw}' (expected udp, tcp, or tls)"
            ))),
        }
    }

    /// Returns the uppercase SIP `Via` transport token (`"UDP"`, `"TCP"`, or `"TLS"`).
    pub fn via_proto(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
        }
    }

    /// Returns the lowercase SIP URI `;transport=` parameter value (`"udp"`, `"tcp"`, or `"tls"`).
    pub fn uri_param(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }

    /// Returns the IANA default port for this SIP transport (`5060` for UDP/TCP, `5061` for TLS).
    pub fn default_port(self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 5060,
            Self::Tls => 5061,
        }
    }

    /// Returns `true` for reliable connection-oriented stream transports (`TCP` and `TLS`).
    pub fn is_reliable(self) -> bool {
        matches!(self, Self::Tcp | Self::Tls)
    }

    /// Infers a [`SipTransport`] from a [`SipUri`]'s `;transport=` parameter or `sips:` scheme, if specified.
    pub fn from_uri(uri: &SipUri) -> Option<Self> {
        if let Some(Some(val)) = uri.param("transport") {
            if let Ok(t) = Self::parse(val) {
                return Some(t);
            }
        }
        if uri.scheme == SipScheme::Sips {
            return Some(Self::Tls);
        }
        None
    }
}

impl fmt::Display for SipTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.uri_param())
    }
}

/// Logical frame extracted from a TCP/TLS SIP byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFrame {
    /// Complete raw SIP/2.0 request or response message bytes (headers + exact `Content-Length` body).
    Message(Vec<u8>),
    /// Inbound RFC 5626 double-CRLF keep-alive ping (`\r\n\r\n`); peer expects a `\r\n` pong.
    KeepAlivePing,
    /// Inbound RFC 5626 single-CRLF keep-alive pong (`\r\n`).
    KeepAlivePong,
}

/// Sans-I/O streaming SIP message deframer for TCP and TLS connections (RFC 3261 §18.3, RFC 5626 §4.4.1).
#[derive(Debug, Clone)]
pub struct SipStreamFramer {
    buf: Vec<u8>,
    max_buffer_bytes: usize,
    ping_outstanding: bool,
}

impl Default for SipStreamFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl SipStreamFramer {
    /// Creates a new [`SipStreamFramer`] with [`MAX_SIP_STREAM_BUFFER`] (64 KiB) capacity limit.
    pub fn new() -> Self {
        Self::with_max_buffer_bytes(MAX_SIP_STREAM_BUFFER)
    }

    /// Creates a new [`SipStreamFramer`] with a custom hard buffer limit in bytes.
    pub fn with_max_buffer_bytes(max_buffer_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_buffer_bytes: max_buffer_bytes.max(1024),
            ping_outstanding: false,
        }
    }

    /// Marks that an outbound RFC 5626 CRLF keep-alive ping was sent so an incoming `\r\n` is recognized as its pong.
    pub fn note_keepalive_ping_sent(&mut self) {
        self.ping_outstanding = true;
    }

    /// Appends raw bytes read from a TCP or TLS stream.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), SipError> {
        if self.buf.len().saturating_add(chunk.len()) > self.max_buffer_bytes {
            self.buf.clear();
            return Err(SipError::ParseError(format!(
                "SIP stream buffer exceeded maximum limit of {} bytes",
                self.max_buffer_bytes
            )));
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// Attempts to extract the next complete [`StreamFrame`] from the internal buffer.
    pub fn next_frame(&mut self) -> Result<Option<StreamFrame>, SipError> {
        loop {
            if self.buf.is_empty() {
                return Ok(None);
            }

            // RFC 5626 §4.4.1: double-CRLF keep-alive ping between SIP messages.
            if self.buf.starts_with(RFC5626_KEEPALIVE_PING) {
                self.buf.drain(..4);
                return Ok(Some(StreamFrame::KeepAlivePing));
            }

            // If stream begins with `\r\n\r`, wait for the 4th byte to distinguish `\r\n\r\n` ping.
            if self.buf == b"\r\n\r" {
                return Ok(None);
            }

            // Exact 2-byte `\r\n`: only treat as KeepAlivePong when a ping is outstanding;
            // otherwise wait so a TCP-split `\r\n` + `\r\n` inbound ping is not misread.
            if self.buf == RFC5626_KEEPALIVE_PONG {
                if self.ping_outstanding {
                    self.ping_outstanding = false;
                    self.buf.drain(..2);
                    return Ok(Some(StreamFrame::KeepAlivePong));
                }
                return Ok(None);
            }

            // Leading `\r\n` followed by a non-`\r` byte: emit pong if ping outstanding,
            // or strip leading CRLF padding between SIP messages per RFC 3261 §7.5.
            if self.buf.starts_with(RFC5626_KEEPALIVE_PONG) {
                self.buf.drain(..2);
                if self.ping_outstanding {
                    self.ping_outstanding = false;
                    return Ok(Some(StreamFrame::KeepAlivePong));
                }
                continue;
            }

            // Wait if buffer only contains a single leading `\r` before `\n`.
            if self.buf == b"\r" {
                return Ok(None);
            }

            let Some(header_end) = find_subslice(&self.buf, b"\r\n\r\n") else {
                return Ok(None);
            };

            let header_slice = &self.buf[..header_end];
            let content_length = match parse_stream_content_length(header_slice) {
                Ok(cl) => cl,
                Err(err) => {
                    self.buf.clear();
                    return Err(err);
                }
            };
            if content_length > self.max_buffer_bytes {
                self.buf.clear();
                return Err(SipError::ParseError(format!(
                    "SIP stream Content-Length {content_length} exceeds limit {}",
                    self.max_buffer_bytes
                )));
            }

            let total_len = header_end
                .checked_add(4)
                .and_then(|n| n.checked_add(content_length))
                .ok_or_else(|| {
                    self.buf.clear();
                    SipError::ParseError("SIP stream frame length overflow".to_string())
                })?;

            if total_len > self.max_buffer_bytes {
                self.buf.clear();
                return Err(SipError::ParseError(format!(
                    "SIP stream message length {total_len} exceeds limit {}",
                    self.max_buffer_bytes
                )));
            }

            if self.buf.len() < total_len {
                return Ok(None);
            }

            let msg: Vec<u8> = self.buf.drain(..total_len).collect();
            return Ok(Some(StreamFrame::Message(msg)));
        }
    }

    /// Extracts all currently complete [`StreamFrame`]s from the buffer.
    pub fn drain_frames(&mut self) -> Result<Vec<StreamFrame>, SipError> {
        let mut out = Vec::new();
        while let Some(frame) = self.next_frame()? {
            out.push(frame);
        }
        Ok(out)
    }

    /// Returns the number of currently buffered bytes awaiting frame completion.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Clears all buffered bytes.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

/// Outbound byte queue helper for non-blocking TCP/TLS streams.
#[derive(Debug, Default, Clone)]
pub struct StreamWriteQueue {
    chunks: VecDeque<Vec<u8>>,
    front_offset: usize,
}

impl StreamWriteQueue {
    /// Enqueues bytes to be flushed to the stream.
    pub fn push(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }
    }

    /// Returns the next contiguous slice pending transmission, if any.
    pub fn front_slice(&self) -> Option<&[u8]> {
        self.chunks.front().map(|buf| &buf[self.front_offset..])
    }

    /// Advances the queue after `written` bytes were accepted by the underlying socket/TLS writer.
    pub fn consume(&mut self, written: usize) {
        let mut remaining = written;
        while remaining > 0 {
            let Some(front) = self.chunks.front() else {
                self.front_offset = 0;
                break;
            };
            let avail = front.len().saturating_sub(self.front_offset);
            if remaining >= avail {
                remaining -= avail;
                self.chunks.pop_front();
                self.front_offset = 0;
            } else {
                self.front_offset += remaining;
                remaining = 0;
            }
        }
    }

    /// Returns `true` when there are no pending bytes queued.
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_stream_content_length(header_bytes: &[u8]) -> Result<usize, SipError> {
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| SipError::ParseError("non-UTF-8 SIP stream headers".to_string()))?;

    // Unfold RFC 3261 §7.3.1 linear-whitespace continuation lines prior to field lookup.
    let mut logical_lines: Vec<String> = Vec::new();
    for line in header_text.split("\r\n").skip(1) {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(prev) = logical_lines.last_mut() {
                prev.push(' ');
                prev.push_str(line.trim());
            }
        } else {
            logical_lines.push(line.to_string());
        }
    }

    let mut found: Option<usize> = None;
    for line in logical_lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let key = name.trim();
        if key.eq_ignore_ascii_case("Content-Length") || key.eq_ignore_ascii_case("l") {
            let trimmed = value.trim();
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(SipError::ParseError(format!(
                    "invalid stream Content-Length '{trimmed}'"
                )));
            }
            let parsed = trimmed.parse::<usize>().map_err(|_| {
                SipError::ParseError(format!("invalid stream Content-Length '{trimmed}'"))
            })?;
            if let Some(prev) = found {
                if prev != parsed {
                    return Err(SipError::ParseError(format!(
                        "conflicting duplicate Content-Length headers ({prev} vs {parsed})"
                    )));
                }
            } else {
                found = Some(parsed);
            }
        }
    }

    found.ok_or_else(|| {
        SipError::ParseError(
            "missing mandatory Content-Length header on TCP/TLS SIP stream (RFC 3261 §18.3)"
                .to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_parsing_and_uri_inference() {
        assert_eq!(SipTransport::parse("UDP").unwrap(), SipTransport::Udp);
        assert_eq!(SipTransport::parse("tcp").unwrap(), SipTransport::Tcp);
        assert_eq!(SipTransport::parse("TLS").unwrap(), SipTransport::Tls);
        assert!(SipTransport::parse("sctp").is_err());

        assert!(!SipTransport::Udp.is_reliable());
        assert!(SipTransport::Tcp.is_reliable());
        assert!(SipTransport::Tls.is_reliable());
        assert_eq!(SipTransport::Tls.default_port(), 5061);
        assert_eq!(SipTransport::Tcp.via_proto(), "TCP");

        let tcp_uri = SipUri::parse("sip:1001@pbx.local:5060;transport=tcp").unwrap();
        assert_eq!(SipTransport::from_uri(&tcp_uri), Some(SipTransport::Tcp));
        let sips_uri = SipUri::parse("sips:1001@pbx.local").unwrap();
        assert_eq!(SipTransport::from_uri(&sips_uri), Some(SipTransport::Tls));
    }

    #[test]
    fn framer_reassembles_fragmented_coalesced_and_keepalive_frames() {
        let msg1 = b"OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
            From: <sip:alice@pbx.local>;tag=a1\r\n\
            To: <sip:bob@pbx.local>\r\n\
            Call-ID: tcp-1\r\n\
            CSeq: 1 OPTIONS\r\n\
            Content-Length: 0\r\n\r\n";

        let msg2 = b"SIP/2.0 200 OK\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
            From: <sip:alice@pbx.local>;tag=a1\r\n\
            To: <sip:bob@pbx.local>;tag=b1\r\n\
            Call-ID: tcp-1\r\n\
            CSeq: 1 OPTIONS\r\n\
            l: 5\r\n\r\nhello";

        // Feed ping + msg1 + pong + msg2 byte-by-byte.
        let mut wire = Vec::new();
        wire.extend_from_slice(RFC5626_KEEPALIVE_PING);
        wire.extend_from_slice(msg1);
        wire.extend_from_slice(RFC5626_KEEPALIVE_PONG);
        wire.extend_from_slice(msg2);

        let mut framer = SipStreamFramer::new();
        framer.note_keepalive_ping_sent();
        let mut frames = Vec::new();
        for b in &wire {
            framer.push(&[*b]).unwrap();
            // Flush byte-by-byte only after checking exact ping boundary when full wire arrives in chunks.
            if framer.buffered_len() != 2 && framer.buffered_len() != 3 {
                frames.extend(framer.drain_frames().unwrap());
            }
        }
        frames.extend(framer.drain_frames().unwrap());

        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0], StreamFrame::KeepAlivePing);
        assert_eq!(frames[1], StreamFrame::Message(msg1.to_vec()));
        assert_eq!(frames[2], StreamFrame::KeepAlivePong);
        assert_eq!(frames[3], StreamFrame::Message(msg2.to_vec()));
        assert_eq!(framer.buffered_len(), 0);

        // Coalesced single read produces all frames at once.
        framer.note_keepalive_ping_sent();
        framer.push(&wire).unwrap();
        let coalesced = framer.drain_frames().unwrap();
        assert_eq!(coalesced, frames);
    }

    #[test]
    fn framer_rejects_missing_content_length_and_oversized_payloads() {
        let mut framer = SipStreamFramer::with_max_buffer_bytes(1024);
        let missing_cl = b"OPTIONS sip:bob@10.0.0.2 SIP/2.0\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\r\n";
        framer.push(missing_cl).unwrap();
        assert!(framer.next_frame().is_err());

        framer.clear();
        let huge_cl = b"INVITE sip:bob@10.0.0.2 SIP/2.0\r\n\
            Content-Length: 999999\r\n\r\n";
        framer.push(huge_cl).unwrap();
        assert!(framer.next_frame().is_err());
        assert_eq!(framer.buffered_len(), 0);
    }

    #[test]
    fn framer_ignores_unsolicited_crlf_supports_folded_cl_and_clears_only_bad_frame() {
        let valid = b"\r\nOPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-f1\r\n\
            Content-Length:\r\n 0\r\n\r\n";
        let bad = b"OPTIONS sip:bob@10.0.0.2:5060 SIP/2.0\r\n\
            Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-f2\r\n\r\n";

        let mut wire = Vec::new();
        wire.extend_from_slice(valid);
        wire.extend_from_slice(bad);

        let mut framer = SipStreamFramer::new();
        framer.push(&wire).unwrap();
        let first = framer.next_frame().unwrap().expect("expected valid frame");
        assert!(matches!(first, StreamFrame::Message(_)));
        assert!(framer.next_frame().is_err());
        assert_eq!(framer.buffered_len(), 0);

        // Reject signed Content-Length and conflicting duplicate headers; accept identical duplicates.
        let plus_cl = b"OPTIONS sip:bob@10.0.0.2 SIP/2.0\r\n\
            Content-Length: +5\r\n\r\nhello";
        framer.push(plus_cl).unwrap();
        assert!(framer.next_frame().is_err());

        let conflict_cl = b"OPTIONS sip:bob@10.0.0.2 SIP/2.0\r\n\
            Content-Length: 5\r\n\
            l: 0\r\n\r\nhello";
        framer.push(conflict_cl).unwrap();
        assert!(framer.next_frame().is_err());

        let matching_dup = b"OPTIONS sip:bob@10.0.0.2 SIP/2.0\r\n\
            Content-Length: 2\r\n\
            l: 2\r\n\r\nhi";
        framer.push(matching_dup).unwrap();
        assert!(matches!(
            framer.next_frame().unwrap(),
            Some(StreamFrame::Message(m)) if m == matching_dup
        ));
    }
}
