//! MODULE_CONTRACT: `SipMessage`, `SipRequest`, and `SipResponse` parser, serializer, and transaction-key extractors.
//! INVARIANTS: Ignores leading CRLF keepalives; unfolds SP/HTAB continuation lines; enforces `Content-Length` truncation bounds; `to_bytes()` keeps `Content-Length` synchronized with `body.len()`.
//! RFC_REFS: RFC 3261 Sections 7.1, 7.2, 7.3.1, 8.2.6.2.

use std::fmt;

use crate::error::SipError;
use crate::sip::headers::{CSeq, Headers, NameAddr, Via};
use crate::sip::method::Method;
use crate::sip::uri::SipUri;

/// A SIP request message (RFC 3261 Section 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipRequest {
    pub method: Method,
    pub uri: SipUri,
    pub version: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// A SIP response message (RFC 3261 Section 7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Headers,
    pub body: Vec<u8>,
}

/// Either a SIP request or a SIP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SipMessage {
    Request(SipRequest),
    Response(SipResponse),
}

impl SipRequest {
    /// Creates a minimal `SIP/2.0` request with empty body.
    pub fn new(method: Method, uri: SipUri) -> Self {
        Self {
            method,
            uri,
            version: "SIP/2.0".to_string(),
            headers: Headers::new(),
            body: Vec::new(),
        }
    }

    /// Sets the body and updates `Content-Type` and `Content-Length`.
    pub fn with_body(mut self, content_type: &str, body: Vec<u8>) -> Self {
        self.headers.set("Content-Type", content_type);
        self.headers.set("Content-Length", body.len().to_string());
        self.body = body;
        self
    }

    /// Builds a SIP response copying `Via`, `From`, `To`, `Call-ID`, and `CSeq` (RFC 3261 Section 8.2.6.2).
    pub fn create_response(
        &self,
        status_code: u16,
        reason_phrase: impl Into<String>,
    ) -> Result<SipResponse, SipError> {
        let mut resp = SipResponse {
            version: "SIP/2.0".to_string(),
            status_code,
            reason_phrase: reason_phrase.into(),
            headers: Headers::new(),
            body: Vec::new(),
        };

        let vias = self.headers.get_all("Via");
        if vias.is_empty() {
            return Err(SipError::MissingHeader("Via"));
        }
        for via in vias {
            resp.headers.add("Via", via);
        }

        let from = self
            .headers
            .get("From")
            .ok_or(SipError::MissingHeader("From"))?;
        let to = self
            .headers
            .get("To")
            .ok_or(SipError::MissingHeader("To"))?;
        let call_id = self
            .headers
            .get("Call-ID")
            .ok_or(SipError::MissingHeader("Call-ID"))?;
        let cseq = self
            .headers
            .get("CSeq")
            .ok_or(SipError::MissingHeader("CSeq"))?;

        resp.headers.set("From", from);
        resp.headers.set("To", to);
        resp.headers.set("Call-ID", call_id);
        resp.headers.set("CSeq", cseq);
        resp.headers.set("Content-Length", "0");

        Ok(resp)
    }

    /// Returns all parsed `Via` entries across all `Via` headers.
    pub fn vias(&self) -> Result<Vec<Via>, SipError> {
        parse_vias(&self.headers)
    }

    /// Returns the topmost `Via` header.
    pub fn top_via(&self) -> Result<Via, SipError> {
        self.vias()?
            .into_iter()
            .next()
            .ok_or(SipError::MissingHeader("Via"))
    }

    /// Returns the parsed `From` header.
    pub fn from(&self) -> Result<NameAddr, SipError> {
        parse_required_addr(&self.headers, "From")
    }

    /// Returns the parsed `To` header.
    pub fn to(&self) -> Result<NameAddr, SipError> {
        parse_required_addr(&self.headers, "To")
    }

    /// Returns the parsed `Contact` header, if present.
    pub fn contact(&self) -> Result<Option<NameAddr>, SipError> {
        match self.headers.get("Contact") {
            Some(v) if v.trim() == "*" => Ok(None),
            Some(v) => NameAddr::parse(v).map(Some),
            None => Ok(None),
        }
    }

    /// Returns the parsed `CSeq` header.
    pub fn cseq(&self) -> Result<CSeq, SipError> {
        let raw = self
            .headers
            .get("CSeq")
            .ok_or(SipError::MissingHeader("CSeq"))?;
        CSeq::parse(raw)
    }

    /// Returns the `Call-ID` header value.
    pub fn call_id(&self) -> Result<&str, SipError> {
        self.headers
            .get("Call-ID")
            .ok_or(SipError::MissingHeader("Call-ID"))
    }

    /// Serializes the request to SIP wire format (`\r\n` delimited).
    pub fn to_bytes(&self) -> Vec<u8> {
        let start_line = format!("{} {} {}", self.method, self.uri, self.version);
        serialize_sip_message(&start_line, &self.headers, &self.body)
    }
}

impl SipResponse {
    /// Attaches a body and updates `Content-Type` and `Content-Length`.
    pub fn with_body(mut self, content_type: &str, body: Vec<u8>) -> Self {
        self.headers.set("Content-Type", content_type);
        self.headers.set("Content-Length", body.len().to_string());
        self.body = body;
        self
    }

    /// Returns all parsed `Via` entries across all `Via` headers.
    pub fn vias(&self) -> Result<Vec<Via>, SipError> {
        parse_vias(&self.headers)
    }

    /// Returns the topmost `Via` header.
    pub fn top_via(&self) -> Result<Via, SipError> {
        self.vias()?
            .into_iter()
            .next()
            .ok_or(SipError::MissingHeader("Via"))
    }

    /// Returns the parsed `From` header.
    pub fn from(&self) -> Result<NameAddr, SipError> {
        parse_required_addr(&self.headers, "From")
    }

    /// Returns the parsed `To` header.
    pub fn to(&self) -> Result<NameAddr, SipError> {
        parse_required_addr(&self.headers, "To")
    }

    /// Returns the parsed `Contact` header, if present.
    pub fn contact(&self) -> Result<Option<NameAddr>, SipError> {
        match self.headers.get("Contact") {
            Some(v) => NameAddr::parse(v).map(Some),
            None => Ok(None),
        }
    }

    /// Returns the parsed `CSeq` header.
    pub fn cseq(&self) -> Result<CSeq, SipError> {
        let raw = self
            .headers
            .get("CSeq")
            .ok_or(SipError::MissingHeader("CSeq"))?;
        CSeq::parse(raw)
    }

    /// Returns the `Call-ID` header value.
    pub fn call_id(&self) -> Result<&str, SipError> {
        self.headers
            .get("Call-ID")
            .ok_or(SipError::MissingHeader("Call-ID"))
    }

    /// Serializes the response to SIP wire format (`\r\n` delimited).
    pub fn to_bytes(&self) -> Vec<u8> {
        let start_line = format!(
            "{} {} {}",
            self.version, self.status_code, self.reason_phrase
        );
        serialize_sip_message(&start_line, &self.headers, &self.body)
    }
}

impl SipMessage {
    /// Parses a SIP request or response from raw wire bytes.
    pub fn parse(raw: &[u8]) -> Result<Self, SipError> {
        let (head_bytes, body_slice) = split_head_and_body(raw)?;
        let head_str = std::str::from_utf8(head_bytes)
            .map_err(|_| SipError::ParseError("SIP headers are not valid UTF-8".to_string()))?;

        // Ignore leading CRLF keepalive pings before the start-line.
        let trimmed_head = head_str.trim_start_matches(['\r', '\n']);
        if trimmed_head.is_empty() {
            return Err(SipError::ParseError("empty SIP message".to_string()));
        }

        let mut lines = trimmed_head.lines();
        let start_line = lines
            .next()
            .ok_or_else(|| SipError::ParseError("missing SIP start-line".to_string()))?
            .trim_end_matches('\r');

        // Unfold RFC 3261 multi-line headers (lines starting with SP or HTAB).
        let mut raw_header_lines: Vec<String> = Vec::new();
        for raw_line in lines {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                let last = raw_header_lines.last_mut().ok_or_else(|| {
                    SipError::ParseError("folded header line without preceding header".to_string())
                })?;
                last.push(' ');
                last.push_str(line.trim());
            } else {
                raw_header_lines.push(line.to_string());
            }
        }

        let mut headers = Headers::new();
        for header_line in raw_header_lines {
            let (name, value) = header_line.split_once(':').ok_or_else(|| {
                SipError::ParseError(format!("malformed header line '{header_line}'"))
            })?;
            let trimmed_name = name.trim();
            if trimmed_name.is_empty() {
                return Err(SipError::ParseError("empty header name".to_string()));
            }
            headers.add(trimmed_name, value);
        }

        let body = match headers.get("Content-Length") {
            Some(len_str) => {
                let expected = len_str.trim().parse::<usize>().map_err(|_| {
                    SipError::ParseError(format!("invalid Content-Length '{len_str}'"))
                })?;
                if body_slice.len() < expected {
                    return Err(SipError::ParseError(format!(
                        "truncated SIP body: expected {expected} bytes, got {}",
                        body_slice.len()
                    )));
                }
                body_slice[..expected].to_vec()
            }
            None => body_slice.to_vec(),
        };

        if start_line.starts_with("SIP/") {
            let mut parts = start_line.splitn(3, ' ');
            let version = parts
                .next()
                .ok_or_else(|| SipError::ParseError("missing SIP version".to_string()))?;
            let code_str = parts
                .next()
                .ok_or_else(|| SipError::ParseError("missing status code".to_string()))?;
            let reason = parts.next().unwrap_or("").trim();

            if !version.eq_ignore_ascii_case("SIP/2.0") {
                return Err(SipError::ParseError(format!(
                    "unsupported SIP version '{version}'"
                )));
            }
            if code_str.len() != 3 || !code_str.bytes().all(|b| b.is_ascii_digit()) {
                return Err(SipError::ParseError(format!(
                    "invalid SIP status code '{code_str}'"
                )));
            }
            let status_code = code_str.parse::<u16>().map_err(|_| {
                SipError::ParseError(format!("invalid SIP status code '{code_str}'"))
            })?;
            if !(100..=699).contains(&status_code) {
                return Err(SipError::ParseError(format!(
                    "out-of-range SIP status code {status_code}"
                )));
            }

            Ok(Self::Response(SipResponse {
                version: "SIP/2.0".to_string(),
                status_code,
                reason_phrase: reason.to_string(),
                headers,
                body,
            }))
        } else {
            let mut parts = start_line.split_whitespace();
            let method_str = parts
                .next()
                .ok_or_else(|| SipError::ParseError("missing request method".to_string()))?;
            let uri_str = parts
                .next()
                .ok_or_else(|| SipError::ParseError("missing request URI".to_string()))?;
            let version = parts
                .next()
                .ok_or_else(|| SipError::ParseError("missing SIP version".to_string()))?;
            if parts.next().is_some() {
                return Err(SipError::ParseError(format!(
                    "unexpected tokens in request-line '{start_line}'"
                )));
            }
            if !version.eq_ignore_ascii_case("SIP/2.0") {
                return Err(SipError::ParseError(format!(
                    "unsupported SIP version '{version}'"
                )));
            }
            let method = Method::parse(method_str)?;
            let uri = SipUri::parse(uri_str)?;

            Ok(Self::Request(SipRequest {
                method,
                uri,
                version: "SIP/2.0".to_string(),
                headers,
                body,
            }))
        }
    }

    /// Serializes the message to SIP wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Request(req) => req.to_bytes(),
            Self::Response(resp) => resp.to_bytes(),
        }
    }

    /// Returns an immutable reference to the headers.
    pub fn headers(&self) -> &Headers {
        match self {
            Self::Request(req) => &req.headers,
            Self::Response(resp) => &resp.headers,
        }
    }
}

impl fmt::Display for SipMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        f.write_str(&String::from_utf8_lossy(&bytes))
    }
}

fn parse_vias(headers: &Headers) -> Result<Vec<Via>, SipError> {
    let raw_vias = headers.get_all("Via");
    if raw_vias.is_empty() {
        return Err(SipError::MissingHeader("Via"));
    }
    let mut vias = Vec::new();
    for raw in raw_vias {
        vias.extend(Via::parse_list(raw)?);
    }
    if vias.is_empty() {
        return Err(SipError::MissingHeader("Via"));
    }
    Ok(vias)
}

fn parse_required_addr(headers: &Headers, name: &'static str) -> Result<NameAddr, SipError> {
    let raw = headers.get(name).ok_or(SipError::MissingHeader(name))?;
    NameAddr::parse(raw)
}

fn split_head_and_body(raw: &[u8]) -> Result<(&[u8], &[u8]), SipError> {
    let start = raw
        .iter()
        .position(|&b| b != b'\r' && b != b'\n')
        .ok_or_else(|| SipError::ParseError("empty SIP message".to_string()))?;
    let trimmed = &raw[start..];

    if let Some(idx) = trimmed.windows(4).position(|w| w == b"\r\n\r\n") {
        return Ok((&trimmed[..idx], &trimmed[idx + 4..]));
    }
    if let Some(idx) = trimmed.windows(2).position(|w| w == b"\n\n") {
        return Ok((&trimmed[..idx], &trimmed[idx + 2..]));
    }
    Err(SipError::ParseError(
        "missing blank line separating SIP headers and body".to_string(),
    ))
}

fn serialize_sip_message(start_line: &str, headers: &Headers, body: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(start_line);
    out.push_str("\r\n");

    let mut wrote_content_length = false;
    for h in headers.iter() {
        if h.name.eq_ignore_ascii_case("Content-Length") {
            if !wrote_content_length {
                out.push_str(&format!("Content-Length: {}\r\n", body.len()));
                wrote_content_length = true;
            }
        } else {
            out.push_str(&format!("{}: {}\r\n", h.name, h.value));
        }
    }
    if !wrote_content_length {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");

    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_and_folded_invite() {
        let raw = b"\r\n\r\nINVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
            v: SIP/2.0/UDP pc33.atlanta.example.com:5060;\r\n branch=z9hG4bK776asdhds;rport\r\n\
            f: \"Alice\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n\
            t: Bob <sip:bob@biloxi.example.com>\r\n\
            i: a84b4c76e66710@pc33.atlanta.example.com\r\n\
            CSeq: 314159 INVITE\r\n\
            m: <sip:alice@pc33.atlanta.example.com>\r\n\
            c: application/sdp\r\n\
            l: 4\r\n\
            \r\n\
            v=0\n";

        let msg = SipMessage::parse(raw).unwrap();
        let req = match msg {
            SipMessage::Request(r) => r,
            SipMessage::Response(_) => panic!("expected request"),
        };

        assert_eq!(req.method, Method::Invite);
        assert_eq!(
            req.top_via().unwrap().branch.as_deref(),
            Some("z9hG4bK776asdhds")
        );
        assert_eq!(req.top_via().unwrap().rport, Some(None));
        assert_eq!(req.from().unwrap().tag.as_deref(), Some("1928301774"));
        assert_eq!(req.to().unwrap().display_name.as_deref(), Some("Bob"));
        assert_eq!(req.cseq().unwrap().seq, 314159);
        assert_eq!(
            req.call_id().unwrap(),
            "a84b4c76e66710@pc33.atlanta.example.com"
        );
        assert_eq!(req.body, b"v=0\n");

        // Round-trip re-parse check
        let serialized = req.to_bytes();
        let reparsed = SipMessage::parse(&serialized).unwrap();
        assert_eq!(reparsed, SipMessage::Request(req));
    }

    #[test]
    fn parses_response_and_create_response() {
        let mut req = SipRequest::new(Method::Register, SipUri::parse("sip:pbx.local").unwrap());
        req.headers
            .add("Via", "SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKreg1;rport");
        req.headers.add("From", "<sip:100@pbx.local>;tag=from1");
        req.headers.add("To", "<sip:100@pbx.local>");
        req.headers.add("Call-ID", "reg-call-1");
        req.headers.add("CSeq", "1 REGISTER");

        let resp = req.create_response(200, "OK").unwrap();
        let bytes = resp.to_bytes();
        let parsed = SipMessage::parse(&bytes).unwrap();
        match parsed {
            SipMessage::Response(r) => {
                assert_eq!(r.status_code, 200);
                assert_eq!(r.reason_phrase, "OK");
                assert_eq!(r.cseq().unwrap().method, Method::Register);
            }
            SipMessage::Request(_) => panic!("expected response"),
        }
    }

    #[test]
    fn rejects_truncated_body_and_garbage() {
        let truncated = b"INVITE sip:a@b SIP/2.0\r\nContent-Length: 50\r\n\r\nhi";
        assert!(SipMessage::parse(truncated).is_err());
        assert!(SipMessage::parse(b"").is_err());
        assert!(SipMessage::parse(b"\xff\xfe\xfd").is_err());
    }
}
