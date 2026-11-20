//! MODULE_CONTRACT: Ordered `Headers` container and typed `Via`, `NameAddr` (`From`/`To`/`Contact`), and `CSeq` codecs.
//! INVARIANTS: Compact header names (`v`, `f`, `t`, `i`, `m`, `l`, `c`, `k`, etc.) normalize to canonical names; `NameAddr` without `<...>` treats `;...` as header params; comma lists ignore `,` inside quotes or `<...>`.
//! RFC_REFS: RFC 3261 Sections 7.3, 20.10, 20.42; RFC 3581 (`rport`).

use std::fmt;

use crate::error::SipError;
use crate::sip::method::Method;
use crate::sip::uri::SipUri;

/// A single raw SIP header name-value pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Ordered collection of SIP headers with case-insensitive & compact-name lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: Vec<Header>,
}

impl Headers {
    /// Creates an empty header collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a header without replacing existing headers of the same name.
    pub fn add(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let raw_name = name.into();
        let canonical = canonical_header_name(raw_name.trim());
        self.entries.push(Header {
            name: canonical,
            value: value.into().trim().to_string(),
        });
    }

    /// Inserts a header at the front of the list (used e.g. for adding top `Via`).
    pub fn push_front(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let raw_name = name.into();
        let canonical = canonical_header_name(raw_name.trim());
        self.entries.insert(
            0,
            Header {
                name: canonical,
                value: value.into().trim().to_string(),
            },
        );
    }

    /// Replaces all existing headers matching `name` with a single header.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let raw_name = name.into();
        let canonical = canonical_header_name(raw_name.trim());
        self.remove(&canonical);
        self.entries.push(Header {
            name: canonical,
            value: value.into().trim().to_string(),
        });
    }

    /// Removes all headers matching `name` (case-insensitive, supports compact names).
    pub fn remove(&mut self, name: &str) {
        let target = canonical_header_name(name.trim());
        self.entries
            .retain(|h| !h.name.eq_ignore_ascii_case(&target));
    }

    /// Returns the value of the first header matching `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        let target = canonical_header_name(name.trim());
        self.entries
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(&target))
            .map(|h| h.value.as_str())
    }

    /// Returns all header values matching `name` in wire order.
    pub fn get_all(&self, name: &str) -> Vec<&str> {
        let target = canonical_header_name(name.trim());
        self.entries
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(&target))
            .map(|h| h.value.as_str())
            .collect()
    }

    /// Iterates over all headers in order.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.entries.iter()
    }

    /// Returns `true` if there are no headers.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Normalizes compact SIP header forms (RFC 3261 Section 7.3.3 & 20) and standard casing.
pub fn canonical_header_name(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    match lower.as_str() {
        "v" | "via" => "Via".to_string(),
        "f" | "from" => "From".to_string(),
        "t" | "to" => "To".to_string(),
        "i" | "call-id" => "Call-ID".to_string(),
        "m" | "contact" => "Contact".to_string(),
        "l" | "content-length" => "Content-Length".to_string(),
        "c" | "content-type" => "Content-Type".to_string(),
        "k" | "supported" => "Supported".to_string(),
        "e" | "content-encoding" => "Content-Encoding".to_string(),
        "s" | "subject" => "Subject".to_string(),
        "o" | "event" => "Event".to_string(),
        "u" | "allow-events" => "Allow-Events".to_string(),
        "r" | "refer-to" => "Refer-To".to_string(),
        "b" | "referred-by" => "Referred-By".to_string(),
        "x" | "session-expires" => "Session-Expires".to_string(),
        "cseq" => "CSeq".to_string(),
        "max-forwards" => "Max-Forwards".to_string(),
        "expires" => "Expires".to_string(),
        "user-agent" => "User-Agent".to_string(),
        "allow" => "Allow".to_string(),
        "www-authenticate" => "WWW-Authenticate".to_string(),
        "proxy-authenticate" => "Proxy-Authenticate".to_string(),
        "authorization" => "Authorization".to_string(),
        "proxy-authorization" => "Proxy-Authorization".to_string(),
        "record-route" => "Record-Route".to_string(),
        "route" => "Route".to_string(),
        "require" => "Require".to_string(),
        "min-expires" => "Min-Expires".to_string(),
        _ => name.trim().to_string(),
    }
}

/// Typed `Via` header (RFC 3261 Section 20.42 + RFC 3581 `rport`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub protocol_name: String,
    pub protocol_version: String,
    pub transport: String,
    pub sent_by: String,
    pub branch: Option<String>,
    pub rport: Option<Option<u16>>,
    pub received: Option<String>,
    pub params: Vec<(String, Option<String>)>,
}

impl Via {
    /// Creates a standard `SIP/2.0/<transport> <sent_by>;branch=<branch>;rport` header.
    pub fn new(
        transport: impl Into<String>,
        sent_by: impl Into<String>,
        branch: impl Into<String>,
    ) -> Self {
        Self {
            protocol_name: "SIP".to_string(),
            protocol_version: "2.0".to_string(),
            transport: transport.into(),
            sent_by: sent_by.into(),
            branch: Some(branch.into()),
            rport: Some(None),
            received: None,
            params: Vec::new(),
        }
    }

    /// Parses a single `Via` entry.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let trimmed = input.trim();
        let mut semi_parts = trimmed.split(';');
        let main_part = semi_parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("empty Via header '{input}'")))?;

        let mut ws_parts = main_part.split_whitespace();
        let sent_protocol = ws_parts.next().ok_or_else(|| {
            SipError::ParseError(format!("missing sent-protocol in Via '{input}'"))
        })?;
        let sent_by = ws_parts
            .next()
            .ok_or_else(|| SipError::ParseError(format!("missing sent-by in Via '{input}'")))?;
        if ws_parts.next().is_some() {
            return Err(SipError::ParseError(format!(
                "unexpected tokens in Via '{input}'"
            )));
        }

        let mut proto_segs = sent_protocol.split('/');
        let protocol_name = proto_segs
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("invalid Via protocol '{sent_protocol}'")))?
            .to_string();
        let protocol_version = proto_segs
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("invalid Via version '{sent_protocol}'")))?
            .to_string();
        let transport = proto_segs
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SipError::ParseError(format!("invalid Via transport '{sent_protocol}'"))
            })?
            .to_string();
        if proto_segs.next().is_some() {
            return Err(SipError::ParseError(format!(
                "invalid Via protocol '{sent_protocol}'"
            )));
        }

        let mut via = Self {
            protocol_name,
            protocol_version,
            transport,
            sent_by: sent_by.to_string(),
            branch: None,
            rport: None,
            received: None,
            params: Vec::new(),
        };

        for raw_param in semi_parts {
            let p = raw_param.trim();
            if p.is_empty() {
                continue;
            }
            let (k, v) = match p.split_once('=') {
                Some((key, val)) => (key.trim(), Some(val.trim())),
                None => (p, None),
            };
            if k.eq_ignore_ascii_case("branch") {
                via.branch = Some(
                    v.ok_or_else(|| {
                        SipError::ParseError(format!("empty Via branch in '{input}'"))
                    })?
                    .to_string(),
                );
            } else if k.eq_ignore_ascii_case("rport") {
                via.rport = match v {
                    None => Some(None),
                    Some(port_str) => {
                        let port = port_str.parse::<u16>().map_err(|_| {
                            SipError::ParseError(format!("invalid Via rport '{port_str}'"))
                        })?;
                        Some(Some(port))
                    }
                };
            } else if k.eq_ignore_ascii_case("received") {
                via.received = v.map(str::to_string);
            } else {
                via.params.push((k.to_string(), v.map(str::to_string)));
            }
        }

        Ok(via)
    }

    /// Parses comma-separated `Via` entries from one header value.
    pub fn parse_list(input: &str) -> Result<Vec<Self>, SipError> {
        split_comma_respecting_quotes_and_angles(input)
            .into_iter()
            .filter(|item| !item.trim().is_empty())
            .map(Self::parse)
            .collect()
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{} {}",
            self.protocol_name, self.protocol_version, self.transport, self.sent_by
        )?;
        if let Some(branch) = &self.branch {
            write!(f, ";branch={branch}")?;
        }
        if let Some(rport) = self.rport {
            match rport {
                Some(port) => write!(f, ";rport={port}")?,
                None => f.write_str(";rport")?,
            }
        }
        if let Some(received) = &self.received {
            write!(f, ";received={received}")?;
        }
        for (k, v) in &self.params {
            match v {
                Some(val) => write!(f, ";{k}={val}")?,
                None => write!(f, ";{k}")?,
            }
        }
        Ok(())
    }
}

/// Typed `From` / `To` / `Contact` address specification (`[display] <uri>;params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAddr {
    pub display_name: Option<String>,
    pub uri: SipUri,
    pub tag: Option<String>,
    pub expires: Option<u32>,
    pub params: Vec<(String, Option<String>)>,
}

impl NameAddr {
    /// Creates a `NameAddr` from a URI with optional display name and tag.
    pub fn new(uri: SipUri) -> Self {
        Self {
            display_name: None,
            uri,
            tag: None,
            expires: None,
            params: Vec::new(),
        }
    }

    /// Sets the display name.
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets the `;tag=...` parameter.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Sets the `;expires=...` parameter.
    pub fn with_expires(mut self, expires: u32) -> Self {
        self.expires = Some(expires);
        self
    }

    /// Parses a `From`, `To`, `Contact`, or `Route` single address value.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(SipError::ParseError("empty NameAddr header".to_string()));
        }

        let (display_name, uri_str, raw_params) =
            if let Some(open_idx) = find_unquoted_char(trimmed, '<') {
                let before = trimmed[..open_idx].trim();
                let after_open = &trimmed[open_idx + 1..];
                let close_idx = after_open
                    .find('>')
                    .ok_or_else(|| SipError::ParseError(format!("unclosed '<' in '{trimmed}'")))?;
                let uri_part = after_open[..close_idx].trim();
                let params_part = after_open[close_idx + 1..].trim();
                let dn = parse_display_name(before)?;
                (dn, uri_part, params_part)
            } else {
                // Without angle brackets, RFC 3261 treats `;...` as header params.
                match trimmed.split_once(';') {
                    Some((uri_part, params_part)) => (None, uri_part.trim(), params_part.trim()),
                    None => (None, trimmed, ""),
                }
            };

        let uri = SipUri::parse(uri_str)?;
        let mut addr = Self {
            display_name,
            uri,
            tag: None,
            expires: None,
            params: Vec::new(),
        };

        for raw_param in raw_params.split(';') {
            let p = raw_param.trim();
            if p.is_empty() {
                continue;
            }
            let (k, v) = match p.split_once('=') {
                Some((key, val)) => (key.trim(), Some(val.trim())),
                None => (p, None),
            };
            if k.eq_ignore_ascii_case("tag") {
                let tag_val = v.ok_or_else(|| {
                    SipError::ParseError(format!("empty tag param in '{trimmed}'"))
                })?;
                addr.tag = Some(tag_val.to_string());
            } else if k.eq_ignore_ascii_case("expires") {
                let exp_str = v.ok_or_else(|| {
                    SipError::ParseError(format!("empty expires param in '{trimmed}'"))
                })?;
                let exp = exp_str.parse::<u32>().map_err(|_| {
                    SipError::ParseError(format!("invalid expires '{exp_str}' in '{trimmed}'"))
                })?;
                addr.expires = Some(exp);
            } else {
                addr.params.push((k.to_string(), v.map(str::to_string)));
            }
        }

        Ok(addr)
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(dn) = &self.display_name {
            let escaped = dn.replace('\\', "\\\\").replace('"', "\\\"");
            write!(f, "\"{escaped}\" ")?;
        }
        write!(f, "<{}>", self.uri)?;
        if let Some(tag) = &self.tag {
            write!(f, ";tag={tag}")?;
        }
        if let Some(expires) = self.expires {
            write!(f, ";expires={expires}")?;
        }
        for (k, v) in &self.params {
            match v {
                Some(val) => write!(f, ";{k}={val}")?,
                None => write!(f, ";{k}")?,
            }
        }
        Ok(())
    }
}

/// Typed `CSeq` header (`<seq> <METHOD>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeq {
    pub seq: u32,
    pub method: Method,
}

impl CSeq {
    /// Creates a new `CSeq`.
    pub fn new(seq: u32, method: Method) -> Self {
        Self { seq, method }
    }

    /// Parses `<seq> <METHOD>`.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let mut parts = input.split_whitespace();
        let seq_str = parts
            .next()
            .ok_or_else(|| SipError::ParseError(format!("empty CSeq '{input}'")))?;
        let method_str = parts
            .next()
            .ok_or_else(|| SipError::ParseError(format!("missing method in CSeq '{input}'")))?;
        if parts.next().is_some() {
            return Err(SipError::ParseError(format!(
                "trailing tokens in CSeq '{input}'"
            )));
        }
        let seq = seq_str
            .parse::<u32>()
            .map_err(|_| SipError::ParseError(format!("invalid CSeq number '{seq_str}'")))?;
        let method = Method::parse(method_str)?;
        Ok(Self { seq, method })
    }
}

impl fmt::Display for CSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.seq, self.method)
    }
}

fn find_unquoted_char(input: &str, target: char) -> Option<usize> {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes && ch == target {
            return Some(idx);
        }
    }
    None
}

fn parse_display_name(raw: &str) -> Result<Option<String>, SipError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.starts_with('"') {
        if !trimmed.ends_with('"') || trimmed.len() < 2 {
            return Err(SipError::ParseError(format!(
                "unterminated quoted display name '{trimmed}'"
            )));
        }
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for ch in inner.chars() {
            if escaped {
                out.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                out.push(ch);
            }
        }
        return Ok(Some(out));
    }
    Ok(Some(trimmed.to_string()))
}

pub(crate) fn split_comma_respecting_quotes_and_angles(input: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut angle_depth: usize = 0;

    for (idx, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes {
            match ch {
                '<' => angle_depth = angle_depth.saturating_add(1),
                '>' => angle_depth = angle_depth.saturating_sub(1),
                ',' if angle_depth == 0 => {
                    items.push(input[start..idx].trim());
                    start = idx + 1;
                }
                _ => {}
            }
        }
    }
    items.push(input[start..].trim());
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_compact_headers() {
        let mut headers = Headers::new();
        headers.add("v", "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1");
        headers.add("f", "\"Alice\" <sip:alice@example.com>;tag=a1");
        headers.add("t", "<sip:bob@example.com>");
        headers.add("i", "call-123");
        headers.add("m", "<sip:alice@10.0.0.1:5060>");
        headers.add("l", "0");

        assert_eq!(
            headers.get("Via"),
            Some("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1")
        );
        assert_eq!(headers.get("i"), Some("call-123"));
        assert_eq!(headers.get("Call-ID"), Some("call-123"));
        assert_eq!(headers.get("Content-Length"), Some("0"));
    }

    #[test]
    fn parses_via_with_rport_and_received() {
        let via = Via::parse(
            "SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKabc;rport=55123;received=203.0.113.7",
        )
        .unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.sent_by, "192.168.1.5:5060");
        assert_eq!(via.branch.as_deref(), Some("z9hG4bKabc"));
        assert_eq!(via.rport, Some(Some(55123)));
        assert_eq!(via.received.as_deref(), Some("203.0.113.7"));
        assert_eq!(
            via.to_string(),
            "SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bKabc;rport=55123;received=203.0.113.7"
        );
    }

    #[test]
    fn parses_name_addr_variants() {
        let quoted = NameAddr::parse(
            "\"Alice, Bob\" <sip:alice@example.com;transport=tcp>;tag=t1;expires=60",
        )
        .unwrap();
        assert_eq!(quoted.display_name.as_deref(), Some("Alice, Bob"));
        assert_eq!(quoted.uri.param("transport"), Some(Some("tcp")));
        assert_eq!(quoted.tag.as_deref(), Some("t1"));
        assert_eq!(quoted.expires, Some(60));

        let bare = NameAddr::parse("sip:bob@example.com;tag=t2").unwrap();
        assert_eq!(bare.display_name, None);
        assert_eq!(bare.uri.host, "example.com");
        assert_eq!(bare.tag.as_deref(), Some("t2"));
        assert!(bare.uri.params.is_empty());
    }

    #[test]
    fn parses_cseq() {
        let cseq = CSeq::parse("42 INVITE").unwrap();
        assert_eq!(cseq.seq, 42);
        assert_eq!(cseq.method, Method::Invite);
        assert_eq!(cseq.to_string(), "42 INVITE");
    }
}
