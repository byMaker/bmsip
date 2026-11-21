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
        "rseq" => "RSeq".to_string(),
        "rack" => "RAck".to_string(),
        "min-se" => "Min-SE".to_string(),
        "replaces" => "Replaces".to_string(),
        "reason" => "Reason".to_string(),
        "privacy" => "Privacy".to_string(),
        "p-asserted-identity" => "P-Asserted-Identity".to_string(),
        "p-preferred-identity" => "P-Preferred-Identity".to_string(),
        "remote-party-id" => "Remote-Party-ID".to_string(),
        "subscription-state" => "Subscription-State".to_string(),
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
        let semi_parts = split_unquoted(trimmed, ';');
        let mut semi_iter = semi_parts.into_iter();
        let main_part = semi_iter
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("empty Via header '{input}'")))?;

        let mut slash_parts = main_part.splitn(3, '/');
        let protocol_name = slash_parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.chars().any(char::is_whitespace))
            .ok_or_else(|| SipError::ParseError(format!("invalid Via protocol '{main_part}'")))?
            .to_string();
        let protocol_version = slash_parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.chars().any(char::is_whitespace))
            .ok_or_else(|| SipError::ParseError(format!("invalid Via version '{main_part}'")))?
            .to_string();
        let transport_and_sent = slash_parts
            .next()
            .map(str::trim_start)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("invalid Via transport '{main_part}'")))?;

        let split_ws = transport_and_sent
            .char_indices()
            .find(|(_, ch)| ch.is_whitespace())
            .map(|(idx, _)| idx)
            .ok_or_else(|| SipError::ParseError(format!("missing sent-by in Via '{input}'")))?;
        let transport = transport_and_sent[..split_ws].trim();
        if transport.is_empty() || transport.contains('/') {
            return Err(SipError::ParseError(format!(
                "invalid Via transport '{transport}' in '{input}'"
            )));
        }
        let sent_by = collapse_colon_lws(transport_and_sent[split_ws..].trim())?;

        let mut via = Self {
            protocol_name,
            protocol_version,
            transport: transport.to_string(),
            sent_by,
            branch: None,
            rport: None,
            received: None,
            params: Vec::new(),
        };

        for raw_param in semi_iter {
            let p = raw_param.trim();
            if p.is_empty() {
                continue;
            }
            let (k, v) = match p.split_once('=') {
                Some((key, val)) => (key.trim(), Some(unquote_sip_string(val.trim()))),
                None => (p, None),
            };
            if k.eq_ignore_ascii_case("branch") {
                let branch_val = v.filter(|s| !s.is_empty()).ok_or_else(|| {
                    SipError::ParseError(format!("empty Via branch in '{input}'"))
                })?;
                via.branch = Some(branch_val);
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
                via.received = v;
            } else {
                via.params.push((k.to_string(), v));
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

        for raw_param in split_unquoted(raw_params, ';') {
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

    /// Parses comma-separated address specifications from a single header value.
    pub fn parse_list(input: &str) -> Result<Vec<Self>, SipError> {
        split_unquoted(input, ',')
            .into_iter()
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(Self::parse)
            .collect()
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

/// Typed `Replaces` header (RFC 3891) for attended call transfer dialog replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacesHeader {
    pub call_id: String,
    pub to_tag: String,
    pub from_tag: String,
    pub early_only: bool,
}

impl ReplacesHeader {
    /// Creates a `ReplacesHeader` identifying an existing dialog to replace.
    pub fn new(
        call_id: impl Into<String>,
        to_tag: impl Into<String>,
        from_tag: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            to_tag: to_tag.into(),
            from_tag: from_tag.into(),
            early_only: false,
        }
    }

    /// Sets the `early-only` parameter (RFC 3891 §3).
    pub fn with_early_only(mut self, early_only: bool) -> Self {
        self.early_only = early_only;
        self
    }

    /// Parses a URI-percent-encoded `Replaces` value (`?Replaces=...`).
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let decoded = percent_decode(input.trim());
        Self::parse_raw(&decoded, input)
    }

    /// Parses a standalone SIP `Replaces:` header value without percent-decoding `Call-ID` or tags.
    pub fn parse_header_value(input: &str) -> Result<Self, SipError> {
        Self::parse_raw(input.trim(), input)
    }

    fn parse_raw(raw: &str, orig_input: &str) -> Result<Self, SipError> {
        let parts = split_unquoted(raw, ';');
        let mut iter = parts.into_iter();
        let call_id = iter
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                SipError::ParseError(format!("missing call-id in Replaces '{orig_input}'"))
            })?
            .to_string();

        let mut to_tag: Option<String> = None;
        let mut from_tag: Option<String> = None;
        let mut early_only = false;

        for raw_param in iter {
            let p = raw_param.trim();
            if p.is_empty() {
                continue;
            }
            match p.split_once('=') {
                Some((k, v)) => {
                    let key = k.trim();
                    let val = unquote_sip_string(v.trim());
                    if key.eq_ignore_ascii_case("to-tag") {
                        to_tag = Some(val);
                    } else if key.eq_ignore_ascii_case("from-tag") {
                        from_tag = Some(val);
                    }
                }
                None => {
                    if p.eq_ignore_ascii_case("early-only") {
                        early_only = true;
                    }
                }
            }
        }

        let to_tag = to_tag.filter(|s| !s.is_empty()).ok_or_else(|| {
            SipError::ParseError(format!("missing to-tag in Replaces '{orig_input}'"))
        })?;
        let from_tag = from_tag.filter(|s| !s.is_empty()).ok_or_else(|| {
            SipError::ParseError(format!("missing from-tag in Replaces '{orig_input}'"))
        })?;

        Ok(Self {
            call_id,
            to_tag,
            from_tag,
            early_only,
        })
    }

    /// Encodes the `Replaces` value for safe inclusion inside a `Refer-To` URI `?Replaces=` header parameter.
    pub fn to_uri_escaped(&self) -> String {
        let raw = self.to_string();
        let mut out = String::with_capacity(raw.len() + 16);
        for b in raw.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char);
                }
                _ => {
                    use std::fmt::Write as _;
                    let _ = write!(out, "%{b:02X}");
                }
            }
        }
        out
    }
}

impl fmt::Display for ReplacesHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{};to-tag={};from-tag={}",
            self.call_id, self.to_tag, self.from_tag
        )?;
        if self.early_only {
            f.write_str(";early-only")?;
        }
        Ok(())
    }
}

/// Refresher role for RFC 4028 SIP Session Timers (`uac` or `uas`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRefresher {
    Uac,
    Uas,
}

impl SessionRefresher {
    /// Returns the wire `refresher=` parameter value (`"uac"` or `"uas"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uac => "uac",
            Self::Uas => "uas",
        }
    }
}

impl fmt::Display for SessionRefresher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed `Session-Expires` header (RFC 4028).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExpires {
    pub delta_seconds: u32,
    pub refresher: Option<SessionRefresher>,
}

impl SessionExpires {
    /// Creates a `Session-Expires` value with interval in seconds and optional refresher role.
    pub fn new(delta_seconds: u32, refresher: Option<SessionRefresher>) -> Self {
        Self {
            delta_seconds,
            refresher,
        }
    }

    /// Parses `<delta-seconds>[;refresher=uac|uas]`.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let mut parts = input.trim().split(';');
        let delta_str = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("empty Session-Expires '{input}'")))?;
        let delta_seconds = delta_str.parse::<u32>().map_err(|_| {
            SipError::ParseError(format!("invalid Session-Expires delta '{delta_str}'"))
        })?;

        let mut refresher = None;
        for param in parts {
            let p = param.trim();
            if let Some((k, v)) = p.split_once('=') {
                if k.trim().eq_ignore_ascii_case("refresher") {
                    let role = v.trim();
                    if role.eq_ignore_ascii_case("uac") {
                        refresher = Some(SessionRefresher::Uac);
                    } else if role.eq_ignore_ascii_case("uas") {
                        refresher = Some(SessionRefresher::Uas);
                    } else {
                        return Err(SipError::ParseError(format!(
                            "invalid Session-Expires refresher '{role}'"
                        )));
                    }
                }
            }
        }

        Ok(Self {
            delta_seconds,
            refresher,
        })
    }
}

impl fmt::Display for SessionExpires {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.delta_seconds)?;
        if let Some(r) = self.refresher {
            write!(f, ";refresher={r}")?;
        }
        Ok(())
    }
}

/// Typed `RAck` header (RFC 3262 §7.2) acknowledging a reliable provisional `1xx` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAck {
    pub rseq: u32,
    pub cseq: u32,
    pub method: Method,
}

impl RAck {
    /// Creates a `RAck` header referencing `RSeq`, `CSeq` number, and method (typically `INVITE`).
    pub fn new(rseq: u32, cseq: u32, method: Method) -> Self {
        Self { rseq, cseq, method }
    }

    /// Parses `<rseq> <cseq> <METHOD>`.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let mut parts = input.split_whitespace();
        let rseq_str = parts
            .next()
            .ok_or_else(|| SipError::ParseError(format!("empty RAck '{input}'")))?;
        let cseq_str = parts
            .next()
            .ok_or_else(|| SipError::ParseError(format!("missing cseq in RAck '{input}'")))?;
        let method_str = parts
            .next()
            .ok_or_else(|| SipError::ParseError(format!("missing method in RAck '{input}'")))?;
        if parts.next().is_some() {
            return Err(SipError::ParseError(format!(
                "trailing tokens in RAck '{input}'"
            )));
        }
        let rseq = rseq_str
            .parse::<u32>()
            .map_err(|_| SipError::ParseError(format!("invalid RAck rseq '{rseq_str}'")))?;
        let cseq = cseq_str
            .parse::<u32>()
            .map_err(|_| SipError::ParseError(format!("invalid RAck cseq '{cseq_str}'")))?;
        let method = Method::parse(method_str)?;
        Ok(Self { rseq, cseq, method })
    }
}

impl fmt::Display for RAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.rseq, self.cseq, self.method)
    }
}

/// Typed `Reason` header (RFC 3326) carrying SIP or ITU-T Q.850 release cause and reason text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasonHeader {
    pub protocol: String,
    pub cause: Option<u16>,
    pub text: Option<String>,
}

impl ReasonHeader {
    /// Creates an ITU-T `Q.850` `Reason` header (e.g., `Q.850;cause=16;text="Normal call clearing"`).
    pub fn q850(cause: u16, text: impl Into<String>) -> Self {
        Self {
            protocol: "Q.850".to_string(),
            cause: Some(cause),
            text: Some(text.into()),
        }
    }

    /// Creates a `SIP` `Reason` header (e.g., `SIP;cause=200;text="Call completed elsewhere"`).
    pub fn sip(cause: u16, text: impl Into<String>) -> Self {
        Self {
            protocol: "SIP".to_string(),
            cause: Some(cause),
            text: Some(text.into()),
        }
    }

    /// Parses `<protocol>[;cause=<u16>][;text="..."]`.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let trimmed = input.trim();
        let mut parts = split_unquoted(trimmed, ';').into_iter();
        let protocol = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SipError::ParseError(format!("empty Reason header '{input}'")))?
            .to_string();

        let mut cause = None;
        let mut text = None;
        for param in parts {
            let p = param.trim();
            if let Some((k, v)) = p.split_once('=') {
                let key = k.trim();
                let val = v.trim();
                if key.eq_ignore_ascii_case("cause") {
                    cause = val.parse::<u16>().ok();
                } else if key.eq_ignore_ascii_case("text") {
                    text = Some(unquote_sip_string(val));
                }
            }
        }

        Ok(Self {
            protocol,
            cause,
            text,
        })
    }
}

impl fmt::Display for ReasonHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.protocol)?;
        if let Some(c) = self.cause {
            write!(f, ";cause={c}")?;
        }
        if let Some(t) = &self.text {
            let escaped = t.replace('\\', "\\\\").replace('"', "\\\"");
            write!(f, ";text=\"{escaped}\"")?;
        }
        Ok(())
    }
}

/// Caller identity & privacy metadata extracted from `P-Asserted-Identity` / `Remote-Party-ID` / `Privacy` (RFC 3323 & RFC 3325).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    pub asserted_identity: Option<NameAddr>,
    pub privacy: Vec<String>,
}

impl CallerIdentity {
    /// Extracts caller identity and privacy tokens from SIP `Headers`, if any are present.
    pub fn from_headers(headers: &Headers) -> Option<Self> {
        let asserted_identity = [
            "P-Asserted-Identity",
            "P-Preferred-Identity",
            "Remote-Party-ID",
        ]
        .into_iter()
        .flat_map(|hdr| headers.get_all(hdr))
        .flat_map(|raw| split_unquoted(raw, ','))
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .find_map(|item| NameAddr::parse(item).ok());

        let mut privacy = Vec::new();
        for raw in headers.get_all("Privacy") {
            for tok in raw.split([';', ',']) {
                let t = tok.trim();
                if !t.is_empty() {
                    privacy.push(t.to_string());
                }
            }
        }

        if asserted_identity.is_none() && privacy.is_empty() {
            None
        } else {
            Some(Self {
                asserted_identity,
                privacy,
            })
        }
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn split_unquoted(input: &str, delim: char) -> Vec<&str> {
    let mut out = Vec::new();
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
            if ch == '<' {
                angle_depth = angle_depth.saturating_add(1);
                continue;
            }
            if ch == '>' {
                angle_depth = angle_depth.saturating_sub(1);
                continue;
            }
            if angle_depth == 0 && ch == delim {
                out.push(&input[start..idx]);
                start = idx + delim.len_utf8();
            }
        }
    }
    out.push(&input[start..]);
    out
}

fn collapse_colon_lws(input: &str) -> Result<String, SipError> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    if tokens.is_empty() {
        return Err(SipError::ParseError("empty Via sent-by".to_string()));
    }
    let mut out = tokens[0].to_string();
    for tok in &tokens[1..] {
        if out.ends_with(':') || tok.starts_with(':') {
            out.push_str(tok);
        } else {
            return Err(SipError::ParseError(format!(
                "unexpected tokens in Via sent-by '{input}'"
            )));
        }
    }
    Ok(out)
}

fn unquote_sip_string(val: &str) -> String {
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        let inner = &val[1..val.len() - 1];
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
        out
    } else {
        val.to_string()
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
    split_unquoted(input, ',')
        .into_iter()
        .map(str::trim)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::SipScheme;

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

    #[test]
    fn parses_call_control_headers_replaces_session_expires_rack_reason_and_identity() {
        let rep = ReplacesHeader::new("cid-1@10.0.0.1", "to-t", "from-t").with_early_only(true);
        assert_eq!(
            rep.to_string(),
            "cid-1@10.0.0.1;to-tag=to-t;from-tag=from-t;early-only"
        );
        let escaped = rep.to_uri_escaped();
        assert_eq!(ReplacesHeader::parse(&escaped).unwrap(), rep);
        assert_eq!(ReplacesHeader::parse(&rep.to_string()).unwrap(), rep);

        let se = SessionExpires::parse("1800;refresher=uas").unwrap();
        assert_eq!(se.delta_seconds, 1800);
        assert_eq!(se.refresher, Some(SessionRefresher::Uas));
        assert_eq!(se.to_string(), "1800;refresher=uas");

        let rack = RAck::parse("7 3 INVITE").unwrap();
        assert_eq!(rack.rseq, 7);
        assert_eq!(rack.cseq, 3);
        assert_eq!(rack.method, Method::Invite);
        assert_eq!(rack.to_string(), "7 3 INVITE");

        let reason = ReasonHeader::parse("Q.850;cause=16;text=\"Normal call clearing\"").unwrap();
        assert_eq!(reason.protocol, "Q.850");
        assert_eq!(reason.cause, Some(16));
        assert_eq!(reason.text.as_deref(), Some("Normal call clearing"));
        assert_eq!(
            reason.to_string(),
            "Q.850;cause=16;text=\"Normal call clearing\""
        );

        let mut hdrs = Headers::new();
        hdrs.set("P-Asserted-Identity", "\"CEO\" <sip:1001@pbx.local>");
        hdrs.set("Privacy", "id;header");
        let ci = CallerIdentity::from_headers(&hdrs).unwrap();
        assert_eq!(
            ci.asserted_identity.unwrap().uri,
            SipUri::parse("sip:1001@pbx.local").unwrap()
        );
        assert_eq!(ci.privacy, vec!["id".to_string(), "header".to_string()]);
    }

    #[test]
    fn parses_via_lws_quoted_params_tel_identity_and_raw_replaces_header() {
        let via =
            Via::parse("SIP / 2.0 / UDP 10.0.0.1 : 5060;branch=\"z9hG4bK1\";received=\"10.0.0.1\"")
                .unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.sent_by, "10.0.0.1:5060");
        assert_eq!(via.branch.as_deref(), Some("z9hG4bK1"));
        assert_eq!(via.received.as_deref(), Some("10.0.0.1"));

        let na = NameAddr::parse("<tel:+1-555-0199>;foo=\"a;b\";tag=t9").unwrap();
        assert_eq!(na.uri.scheme, SipScheme::Tel);
        assert_eq!(na.uri.user.as_deref(), Some("+1-555-0199"));
        assert_eq!(na.tag.as_deref(), Some("t9"));
        assert_eq!(
            na.params,
            vec![("foo".to_string(), Some("\"a;b\"".to_string()))]
        );

        // Raw Replaces header values must NOT percent-decode literal `%` sequences in Call-ID.
        let rep = ReplacesHeader::parse_header_value(
            "call%40host;to-tag=t1;from-tag=f1;early-only;custom=1",
        )
        .unwrap();
        assert_eq!(rep.call_id, "call%40host");
        assert_eq!(rep.to_tag, "t1");
        assert_eq!(rep.from_tag, "f1");
        assert!(rep.early_only);

        let mut hdrs = Headers::new();
        hdrs.add("P-Asserted-Identity", "\"Tel\" <tel:+15550100>");
        hdrs.add("P-Asserted-Identity", "<sip:1001@pbx.local>");
        let ci = CallerIdentity::from_headers(&hdrs).unwrap();
        assert_eq!(ci.asserted_identity.unwrap().uri.scheme, SipScheme::Tel);
    }
}
