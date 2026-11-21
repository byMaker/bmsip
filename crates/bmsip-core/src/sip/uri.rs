//! MODULE_CONTRACT: `sip:` and `sips:` URI parser and formatter supporting IPv4/IPv6 hosts, parameters, and URI headers.
//! INVARIANTS: Scheme matching is ASCII case-insensitive; host and port boundaries are validated prior to serialization.
//! RFC_REFS: RFC 3261 Section 19.1, Section 25.1.

use std::fmt;
use std::str::FromStr;

use crate::error::SipError;

/// URI scheme for SIP/telephony addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipScheme {
    Sip,
    Sips,
    Tel,
}

impl SipScheme {
    /// Returns the lowercase wire scheme name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sip => "sip",
            Self::Sips => "sips",
            Self::Tel => "tel",
        }
    }
}

impl fmt::Display for SipScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Semicolon-delimited SIP URI parameter (`;name` or `;name=value`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UriParam {
    pub name: String,
    pub value: Option<String>,
}

/// Parsed SIP or SIPS URI per RFC 3261 Section 19.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SipUri {
    pub scheme: SipScheme,
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<UriParam>,
    pub headers: Vec<(String, String)>,
}

impl SipUri {
    /// Creates a `sip:<host>` URI.
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            scheme: SipScheme::Sip,
            user: None,
            password: None,
            host: host.into(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
        }
    }

    /// Attaches a userinfo username to this URI.
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Sets an explicit destination port on this URI.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Appends a URI parameter (`;name` or `;name=value`).
    pub fn with_param(mut self, name: impl Into<String>, value: Option<String>) -> Self {
        self.params.push(UriParam {
            name: name.into(),
            value,
        });
        self
    }

    /// Looks up a URI parameter case-insensitively.
    pub fn param(&self, name: &str) -> Option<Option<&str>> {
        self.params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .map(|p| p.value.as_deref())
    }

    /// Parses a `sip:`, `sips:`, or RFC 3966 `tel:` URI string.
    pub fn parse(input: &str) -> Result<Self, SipError> {
        let trimmed = input.trim();
        if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "tel:") {
            let mut parts = rest.split(';');
            let subscriber = parts
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    SipError::InvalidUri(format!("empty tel subscriber in '{trimmed}'"))
                })?;
            if subscriber.chars().any(char::is_whitespace) || subscriber.contains('?') {
                return Err(SipError::InvalidUri(format!(
                    "invalid tel subscriber '{subscriber}' in '{trimmed}'"
                )));
            }
            let mut params = Vec::new();
            for raw_param in parts {
                let p = raw_param.trim();
                if p.is_empty() {
                    continue;
                }
                match p.split_once('=') {
                    Some((k, v)) => params.push(UriParam {
                        name: k.trim().to_string(),
                        value: Some(v.trim().to_string()),
                    }),
                    None => params.push(UriParam {
                        name: p.to_string(),
                        value: None,
                    }),
                }
            }
            return Ok(Self {
                scheme: SipScheme::Tel,
                user: Some(subscriber.to_string()),
                password: None,
                host: String::new(),
                port: None,
                params,
                headers: Vec::new(),
            });
        }

        let (scheme, rest) = if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "sips:") {
            (SipScheme::Sips, rest)
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(trimmed, "sip:") {
            (SipScheme::Sip, rest)
        } else {
            return Err(SipError::InvalidUri(format!(
                "missing sip/sips/tel scheme in '{trimmed}'"
            )));
        };

        // Per RFC 3261 §19.1.1 / §25.1, userinfo may contain `;` parameters (e.g.
        // `sip:5551234;phone-context=+1-212@example.com;user=phone`), whereas URI headers after
        // `?` may contain `@` inside header values (e.g. `?Replaces=cid@10.0.0.1`).
        // Treat `@` as the userinfo delimiter only when it precedes `?` or when no `=` appears
        // between `?` and `@`.
        let has_userinfo = match (rest.find('@'), rest.find('?')) {
            (Some(_), None) => true,
            (Some(at), Some(q)) => at < q || !rest[q + 1..at].contains('='),
            (None, _) => false,
        };

        let (user, password, after_userinfo) = if has_userinfo {
            match rest.split_once('@') {
                Some((userinfo, after)) => {
                    if userinfo.is_empty() {
                        return Err(SipError::InvalidUri(format!(
                            "empty userinfo before '@' in '{trimmed}'"
                        )));
                    }
                    let (u, p) = match userinfo.split_once(':') {
                        Some((user, pass)) => (Some(user.to_string()), Some(pass.to_string())),
                        None => (Some(userinfo.to_string()), None),
                    };
                    (u, p, after)
                }
                None => (None, None, rest),
            }
        } else {
            (None, None, rest)
        };

        let (before_headers, headers_part) = match after_userinfo.split_once('?') {
            Some((left, right)) => (left, Some(right)),
            None => (after_userinfo, None),
        };

        let mut parts = before_headers.split(';');
        let hostport = parts
            .next()
            .ok_or_else(|| SipError::InvalidUri("empty authority".to_string()))?;

        let (host, port) = parse_hostport(hostport)?;

        let mut params = Vec::new();
        for raw_param in parts {
            let p = raw_param.trim();
            if p.is_empty() {
                continue;
            }
            let (name, value) = match p.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), Some(v.trim().to_string())),
                None => (p.to_string(), None),
            };
            params.push(UriParam { name, value });
        }

        let mut headers = Vec::new();
        if let Some(raw_headers) = headers_part {
            for pair in raw_headers.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = pair.split_once('=').ok_or_else(|| {
                    SipError::InvalidUri(format!("malformed URI header '{pair}' in '{trimmed}'"))
                })?;
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        Ok(Self {
            scheme,
            user,
            password,
            host,
            port,
            params,
            headers,
        })
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if self.scheme == SipScheme::Tel {
            if let Some(sub) = &self.user {
                f.write_str(sub)?;
            }
            for param in &self.params {
                match &param.value {
                    Some(val) => write!(f, ";{}={val}", param.name)?,
                    None => write!(f, ";{}", param.name)?,
                }
            }
            return Ok(());
        }
        if let Some(user) = &self.user {
            f.write_str(user)?;
            if let Some(pass) = &self.password {
                write!(f, ":{pass}")?;
            }
            f.write_str("@")?;
        }
        f.write_str(&self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        for param in &self.params {
            match &param.value {
                Some(val) => write!(f, ";{}={val}", param.name)?,
                None => write!(f, ";{}", param.name)?,
            }
        }
        if !self.headers.is_empty() {
            f.write_str("?")?;
            for (idx, (k, v)) in self.headers.iter().enumerate() {
                if idx > 0 {
                    f.write_str("&")?;
                }
                write!(f, "{k}={v}")?;
            }
        }
        Ok(())
    }
}

impl FromStr for SipUri {
    type Err = SipError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn parse_hostport(hostport: &str) -> Result<(String, Option<u16>), SipError> {
    let hp = hostport.trim();
    if hp.is_empty() {
        return Err(SipError::InvalidUri("empty host".to_string()));
    }
    if hp.starts_with('[') {
        let close = hp
            .find(']')
            .ok_or_else(|| SipError::InvalidUri(format!("unclosed IPv6 bracket in '{hp}'")))?;
        let host = &hp[..=close];
        let after = &hp[close + 1..];
        if after.is_empty() {
            return Ok((host.to_string(), None));
        }
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| SipError::InvalidUri(format!("invalid IPv6 hostport '{hp}'")))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| SipError::InvalidUri(format!("invalid port '{port_str}'")))?;
        return Ok((host.to_string(), Some(port)));
    }

    match hp.split_once(':') {
        Some((host, port_str)) => {
            if host.is_empty() || port_str.contains(':') {
                return Err(SipError::InvalidUri(format!("invalid hostport '{hp}'")));
            }
            let port = port_str
                .parse::<u16>()
                .map_err(|_| SipError::InvalidUri(format!("invalid port '{port_str}'")))?;
            Ok((host.to_string(), Some(port)))
        }
        None => Ok((hp.to_string(), None)),
    }
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        input.get(prefix.len()..)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_sip_uri_and_roundtrips() {
        let raw = "SIP:alice@atlanta.example.com:5060;transport=udp;lr?Subject=call";
        let uri = SipUri::parse(raw).unwrap();
        assert_eq!(uri.scheme, SipScheme::Sip);
        assert_eq!(uri.user.as_deref(), Some("alice"));
        assert_eq!(uri.host, "atlanta.example.com");
        assert_eq!(uri.port, Some(5060));
        assert_eq!(uri.param("transport"), Some(Some("udp")));
        assert_eq!(uri.param("lr"), Some(None));
        assert_eq!(
            uri.headers,
            vec![("Subject".to_string(), "call".to_string())]
        );
        assert_eq!(
            uri.to_string(),
            "sip:alice@atlanta.example.com:5060;transport=udp;lr?Subject=call"
        );
    }

    #[test]
    fn parses_ipv6_sips_uri() {
        let uri = SipUri::parse("sips:bob@[2001:db8::1]:5061;transport=tls").unwrap();
        assert_eq!(uri.scheme, SipScheme::Sips);
        assert_eq!(uri.host, "[2001:db8::1]");
        assert_eq!(uri.port, Some(5061));
    }

    #[test]
    fn rejects_invalid_uris() {
        assert!(SipUri::parse("http://example.com").is_err());
        assert!(SipUri::parse("sip:").is_err());
        assert!(SipUri::parse("sip:@example.com").is_err());
        assert!(SipUri::parse("sip:example.com:99999").is_err());
    }

    #[test]
    fn parses_userinfo_with_semicolon_params_and_headers_with_at() {
        let uri1 = SipUri::parse("sip:alice;day=tue@atlanta.com").unwrap();
        assert_eq!(uri1.user.as_deref(), Some("alice;day=tue"));
        assert_eq!(uri1.host, "atlanta.com");
        assert!(uri1.params.is_empty());

        let uri2 =
            SipUri::parse("sip:5551234;phone-context=+1-212@example.com;user=phone").unwrap();
        assert_eq!(uri2.user.as_deref(), Some("5551234;phone-context=+1-212"));
        assert_eq!(uri2.host, "example.com");
        assert_eq!(uri2.param("user"), Some(Some("phone")));

        let uri3 = SipUri::parse("sip:10.0.0.2:5062?Replaces=cid@10.0.0.1").unwrap();
        assert_eq!(uri3.user, None);
        assert_eq!(uri3.host, "10.0.0.2");
        assert_eq!(uri3.port, Some(5062));
        assert_eq!(
            uri3.headers,
            vec![("Replaces".to_string(), "cid@10.0.0.1".to_string())]
        );
    }

    #[test]
    fn parses_tel_uri_with_parameters_and_roundtrips() {
        let uri = SipUri::parse("TEL:+1-555-0100;phone-context=+1;isub=123").unwrap();
        assert_eq!(uri.scheme, SipScheme::Tel);
        assert_eq!(uri.user.as_deref(), Some("+1-555-0100"));
        assert!(uri.host.is_empty());
        assert_eq!(uri.port, None);
        assert_eq!(uri.param("phone-context"), Some(Some("+1")));
        assert_eq!(uri.param("isub"), Some(Some("123")));
        assert_eq!(uri.to_string(), "tel:+1-555-0100;phone-context=+1;isub=123");
        assert!(SipUri::parse("tel:").is_err());
        assert!(SipUri::parse("tel:;phone-context=+1").is_err());
    }
}
