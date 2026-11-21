//! MODULE_CONTRACT: HTTP/SIP Digest challenge parser (`DigestChallenge`) and response generator (`DigestCredentials`).
//! INVARIANTS: Supports `MD5`, `MD5-sess`, `SHA-256`, `SHA-256-sess`, `qop=auth`, and legacy no-`qop` challenges; `-sess` and `qop=auth` fail explicitly if `cnonce` is absent.
//! RFC_REFS: RFC 2617, RFC 3261 Section 22, RFC 7616.

pub mod hash;

use crate::error::SipError;
use crate::sip::method::Method;

/// Digest hash algorithm per RFC 2617 & RFC 7616.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DigestAlgorithm {
    #[default]
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
}

impl DigestAlgorithm {
    /// Returns the wire `algorithm=` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
        }
    }

    fn parse(input: &str) -> Result<Self, SipError> {
        let lower = input.trim().to_ascii_lowercase();
        match lower.as_str() {
            "md5" => Ok(Self::Md5),
            "md5-sess" => Ok(Self::Md5Sess),
            "sha-256" => Ok(Self::Sha256),
            "sha-256-sess" => Ok(Self::Sha256Sess),
            _ => Err(SipError::AuthError(format!(
                "unsupported digest algorithm '{input}'"
            ))),
        }
    }

    fn hash_hex(self, input: &str) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => hash::md5_hex(input.as_bytes()),
            Self::Sha256 | Self::Sha256Sess => hash::sha256_hex(input.as_bytes()),
        }
    }

    fn is_sess(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess)
    }
}

/// Parsed `WWW-Authenticate` or `Proxy-Authenticate` Digest challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: DigestAlgorithm,
    pub qop: Vec<String>,
    pub stale: bool,
}

impl DigestChallenge {
    /// Parses a `Digest ...` challenge header value.
    pub fn parse(header_value: &str) -> Result<Self, SipError> {
        let trimmed = header_value.trim();
        let rest = strip_digest_scheme(trimmed).ok_or_else(|| {
            SipError::AuthError(format!("challenge does not use Digest scheme: '{trimmed}'"))
        })?;

        let pairs = parse_auth_params(rest)?;
        let mut realm: Option<String> = None;
        let mut nonce: Option<String> = None;
        let mut opaque: Option<String> = None;
        let mut algorithm = DigestAlgorithm::Md5;
        let mut qop: Vec<String> = Vec::new();
        let mut stale = false;

        for (k, v) in pairs {
            if k.eq_ignore_ascii_case("realm") {
                realm = Some(v);
            } else if k.eq_ignore_ascii_case("nonce") {
                nonce = Some(v);
            } else if k.eq_ignore_ascii_case("opaque") {
                opaque = Some(v);
            } else if k.eq_ignore_ascii_case("algorithm") {
                algorithm = DigestAlgorithm::parse(&v)?;
            } else if k.eq_ignore_ascii_case("qop") {
                qop = v
                    .split(',')
                    .map(|item| item.trim().to_ascii_lowercase())
                    .filter(|item| !item.is_empty())
                    .collect();
            } else if k.eq_ignore_ascii_case("stale") {
                stale = v.eq_ignore_ascii_case("true");
            }
        }

        let realm = realm.ok_or_else(|| SipError::AuthError("missing realm".to_string()))?;
        let nonce = nonce.ok_or_else(|| SipError::AuthError("missing nonce".to_string()))?;

        Ok(Self {
            realm,
            nonce,
            opaque,
            algorithm,
            qop,
            stale,
        })
    }
}

/// User credentials and client nonce state for computing a Digest response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestCredentials {
    pub username: String,
    pub password: String,
    pub cnonce: Option<String>,
    pub nc: u32,
}

impl DigestCredentials {
    /// Creates credentials with `nc = 1` and optional client nonce.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        cnonce: Option<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            cnonce,
            nc: 1,
        }
    }

    /// Computes an `Authorization` / `Proxy-Authorization` header value for a challenge.
    pub fn authorize(
        &self,
        challenge: &DigestChallenge,
        method: &Method,
        digest_uri: &str,
    ) -> Result<String, SipError> {
        let use_qop_auth = if challenge.qop.is_empty() {
            false
        } else if challenge.qop.iter().any(|q| q == "auth") {
            true
        } else {
            return Err(SipError::AuthError(format!(
                "unsupported qop options: {:?}",
                challenge.qop
            )));
        };

        let mut ha1 = challenge.algorithm.hash_hex(&format!(
            "{}:{}:{}",
            self.username, challenge.realm, self.password
        ));

        if challenge.algorithm.is_sess() {
            if !use_qop_auth {
                return Err(SipError::AuthError(
                    "-sess algorithms require qop=auth".to_string(),
                ));
            }
            let cnonce = self.cnonce.as_deref().ok_or_else(|| {
                SipError::AuthError("cnonce is required for -sess algorithms".to_string())
            })?;
            ha1 = challenge
                .algorithm
                .hash_hex(&format!("{ha1}:{}:{cnonce}", challenge.nonce));
        }

        let ha2 = challenge
            .algorithm
            .hash_hex(&format!("{}:{}", method.as_str(), digest_uri));

        let (response, nc_hex, cnonce_used) = if use_qop_auth {
            let cnonce = self.cnonce.as_deref().ok_or_else(|| {
                SipError::AuthError("cnonce is required when qop=auth is used".to_string())
            })?;
            let nc_str = format!("{:08x}", self.nc);
            let digest = challenge.algorithm.hash_hex(&format!(
                "{ha1}:{}:{nc_str}:{cnonce}:auth:{ha2}",
                challenge.nonce
            ));
            (digest, Some(nc_str), Some(cnonce))
        } else {
            let digest = challenge
                .algorithm
                .hash_hex(&format!("{ha1}:{}:{ha2}", challenge.nonce));
            (digest, None, None)
        };

        let mut header = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\", algorithm={}",
            escape_quoted(&self.username),
            escape_quoted(&challenge.realm),
            escape_quoted(&challenge.nonce),
            escape_quoted(digest_uri),
            response,
            challenge.algorithm.as_str()
        );

        if let (Some(nc_str), Some(cnonce)) = (nc_hex, cnonce_used) {
            header.push_str(&format!(
                ", qop=auth, nc={nc_str}, cnonce=\"{}\"",
                escape_quoted(cnonce)
            ));
        }

        if let Some(opaque) = &challenge.opaque {
            header.push_str(&format!(", opaque=\"{}\"", escape_quoted(opaque)));
        }

        Ok(header)
    }
}

fn strip_digest_scheme(input: &str) -> Option<&str> {
    let prefix = input.get(..6)?;
    let rest = input.get(6..)?;
    if prefix.eq_ignore_ascii_case("digest") && rest.starts_with(char::is_whitespace) {
        Some(rest.trim())
    } else {
        None
    }
}

fn parse_auth_params(input: &str) -> Result<Vec<(String, String)>, SipError> {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            return Err(SipError::AuthError(format!(
                "malformed auth parameter in '{input}'"
            )));
        }
        let key = input[key_start..i].trim().to_string();
        i += 1; // skip '='

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        let value = if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let mut val = String::new();
            let mut escaped = false;
            let mut closed = false;
            while i < input.len() {
                let ch = input[i..]
                    .chars()
                    .next()
                    .ok_or_else(|| SipError::AuthError("unexpected end".to_string()))?;
                i += ch.len_utf8();
                if escaped {
                    val.push(ch);
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    closed = true;
                    break;
                } else {
                    val.push(ch);
                }
            }
            if !closed {
                return Err(SipError::AuthError(format!(
                    "unterminated quoted auth value for '{key}'"
                )));
            }
            val
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            input[val_start..i].trim().to_string()
        };

        out.push((key, value));
    }

    Ok(out)
}

fn escape_quoted(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_challenge_and_computes_rfc2617_and_sha256_responses() {
        // RFC 2617 Section 3.5 example-style MD5 qop=auth verification
        let challenge = DigestChallenge::parse(
            "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", algorithm=MD5",
        )
        .unwrap();
        assert_eq!(challenge.realm, "testrealm@host.com");
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5);
        assert_eq!(challenge.qop, vec!["auth", "auth-int"]);

        let creds =
            DigestCredentials::new("Mufasa", "Circle Of Life", Some("0a4f113b".to_string()));
        let auth = creds
            .authorize(&challenge, &Method::Register, "sip:testrealm@host.com")
            .unwrap();

        // Manually verify MD5 computation
        let ha1 = hash::md5_hex(b"Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = hash::md5_hex(b"REGISTER:sip:testrealm@host.com");
        let expected_resp = hash::md5_hex(
            format!("{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}")
                .as_bytes(),
        );
        assert!(auth.contains(&format!("response=\"{expected_resp}\"")));
        assert!(auth.contains("qop=auth, nc=00000001, cnonce=\"0a4f113b\""));
        assert!(auth.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""));

        // SHA-256 verification
        let sha_challenge = DigestChallenge::parse(
            "Digest realm=\"asterisk\", nonce=\"abc123\", algorithm=SHA-256, qop=\"auth\"",
        )
        .unwrap();
        let sha_creds = DigestCredentials::new("100", "secret", Some("deadbeef".to_string()));
        let sha_auth = sha_creds
            .authorize(&sha_challenge, &Method::Invite, "sip:200@asterisk")
            .unwrap();
        let sha_ha1 = hash::sha256_hex(b"100:asterisk:secret");
        let sha_ha2 = hash::sha256_hex(b"INVITE:sip:200@asterisk");
        let sha_resp = hash::sha256_hex(
            format!("{sha_ha1}:abc123:00000001:deadbeef:auth:{sha_ha2}").as_bytes(),
        );
        assert!(sha_auth.contains("algorithm=SHA-256"));
        assert!(sha_auth.contains(&format!("response=\"{sha_resp}\"")));
    }

    #[test]
    fn supports_legacy_digest_without_qop() {
        let challenge =
            DigestChallenge::parse("Digest realm=\"pbx.local\", nonce=\"nonce1\"").unwrap();
        let creds = DigestCredentials::new("alice", "pass", None);
        let auth = creds
            .authorize(&challenge, &Method::Register, "sip:pbx.local")
            .unwrap();
        let ha1 = hash::md5_hex(b"alice:pbx.local:pass");
        let ha2 = hash::md5_hex(b"REGISTER:sip:pbx.local");
        let expected = hash::md5_hex(format!("{ha1}:nonce1:{ha2}").as_bytes());
        assert!(auth.contains(&format!("response=\"{expected}\"")));
        assert!(!auth.contains("qop="));
    }

    #[test]
    fn sess_algorithms_require_qop_auth() {
        let md5_sess_no_qop =
            DigestChallenge::parse("Digest realm=\"pbx.local\", nonce=\"n1\", algorithm=MD5-sess")
                .unwrap();
        let creds = DigestCredentials::new("alice", "pass", Some("cn1".to_string()));
        assert!(creds
            .authorize(&md5_sess_no_qop, &Method::Register, "sip:pbx.local")
            .is_err());

        let sha_sess_no_qop = DigestChallenge::parse(
            "Digest realm=\"pbx.local\", nonce=\"n1\", algorithm=SHA-256-sess",
        )
        .unwrap();
        assert!(creds
            .authorize(&sha_sess_no_qop, &Method::Invite, "sip:bob@pbx.local")
            .is_err());

        let sha_sess_qop = DigestChallenge::parse(
            "Digest realm=\"pbx.local\", nonce=\"n1\", algorithm=SHA-256-sess, qop=\"auth\"",
        )
        .unwrap();
        assert!(creds
            .authorize(&sha_sess_qop, &Method::Invite, "sip:bob@pbx.local")
            .is_ok());
    }
}
