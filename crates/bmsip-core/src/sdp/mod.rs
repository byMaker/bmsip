//! MODULE_CONTRACT: Audio SDP session parser/formatter (`SdpSession`), RFC 4568 SDES (`a=crypto:`) attributes, and RFC 3264 Offer/Answer negotiator.
//! INVARIANTS: Populates static RTP payload types (`0` PCMU, `8` PCMA, `3` GSM, `9` G722, `13` CN) if `a=rtpmap` is omitted; `negotiate_offer_answer` preserves offerer payload type numbers and requires at least one non-DTMF/non-CN audio codec; rejects unsupported SDES MKI parameters and wipes SDES key material on drop.
//! RFC_REFS: RFC 3264 Section 6.1, RFC 3551, RFC 3711, RFC 4566, RFC 4568.

use std::fmt;

use crate::auth::hash::{hmac_sha256, sha256, zeroize_bytes};
use crate::error::SipError;

/// SDP `m=audio` transport protocol profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SdpMediaProfile {
    /// Standard unencrypted RTP (`RTP/AVP` or `RTP/AVPF`).
    #[default]
    RtpAvp,
    /// SRTP with SDES key exchange (`RTP/SAVP` or `RTP/SAVPF`, RFC 3711 / RFC 4568).
    RtpSavp,
    /// DTLS-SRTP (`UDP/TLS/RTP/SAVP` or `UDP/TLS/RTP/SAVPF`, RFC 5763 / RFC 5764).
    UdpTlsRtpSavp,
}

impl SdpMediaProfile {
    /// Returns the canonical SDP `m=audio` transport token.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RtpAvp => "RTP/AVP",
            Self::RtpSavp => "RTP/SAVP",
            Self::UdpTlsRtpSavp => "UDP/TLS/RTP/SAVP",
        }
    }

    /// Parses an SDP `m=audio` transport protocol token.
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "RTP/AVP" | "RTP/AVPF" => Ok(Self::RtpAvp),
            "RTP/SAVP" | "RTP/SAVPF" => Ok(Self::RtpSavp),
            "UDP/TLS/RTP/SAVP" | "UDP/TLS/RTP/SAVPF" => Ok(Self::UdpTlsRtpSavp),
            _ => Err(SipError::InvalidSdp(format!(
                "unsupported SDP media transport profile '{raw}'"
            ))),
        }
    }

    /// Returns `true` if the profile requires SRTP media encryption.
    pub fn is_secure(self) -> bool {
        matches!(self, Self::RtpSavp | Self::UdpTlsRtpSavp)
    }
}

impl fmt::Display for SdpMediaProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Supported RFC 3711 / RFC 4568 / RFC 5764 SRTP cryptographic suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SrtpSuite {
    /// AES-128 Counter Mode encryption with 80-bit (10-byte) HMAC-SHA1 authentication tag.
    #[default]
    AesCm128HmacSha1_80,
    /// AES-128 Counter Mode encryption with 32-bit (4-byte) RTP HMAC-SHA1 tag (80-bit SRTCP tag).
    AesCm128HmacSha1_32,
}

impl SrtpSuite {
    /// Canonical RFC 4568 SDES crypto-suite identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
        }
    }

    /// Parses an RFC 4568 SDES or RFC 5764 DTLS-SRTP suite name.
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "AES_CM_128_HMAC_SHA1_80" | "SRTP_AES128_CM_SHA1_80" => Ok(Self::AesCm128HmacSha1_80),
            "AES_CM_128_HMAC_SHA1_32" | "SRTP_AES128_CM_SHA1_32" => Ok(Self::AesCm128HmacSha1_32),
            _ => Err(SipError::InvalidSdp(format!(
                "unsupported SRTP crypto suite '{raw}'"
            ))),
        }
    }

    /// Returns the SRTP authentication tag length in bytes (`10` for `_80`, `4` for `_32`).
    pub fn rtp_auth_tag_len(self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 => 10,
            Self::AesCm128HmacSha1_32 => 4,
        }
    }

    /// Returns the SRTCP authentication tag length in bytes (`10` for both suites per RFC 3711 §5.2).
    pub fn rtcp_auth_tag_len(self) -> usize {
        10
    }
}

impl fmt::Display for SrtpSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 4568 SDP Security Descriptions (`a=crypto:<tag> <suite> inline:<base64>`) attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesCryptoAttr {
    pub tag: u32,
    pub suite: SrtpSuite,
    /// Concatenated 16-byte SRTP master key and 14-byte SRTP master salt (30 bytes total).
    pub key_salt: [u8; 30],
}

impl SdesCryptoAttr {
    /// Creates an [`SdesCryptoAttr`] from explicit tag, suite, and 30-byte `master_key || master_salt`.
    pub fn new(tag: u32, suite: SrtpSuite, key_salt: [u8; 30]) -> Self {
        Self {
            tag,
            suite,
            key_salt,
        }
    }

    /// Deterministically derives a 30-byte `master_key || master_salt` from an injected seed using SHA-256.
    pub fn from_seed(tag: u32, suite: SrtpSuite, seed: &[u8]) -> Self {
        let mut digest = sha256(seed);
        let mut key_salt = [0u8; 30];
        key_salt.copy_from_slice(&digest[..30]);
        zeroize_bytes(&mut digest);
        Self {
            tag,
            suite,
            key_salt,
        }
    }

    /// Derives a 30-byte `master_key || master_salt` using HMAC-SHA256 over a 256-bit CSPRNG secret and domain-separated context.
    pub fn derive_from_secret(
        tag: u32,
        suite: SrtpSuite,
        secret: &[u8; 32],
        context: &[u8],
    ) -> Self {
        let mut mac = hmac_sha256(secret, context);
        let mut key_salt = [0u8; 30];
        key_salt.copy_from_slice(&mac[..30]);
        zeroize_bytes(&mut mac);
        Self {
            tag,
            suite,
            key_salt,
        }
    }

    /// Returns the 16-byte SRTP master key.
    pub fn master_key(&self) -> [u8; 16] {
        let mut k = [0u8; 16];
        k.copy_from_slice(&self.key_salt[..16]);
        k
    }

    /// Returns the 14-byte SRTP master salt.
    pub fn master_salt(&self) -> [u8; 14] {
        let mut s = [0u8; 14];
        s.copy_from_slice(&self.key_salt[16..30]);
        s
    }

    /// Encodes the 30-byte `key_salt` as a 40-character RFC 4648 Base64 string.
    pub fn inline_base64(&self) -> String {
        base64_encode(&self.key_salt)
    }

    /// Parses an `a=crypto:` value (after `"crypto:"`), e.g. `"1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20"`.
    ///
    /// Rejects lines that negotiate an RFC 4568 Master Key Identifier (`MKI`, `<value>:<length>`) because
    /// wire SRTP MKI trailers are not supported, allowing callers to fall back to a non-MKI candidate.
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        let mut parts = raw.split_whitespace();
        let tag_str = parts
            .next()
            .ok_or_else(|| SipError::InvalidSdp(format!("missing tag in a=crypto:{raw}")))?;
        let tag = tag_str
            .parse::<u32>()
            .map_err(|_| SipError::InvalidSdp(format!("invalid crypto tag '{tag_str}'")))?;
        let suite_str = parts
            .next()
            .ok_or_else(|| SipError::InvalidSdp(format!("missing suite in a=crypto:{raw}")))?;
        let suite = SrtpSuite::parse(suite_str)?;

        let mut key_param: Option<&str> = None;
        for token in parts {
            if let Some(rest) = strip_prefix_ci(token, "inline:") {
                key_param = Some(rest);
                break;
            }
        }
        let inline_raw = key_param.ok_or_else(|| {
            SipError::InvalidSdp(format!("missing inline: key parameter in a=crypto:{raw}"))
        })?;
        // RFC 4568 §6.1: multiple key-params may be separated by ';'; inspect the primary inline parameter.
        let primary_param = inline_raw.split(';').next().unwrap_or(inline_raw);
        let mut pipe_parts = primary_param.split('|');
        let b64_part = pipe_parts.next().unwrap_or("").trim();
        for trailing in pipe_parts {
            let trimmed = trailing.trim();
            if trimmed.contains(':') {
                return Err(SipError::InvalidSdp(format!(
                    "unsupported SDES MKI parameter '{trimmed}' in a=crypto:{raw}"
                )));
            }
        }
        let mut decoded = base64_decode(b64_part)?;
        if decoded.len() != 30 {
            zeroize_bytes(&mut decoded);
            return Err(SipError::InvalidSdp(format!(
                "SDES inline key+salt length mismatch: expected 30 bytes, got {}",
                decoded.len()
            )));
        }
        let mut key_salt = [0u8; 30];
        key_salt.copy_from_slice(&decoded[..30]);
        zeroize_bytes(&mut decoded);
        Ok(Self {
            tag,
            suite,
            key_salt,
        })
    }
}

impl Drop for SdesCryptoAttr {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.key_salt);
    }
}

impl fmt::Display for SdesCryptoAttr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} inline:{}",
            self.tag,
            self.suite,
            self.inline_base64()
        )
    }
}

/// RFC 4145 / RFC 5763 DTLS-SRTP connection setup role (`a=setup:`).
#[cfg(feature = "experimental-dtls")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DtlsSetupRole {
    /// Offerer accepts either active (client) or passive (server) role (`actpass`).
    #[default]
    ActPass,
    /// Endpoint initiates the DTLS client handshake (`active`).
    Active,
    /// Endpoint waits for the DTLS client handshake (`passive`).
    Passive,
}

#[cfg(feature = "experimental-dtls")]
impl DtlsSetupRole {
    /// Returns the SDP `a=setup:` attribute value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ActPass => "actpass",
            Self::Active => "active",
            Self::Passive => "passive",
        }
    }

    /// Parses an `a=setup:` attribute value (`"actpass"`, `"active"`, `"passive"`).
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "actpass" => Ok(Self::ActPass),
            "active" => Ok(Self::Active),
            "passive" => Ok(Self::Passive),
            _ => Err(SipError::InvalidSdp(format!(
                "unsupported SDP a=setup role '{raw}'"
            ))),
        }
    }

    /// Computes the complementary answer role per RFC 5763 Section 5.
    pub fn answer_role(self) -> Self {
        match self {
            Self::ActPass | Self::Passive => Self::Active,
            Self::Active => Self::Passive,
        }
    }
}

#[cfg(feature = "experimental-dtls")]
impl fmt::Display for DtlsSetupRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RFC 4572 / RFC 5763 certificate fingerprint (`a=fingerprint:<hash> <hex>`).
#[cfg(feature = "experimental-dtls")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsFingerprint {
    pub hash_func: String,
    pub fingerprint: String,
}

#[cfg(feature = "experimental-dtls")]
impl DtlsFingerprint {
    /// Computes an RFC 4572 `"sha-256"` fingerprint (`AA:BB:CC:...`) over a DER-encoded X.509 certificate.
    pub fn sha256_from_der(cert_der: &[u8]) -> Self {
        let digest = sha256(cert_der);
        let mut fp = String::with_capacity(32 * 3 - 1);
        for (i, byte) in digest.iter().enumerate() {
            if i > 0 {
                fp.push(':');
            }
            let _ = fmt::Write::write_fmt(&mut fp, format_args!("{byte:02X}"));
        }
        Self {
            hash_func: "sha-256".to_string(),
            fingerprint: fp,
        }
    }

    /// Parses an `a=fingerprint:` value (after `"fingerprint:"`), e.g. `"sha-256 AA:BB:..."`.
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        let trimmed = raw.trim();
        let (hash, hex_part) = trimmed
            .split_once(char::is_whitespace)
            .ok_or_else(|| SipError::InvalidSdp(format!("malformed a=fingerprint:{raw}")))?;
        let hash_func = hash.trim().to_ascii_lowercase();
        let fingerprint = hex_part.trim().to_ascii_uppercase();
        if hash_func.is_empty() || fingerprint.len() < 14 || !fingerprint.contains(':') {
            return Err(SipError::InvalidSdp(format!(
                "invalid certificate fingerprint in a=fingerprint:{raw}"
            )));
        }
        Ok(Self {
            hash_func,
            fingerprint,
        })
    }

    /// Performs case-insensitive comparison of hash function and normalized hex fingerprint bytes.
    pub fn matches(&self, other: &Self) -> bool {
        self.hash_func.eq_ignore_ascii_case(&other.hash_func)
            && self
                .fingerprint
                .trim()
                .eq_ignore_ascii_case(other.fingerprint.trim())
    }
}

#[cfg(feature = "experimental-dtls")]
impl fmt::Display for DtlsFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.hash_func, self.fingerprint)
    }
}

/// User Agent SRTP media encryption policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SrtpMode {
    /// Plain RTP (`RTP/AVP`); secure `RTP/SAVP` / `UDP/TLS/RTP/SAVP` offers are rejected.
    #[default]
    Disabled,
    /// Offers `RTP/AVP` with opportunistic `a=crypto:` (over TLS) and accepts either plain `RTP/AVP` or `RTP/SAVP` SDES.
    SdesOptional,
    /// Offers `RTP/SAVP` with mandatory RFC 4568 `a=crypto:` SDES key exchange (requires SIP over TLS by default).
    SdesRequired,
}

impl SrtpMode {
    /// Parses `"disabled"`/`"off"`/`"none"`, `"sdes-optional"`/`"optional"`, or `"sdes"`/`"sdes-required"`/`"required"`.
    pub fn parse(raw: &str) -> Result<Self, SipError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "disabled" | "off" | "none" => Ok(Self::Disabled),
            "sdes-optional" | "optional" => Ok(Self::SdesOptional),
            "sdes" | "sdes-required" | "required" => Ok(Self::SdesRequired),
            _ => Err(SipError::ParseError(format!(
                "unsupported SRTP mode '{raw}' (expected off, optional, or sdes)"
            ))),
        }
    }
}

/// Negotiated SRTP security parameters for an active call dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiatedSrtp {
    /// RFC 4568 SDES key pair (`local_key_salt` encrypts outbound TX; `remote_key_salt` decrypts inbound RX).
    Sdes {
        suite: SrtpSuite,
        local_key_salt: [u8; 30],
        remote_key_salt: [u8; 30],
    },
}

impl Drop for NegotiatedSrtp {
    fn drop(&mut self) {
        match self {
            Self::Sdes {
                local_key_salt,
                remote_key_salt,
                ..
            } => {
                zeroize_bytes(local_key_salt);
                zeroize_bytes(remote_key_salt);
            }
        }
    }
}

/// Media stream direction attribute (RFC 3264 / RFC 4566).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    /// Returns the SDP `a=<dir>` attribute string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SendRecv => "sendrecv",
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::Inactive => "inactive",
        }
    }

    /// Computes the complementary SDP answer direction per RFC 3264 Section 6.1.
    pub fn answer_direction(self) -> Self {
        match self {
            Self::SendRecv => Self::SendRecv,
            Self::SendOnly => Self::RecvOnly,
            Self::RecvOnly => Self::SendOnly,
            Self::Inactive => Self::Inactive,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// RTP audio codec entry described in `m=audio` / `a=rtpmap` / `a=fmtp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpCodec {
    pub payload_type: u8,
    pub encoding_name: String,
    pub clock_rate: u32,
    pub channels: Option<u8>,
    pub fmtp: Option<String>,
}

impl RtpCodec {
    /// G.711 mu-law (PCMU, static payload type 0, 8000 Hz).
    pub fn pcmu() -> Self {
        Self {
            payload_type: 0,
            encoding_name: "PCMU".to_string(),
            clock_rate: 8000,
            channels: None,
            fmtp: None,
        }
    }

    /// G.711 A-law (PCMA, static payload type 8, 8000 Hz).
    pub fn pcma() -> Self {
        Self {
            payload_type: 8,
            encoding_name: "PCMA".to_string(),
            clock_rate: 8000,
            channels: None,
            fmtp: None,
        }
    }

    /// ITU-T G.722 16 kHz wideband audio codec (static payload type 9, 8000 Hz RTP clock per RFC 3551 §4.5.2).
    pub fn g722() -> Self {
        Self {
            payload_type: 9,
            encoding_name: "G722".to_string(),
            clock_rate: 8000,
            channels: None,
            fmtp: None,
        }
    }

    /// RFC 3389 Comfort Noise (static payload type 13, 8000 Hz RTP clock).
    pub fn cn() -> Self {
        Self {
            payload_type: 13,
            encoding_name: "CN".to_string(),
            clock_rate: 8000,
            channels: None,
            fmtp: None,
        }
    }

    /// Opus audio codec (typical dynamic PT 111, 48000 Hz, 2 channels).
    pub fn opus() -> Self {
        Self {
            payload_type: 111,
            encoding_name: "opus".to_string(),
            clock_rate: 48000,
            channels: Some(2),
            fmtp: Some("minptime=10;useinbandfec=1".to_string()),
        }
    }

    /// RFC 4733 DTMF telephone-event codec (typically PT 101, 8000 Hz).
    pub fn telephone_event(payload_type: u8) -> Self {
        Self {
            payload_type,
            encoding_name: "telephone-event".to_string(),
            clock_rate: 8000,
            channels: None,
            fmtp: Some("0-16".to_string()),
        }
    }

    /// RFC 4733 DTMF telephone-event codec synchronized to 48000 Hz RTP clocks (e.g., with Opus).
    pub fn telephone_event_48k(payload_type: u8) -> Self {
        Self {
            payload_type,
            encoding_name: "telephone-event".to_string(),
            clock_rate: 48000,
            channels: None,
            fmtp: Some("0-16".to_string()),
        }
    }

    fn matches_format(&self, other: &Self) -> bool {
        self.encoding_name
            .eq_ignore_ascii_case(&other.encoding_name)
            && self.clock_rate == other.clock_rate
            && self.channels.unwrap_or(1) == other.channels.unwrap_or(1)
    }

    fn is_telephone_event(&self) -> bool {
        self.encoding_name.eq_ignore_ascii_case("telephone-event")
    }

    /// Returns `true` if this entry represents RFC 3389 Comfort Noise (`CN`, PT 13).
    pub fn is_comfort_noise(&self) -> bool {
        self.encoding_name.eq_ignore_ascii_case("CN") || self.payload_type == 13
    }
}

/// Parsed or constructed SDP audio session (RFC 4566).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpSession {
    pub origin_username: String,
    pub session_id: String,
    pub session_version: String,
    pub connection_ip: String,
    pub audio_port: u16,
    pub profile: SdpMediaProfile,
    pub direction: Direction,
    pub codecs: Vec<RtpCodec>,
    pub ptime: Option<u32>,
    pub crypto: Vec<SdesCryptoAttr>,
    pub rtcp_port: Option<u16>,
    pub rtcp_ip: Option<String>,
    pub rtcp_mux: bool,
}

impl SdpSession {
    /// Creates a new audio SDP session with `RTP/AVP`, `sendrecv` direction, and 20 ms ptime.
    pub fn new(
        origin_username: impl Into<String>,
        session_id: impl Into<String>,
        connection_ip: impl Into<String>,
        audio_port: u16,
        codecs: Vec<RtpCodec>,
    ) -> Self {
        let sid = session_id.into();
        Self {
            origin_username: origin_username.into(),
            session_id: sid.clone(),
            session_version: sid,
            connection_ip: connection_ip.into(),
            audio_port,
            profile: SdpMediaProfile::RtpAvp,
            direction: Direction::SendRecv,
            codecs,
            ptime: Some(20),
            crypto: Vec::new(),
            rtcp_port: None,
            rtcp_ip: None,
            rtcp_mux: false,
        }
    }

    /// Parses an SDP session description containing an `m=audio` media block.
    pub fn parse(text: &str) -> Result<Self, SipError> {
        let mut saw_version = false;
        let mut origin_username = "-".to_string();
        let mut session_id = "0".to_string();
        let mut session_version = "0".to_string();
        let mut session_ip: Option<String> = None;

        let mut in_audio_section = false;
        let mut saw_audio = false;
        let mut audio_port: u16 = 0;
        let mut profile = SdpMediaProfile::RtpAvp;
        let mut audio_ip: Option<String> = None;
        let mut payload_types: Vec<u8> = Vec::new();
        let mut direction = Direction::SendRecv;
        let mut ptime: Option<u32> = None;
        let mut rtpmaps: Vec<(u8, String, u32, Option<u8>)> = Vec::new();
        let mut fmtps: Vec<(u8, String)> = Vec::new();
        let mut crypto: Vec<SdesCryptoAttr> = Vec::new();
        let mut rtcp_port: Option<u16> = None;
        let mut rtcp_ip: Option<String> = None;
        let mut rtcp_mux = false;

        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }
            let (kind, value) = line
                .split_once('=')
                .ok_or_else(|| SipError::InvalidSdp(format!("malformed SDP line '{line}'")))?;
            if kind.len() != 1 {
                return Err(SipError::InvalidSdp(format!("invalid SDP key '{kind}'")));
            }

            match kind {
                "v" => {
                    if value.trim() != "0" {
                        return Err(SipError::InvalidSdp(format!(
                            "unsupported SDP version '{value}'"
                        )));
                    }
                    saw_version = true;
                }
                "o" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() < 6 {
                        return Err(SipError::InvalidSdp(format!(
                            "malformed SDP origin 'o={value}'"
                        )));
                    }
                    origin_username = parts[0].to_string();
                    session_id = parts[1].to_string();
                    session_version = parts[2].to_string();
                }
                "c" => {
                    let ip = parse_connection_ip(value)?;
                    if in_audio_section {
                        audio_ip = Some(ip);
                    } else if !saw_audio {
                        session_ip = Some(ip);
                    }
                }
                "m" => {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() < 4 {
                        return Err(SipError::InvalidSdp(format!(
                            "malformed SDP media line 'm={value}'"
                        )));
                    }
                    if parts[0].eq_ignore_ascii_case("audio") {
                        in_audio_section = true;
                        saw_audio = true;
                        let port_token = parts[1].split('/').next().unwrap_or(parts[1]);
                        audio_port = port_token.parse::<u16>().map_err(|_| {
                            SipError::InvalidSdp(format!("invalid audio port '{port_token}'"))
                        })?;
                        profile = SdpMediaProfile::parse(parts[2])?;
                        for pt_str in &parts[3..] {
                            let pt = pt_str.parse::<u8>().map_err(|_| {
                                SipError::InvalidSdp(format!("invalid RTP payload type '{pt_str}'"))
                            })?;
                            payload_types.push(pt);
                        }
                    } else {
                        in_audio_section = false;
                    }
                }
                "a" => {
                    let attr = value.trim();
                    if attr.eq_ignore_ascii_case("sendrecv") {
                        if in_audio_section || !saw_audio {
                            direction = Direction::SendRecv;
                        }
                    } else if attr.eq_ignore_ascii_case("sendonly") {
                        if in_audio_section || !saw_audio {
                            direction = Direction::SendOnly;
                        }
                    } else if attr.eq_ignore_ascii_case("recvonly") {
                        if in_audio_section || !saw_audio {
                            direction = Direction::RecvOnly;
                        }
                    } else if attr.eq_ignore_ascii_case("inactive") {
                        if in_audio_section || !saw_audio {
                            direction = Direction::Inactive;
                        }
                    } else if in_audio_section {
                        if let Some(rest) = strip_prefix_ci(attr, "rtpmap:") {
                            let (pt, name, rate, ch) = parse_rtpmap(rest)?;
                            rtpmaps.push((pt, name, rate, ch));
                        } else if let Some(rest) = strip_prefix_ci(attr, "fmtp:") {
                            let (pt, params) = parse_fmtp(rest)?;
                            fmtps.push((pt, params));
                        } else if let Some(rest) = strip_prefix_ci(attr, "ptime:") {
                            let val = rest.trim().parse::<u32>().map_err(|_| {
                                SipError::InvalidSdp(format!("invalid ptime '{rest}'"))
                            })?;
                            ptime = Some(val);
                        } else if let Some(rest) = strip_prefix_ci(attr, "crypto:") {
                            if let Ok(c) = SdesCryptoAttr::parse(rest) {
                                crypto.push(c);
                            }
                        } else if attr.eq_ignore_ascii_case("rtcp-mux") {
                            rtcp_mux = true;
                        } else if let Some(rest) = strip_prefix_ci(attr, "rtcp:") {
                            let parts: Vec<&str> = rest.split_whitespace().collect();
                            if let Some(port) = parts.first().and_then(|p| p.parse::<u16>().ok()) {
                                if port > 0 {
                                    rtcp_port = Some(port);
                                    if parts.len() >= 4
                                        && parts[1].eq_ignore_ascii_case("IN")
                                        && (parts[2].eq_ignore_ascii_case("IP4")
                                            || parts[2].eq_ignore_ascii_case("IP6"))
                                    {
                                        if let Some(ip) =
                                            parts[3].split('/').next().filter(|s| !s.is_empty())
                                        {
                                            rtcp_ip = Some(ip.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if !saw_version {
            return Err(SipError::InvalidSdp("missing SDP v=0 line".to_string()));
        }
        if !saw_audio {
            return Err(SipError::InvalidSdp("missing SDP m=audio line".to_string()));
        }
        let connection_ip = audio_ip
            .or(session_ip)
            .ok_or_else(|| SipError::InvalidSdp("missing SDP c= connection line".to_string()))?;

        let mut codecs = Vec::with_capacity(payload_types.len());
        for pt in payload_types {
            let fmtp = fmtps
                .iter()
                .find(|(p, _)| *p == pt)
                .map(|(_, params)| params.clone());

            if let Some((_, name, rate, channels)) = rtpmaps.iter().find(|(p, _, _, _)| *p == pt) {
                codecs.push(RtpCodec {
                    payload_type: pt,
                    encoding_name: name.clone(),
                    clock_rate: *rate,
                    channels: *channels,
                    fmtp,
                });
            } else if let Some((name, rate)) = static_audio_codec(pt) {
                codecs.push(RtpCodec {
                    payload_type: pt,
                    encoding_name: name.to_string(),
                    clock_rate: rate,
                    channels: None,
                    fmtp,
                });
            }
        }

        Ok(Self {
            origin_username,
            session_id,
            session_version,
            connection_ip,
            audio_port,
            profile,
            direction,
            codecs,
            ptime,
            crypto,
            rtcp_port,
            rtcp_ip,
            rtcp_mux,
        })
    }
}

impl fmt::Display for SdpSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr_type = if self.connection_ip.contains(':') {
            "IP6"
        } else {
            "IP4"
        };
        write!(f, "v=0\r\n")?;
        write!(
            f,
            "o={} {} {} IN {addr_type} {}\r\n",
            self.origin_username, self.session_id, self.session_version, self.connection_ip
        )?;
        write!(f, "s=bmsip\r\n")?;
        write!(f, "c=IN {addr_type} {}\r\n", self.connection_ip)?;
        write!(f, "t=0 0\r\n")?;

        write!(f, "m=audio {} {}", self.audio_port, self.profile)?;
        for codec in &self.codecs {
            write!(f, " {}", codec.payload_type)?;
        }
        write!(f, "\r\n")?;

        for codec in &self.codecs {
            if let Some(ch) = codec.channels {
                write!(
                    f,
                    "a=rtpmap:{} {}/{}/{ch}\r\n",
                    codec.payload_type, codec.encoding_name, codec.clock_rate
                )?;
            } else {
                write!(
                    f,
                    "a=rtpmap:{} {}/{}\r\n",
                    codec.payload_type, codec.encoding_name, codec.clock_rate
                )?;
            }
            if let Some(fmtp) = &codec.fmtp {
                write!(f, "a=fmtp:{} {fmtp}\r\n", codec.payload_type)?;
            }
        }

        for c in &self.crypto {
            write!(f, "a=crypto:{c}\r\n")?;
        }

        if let Some(rp) = self.rtcp_port {
            if let Some(rip) = &self.rtcp_ip {
                let rtcp_addr_type = if rip.contains(':') { "IP6" } else { "IP4" };
                write!(f, "a=rtcp:{rp} IN {rtcp_addr_type} {rip}\r\n")?;
            } else {
                write!(f, "a=rtcp:{rp}\r\n")?;
            }
        }
        if self.rtcp_mux {
            write!(f, "a=rtcp-mux\r\n")?;
        }

        if let Some(ptime) = self.ptime {
            write!(f, "a=ptime:{ptime}\r\n")?;
        }
        write!(f, "a={}\r\n", self.direction)?;
        Ok(())
    }
}

/// Performs RFC 3264 Offer/Answer codec and direction negotiation for plain `RTP/AVP` audio.
///
/// Selects matching audio codecs (using the offer's RTP payload type numbers per RFC 3264),
/// preserves matching `telephone-event` DTMF support, and derives the complementary direction.
pub fn negotiate_offer_answer(
    offer: &SdpSession,
    local_supported: &[RtpCodec],
    local_ip: &str,
    local_port: u16,
) -> Result<(SdpSession, Vec<RtpCodec>), SipError> {
    let (answer, negotiated, _) = negotiate_offer_answer_with_srtp(
        offer,
        local_supported,
        local_ip,
        local_port,
        SrtpMode::Disabled,
        &[],
    )?;
    Ok((answer, negotiated))
}

/// Performs RFC 3264 + RFC 4568 (SDES) Offer/Answer negotiation.
pub fn negotiate_offer_answer_with_srtp(
    offer: &SdpSession,
    local_supported: &[RtpCodec],
    local_ip: &str,
    local_port: u16,
    srtp_mode: SrtpMode,
    local_sdes_candidates: &[SdesCryptoAttr],
) -> Result<(SdpSession, Vec<RtpCodec>, Option<NegotiatedSrtp>), SipError> {
    if offer.audio_port == 0 {
        return Err(SipError::InvalidSdp(
            "offer disabled audio stream with port 0".to_string(),
        ));
    }

    let mut negotiated = Vec::new();
    let mut has_real_audio = false;

    for offered in &offer.codecs {
        if let Some(local) = local_supported.iter().find(|c| c.matches_format(offered)) {
            if !offered.is_telephone_event() && !offered.is_comfort_noise() {
                has_real_audio = true;
            }
            // RFC 3264: answer MUST use the payload type number sent by the offerer.
            negotiated.push(RtpCodec {
                payload_type: offered.payload_type,
                encoding_name: offered.encoding_name.clone(),
                clock_rate: offered.clock_rate,
                channels: offered.channels.or(local.channels),
                fmtp: offered.fmtp.clone().or_else(|| local.fmtp.clone()),
            });
        }
    }

    if !has_real_audio {
        return Err(SipError::InvalidSdp(
            "no common audio codecs between offer and local capabilities".to_string(),
        ));
    }

    if offer.profile == SdpMediaProfile::UdpTlsRtpSavp {
        return Err(SipError::InvalidSdp(
            "DTLS-SRTP (UDP/TLS/RTP/SAVP) is not supported".to_string(),
        ));
    }

    let (profile, answer_crypto, negotiated_srtp) = match srtp_mode {
        SrtpMode::Disabled => {
            if offer.profile != SdpMediaProfile::RtpAvp {
                return Err(SipError::InvalidSdp(format!(
                    "SRTP is disabled locally, cannot accept secure SDP profile '{}'",
                    offer.profile
                )));
            }
            (SdpMediaProfile::RtpAvp, Vec::new(), None)
        }
        SrtpMode::SdesOptional => {
            if let Some(remote_c) = offer.crypto.first() {
                let local_key_salt = local_sdes_candidates
                    .iter()
                    .find(|c| c.suite == remote_c.suite)
                    .or_else(|| local_sdes_candidates.first())
                    .map(|c| c.key_salt)
                    .ok_or_else(|| {
                        SipError::InvalidSdp("missing local SDES crypto key candidates".to_string())
                    })?;
                let ans_attr = SdesCryptoAttr::new(remote_c.tag, remote_c.suite, local_key_salt);
                (
                    offer.profile,
                    vec![ans_attr],
                    Some(NegotiatedSrtp::Sdes {
                        suite: remote_c.suite,
                        local_key_salt,
                        remote_key_salt: remote_c.key_salt,
                    }),
                )
            } else if offer.profile == SdpMediaProfile::RtpAvp {
                (SdpMediaProfile::RtpAvp, Vec::new(), None)
            } else {
                return Err(SipError::InvalidSdp(
                    "RTP/SAVP offer lacked supported non-MKI a=crypto SDES attributes".to_string(),
                ));
            }
        }
        SrtpMode::SdesRequired => {
            let Some(remote_c) = offer.crypto.first() else {
                return Err(SipError::InvalidSdp(
                    "SDES SRTP required locally, but remote offer lacked supported non-MKI a=crypto"
                        .to_string(),
                ));
            };
            let local_key_salt = local_sdes_candidates
                .iter()
                .find(|c| c.suite == remote_c.suite)
                .or_else(|| local_sdes_candidates.first())
                .map(|c| c.key_salt)
                .ok_or_else(|| {
                    SipError::InvalidSdp("missing local SDES crypto key candidates".to_string())
                })?;
            let ans_attr = SdesCryptoAttr::new(remote_c.tag, remote_c.suite, local_key_salt);
            (
                offer.profile,
                vec![ans_attr],
                Some(NegotiatedSrtp::Sdes {
                    suite: remote_c.suite,
                    local_key_salt,
                    remote_key_salt: remote_c.key_salt,
                }),
            )
        }
    };

    let answer = SdpSession {
        origin_username: "-".to_string(),
        session_id: offer.session_id.clone(),
        session_version: offer.session_version.clone(),
        connection_ip: local_ip.to_string(),
        audio_port: local_port,
        profile,
        direction: offer.direction.answer_direction(),
        codecs: negotiated.clone(),
        ptime: offer.ptime.or(Some(20)),
        crypto: answer_crypto,
        rtcp_port: None,
        rtcp_ip: None,
        rtcp_mux: offer.rtcp_mux,
    };

    Ok((answer, negotiated, negotiated_srtp))
}

/// Validates and extracts negotiated SRTP parameters when an outbound offer receives a remote SDP answer.
pub fn resolve_outbound_answer_srtp(
    local_offer: &SdpSession,
    remote_answer: &SdpSession,
    srtp_mode: SrtpMode,
) -> Result<Option<NegotiatedSrtp>, SipError> {
    if remote_answer.profile == SdpMediaProfile::UdpTlsRtpSavp {
        return Err(SipError::InvalidSdp(
            "DTLS-SRTP (UDP/TLS/RTP/SAVP) is not supported".to_string(),
        ));
    }
    match srtp_mode {
        SrtpMode::Disabled => {
            if remote_answer.profile.is_secure() {
                return Err(SipError::InvalidSdp(
                    "remote answer selected secure RTP profile when SRTP was disabled".to_string(),
                ));
            }
            Ok(None)
        }
        SrtpMode::SdesOptional => {
            if let Some(rem) = remote_answer.crypto.first() {
                let loc = local_offer
                    .crypto
                    .iter()
                    .find(|c| c.tag == rem.tag && c.suite == rem.suite)
                    .or_else(|| local_offer.crypto.iter().find(|c| c.suite == rem.suite))
                    .ok_or_else(|| {
                        SipError::InvalidSdp(
                            "remote SDES a=crypto tag/suite did not match local offer".to_string(),
                        )
                    })?;
                Ok(Some(NegotiatedSrtp::Sdes {
                    suite: rem.suite,
                    local_key_salt: loc.key_salt,
                    remote_key_salt: rem.key_salt,
                }))
            } else {
                Ok(None)
            }
        }
        SrtpMode::SdesRequired => {
            let rem = remote_answer.crypto.first().ok_or_else(|| {
                SipError::InvalidSdp(
                    "SDES SRTP required locally, but remote answer lacked supported non-MKI a=crypto"
                        .to_string(),
                )
            })?;
            let loc = local_offer
                .crypto
                .iter()
                .find(|c| c.tag == rem.tag && c.suite == rem.suite)
                .or_else(|| local_offer.crypto.iter().find(|c| c.suite == rem.suite))
                .ok_or_else(|| {
                    SipError::InvalidSdp(
                        "remote SDES a=crypto tag/suite did not match local offer".to_string(),
                    )
                })?;
            Ok(Some(NegotiatedSrtp::Sdes {
                suite: rem.suite,
                local_key_salt: loc.key_salt,
                remote_key_salt: rem.key_salt,
            }))
        }
    }
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 {
            u32::from(chunk[1])
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            u32::from(chunk[2])
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, SipError> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    if clean.len() % 4 == 1 {
        return Err(SipError::InvalidSdp(format!(
            "invalid Base64 length in '{input}'"
        )));
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let v0 = base64_val(chunk[0]).ok_or_else(|| {
            SipError::InvalidSdp(format!("invalid Base64 character in '{input}'"))
        })?;
        let v1 = base64_val(chunk[1]).ok_or_else(|| {
            SipError::InvalidSdp(format!("invalid Base64 character in '{input}'"))
        })?;
        out.push((v0 << 2) | (v1 >> 4));
        if chunk.len() > 2 {
            let v2 = base64_val(chunk[2]).ok_or_else(|| {
                SipError::InvalidSdp(format!("invalid Base64 character in '{input}'"))
            })?;
            out.push((v1 << 4) | (v2 >> 2));
            if chunk.len() > 3 {
                let v3 = base64_val(chunk[3]).ok_or_else(|| {
                    SipError::InvalidSdp(format!("invalid Base64 character in '{input}'"))
                })?;
                out.push((v2 << 6) | v3);
            }
        }
    }
    Ok(out)
}

fn parse_connection_ip(value: &str) -> Result<String, SipError> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 3 || !parts[0].eq_ignore_ascii_case("IN") {
        return Err(SipError::InvalidSdp(format!(
            "malformed SDP connection 'c={value}'"
        )));
    }
    let ip_with_ttl = parts[2];
    let ip = ip_with_ttl.split('/').next().unwrap_or(ip_with_ttl);
    if ip.is_empty() {
        return Err(SipError::InvalidSdp(format!(
            "empty IP in SDP connection 'c={value}'"
        )));
    }
    Ok(ip.to_string())
}

fn parse_rtpmap(rest: &str) -> Result<(u8, String, u32, Option<u8>), SipError> {
    let mut parts = rest.split_whitespace();
    let pt_str = parts
        .next()
        .ok_or_else(|| SipError::InvalidSdp(format!("missing payload type in rtpmap:{rest}")))?;
    let encoding_str = parts
        .next()
        .ok_or_else(|| SipError::InvalidSdp(format!("missing encoding in rtpmap:{rest}")))?;
    let pt = pt_str
        .parse::<u8>()
        .map_err(|_| SipError::InvalidSdp(format!("invalid rtpmap payload type '{pt_str}'")))?;

    let mut enc_parts = encoding_str.split('/');
    let name = enc_parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| SipError::InvalidSdp(format!("invalid rtpmap encoding '{encoding_str}'")))?
        .to_string();
    let rate_str = enc_parts
        .next()
        .ok_or_else(|| SipError::InvalidSdp(format!("missing clock rate in '{encoding_str}'")))?;
    let rate = rate_str
        .parse::<u32>()
        .map_err(|_| SipError::InvalidSdp(format!("invalid clock rate '{rate_str}'")))?;
    let channels = match enc_parts.next() {
        Some(ch_str) => Some(
            ch_str
                .parse::<u8>()
                .map_err(|_| SipError::InvalidSdp(format!("invalid channel count '{ch_str}'")))?,
        ),
        None => None,
    };

    Ok((pt, name, rate, channels))
}

fn parse_fmtp(rest: &str) -> Result<(u8, String), SipError> {
    let trimmed = rest.trim();
    let (pt_str, params) = trimmed
        .split_once(char::is_whitespace)
        .ok_or_else(|| SipError::InvalidSdp(format!("malformed fmtp:{rest}")))?;
    let pt = pt_str
        .trim()
        .parse::<u8>()
        .map_err(|_| SipError::InvalidSdp(format!("invalid fmtp payload type '{pt_str}'")))?;
    Ok((pt, params.trim().to_string()))
}

fn static_audio_codec(pt: u8) -> Option<(&'static str, u32)> {
    match pt {
        0 => Some(("PCMU", 8000)),
        3 => Some(("GSM", 8000)),
        8 => Some(("PCMA", 8000)),
        9 => Some(("G722", 8000)),
        13 => Some(("CN", 8000)),
        _ => None,
    }
}

fn strip_prefix_ci<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
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
    fn parses_and_serializes_sdp_with_static_and_dynamic_codecs() {
        let raw = "\
            v=0\r\n\
            o=alice 2890844526 2890844526 IN IP4 10.0.0.10\r\n\
            s=Call\r\n\
            c=IN IP4 10.0.0.10\r\n\
            t=0 0\r\n\
            m=audio 40000 RTP/AVP 96 0 9 101\r\n\
            a=rtpmap:96 opus/48000/2\r\n\
            a=fmtp:96 minptime=10;useinbandfec=1\r\n\
            a=rtpmap:101 telephone-event/8000\r\n\
            a=fmtp:101 0-16\r\n\
            a=ptime:20\r\n\
            a=sendonly\r\n";

        let sdp = SdpSession::parse(raw).unwrap();
        assert_eq!(sdp.connection_ip, "10.0.0.10");
        assert_eq!(sdp.audio_port, 40000);
        assert_eq!(sdp.direction, Direction::SendOnly);
        assert_eq!(sdp.ptime, Some(20));
        assert_eq!(sdp.codecs.len(), 4);
        assert_eq!(sdp.codecs[0].payload_type, 96);
        assert_eq!(sdp.codecs[0].encoding_name, "opus");
        assert_eq!(sdp.codecs[1], RtpCodec::pcmu());
        assert_eq!(sdp.codecs[2], RtpCodec::g722());
        assert_eq!(sdp.codecs[3].encoding_name, "telephone-event");

        let rendered = sdp.to_string();
        let reparsed = SdpSession::parse(&rendered).unwrap();
        assert_eq!(reparsed.codecs, sdp.codecs);
        assert_eq!(reparsed.direction, Direction::SendOnly);
    }

    #[test]
    fn negotiates_offer_answer_preserving_offer_pt_and_flipping_direction() {
        let mut offer = SdpSession::new(
            "alice",
            "1001",
            "192.168.1.10",
            50000,
            vec![
                RtpCodec {
                    payload_type: 96,
                    encoding_name: "opus".to_string(),
                    clock_rate: 48000,
                    channels: Some(2),
                    fmtp: None,
                },
                RtpCodec::pcma(),
                RtpCodec::telephone_event(101),
            ],
        );
        offer.direction = Direction::SendOnly;

        let local_supported = vec![
            RtpCodec::opus(),
            RtpCodec::pcmu(),
            RtpCodec::telephone_event(101),
        ];
        let (answer, codecs) =
            negotiate_offer_answer(&offer, &local_supported, "192.168.1.20", 50002).unwrap();

        assert_eq!(answer.connection_ip, "192.168.1.20");
        assert_eq!(answer.audio_port, 50002);
        assert_eq!(answer.direction, Direction::RecvOnly);
        assert_eq!(codecs.len(), 2);
        assert_eq!(codecs[0].payload_type, 96);
        assert_eq!(codecs[0].encoding_name, "opus");
        assert_eq!(codecs[1].encoding_name, "telephone-event");
    }

    #[test]
    fn rejects_offer_without_common_audio_codec() {
        let offer = SdpSession::new(
            "alice",
            "1",
            "10.0.0.1",
            4000,
            vec![RtpCodec::pcma(), RtpCodec::telephone_event(101)],
        );
        let local = vec![RtpCodec::pcmu(), RtpCodec::telephone_event(101)];
        assert!(negotiate_offer_answer(&offer, &local, "10.0.0.2", 4002).is_err());
    }

    #[test]
    fn parses_and_negotiates_comfort_noise_pt13_and_rejects_cn_only_offer() {
        let offer = SdpSession::new(
            "alice",
            "1",
            "10.0.0.1",
            4000,
            vec![
                RtpCodec::pcmu(),
                RtpCodec::cn(),
                RtpCodec::telephone_event(101),
            ],
        );
        let reparsed = SdpSession::parse(&offer.to_string()).unwrap();
        assert!(reparsed.codecs.iter().any(RtpCodec::is_comfort_noise));

        let local = vec![
            RtpCodec::pcmu(),
            RtpCodec::cn(),
            RtpCodec::telephone_event(101),
        ];
        let (ans, negotiated) =
            negotiate_offer_answer(&reparsed, &local, "10.0.0.2", 4002).unwrap();
        assert_eq!(ans.codecs.len(), 3);
        assert!(negotiated
            .iter()
            .any(|c| c.payload_type == 13 && c.is_comfort_noise()));

        let cn_only = SdpSession::new(
            "alice",
            "2",
            "10.0.0.1",
            4000,
            vec![RtpCodec::cn(), RtpCodec::telephone_event(101)],
        );
        assert!(negotiate_offer_answer(&cn_only, &local, "10.0.0.2", 4002).is_err());
    }

    #[test]
    fn parses_and_negotiates_sdes_srtp_rejects_mki_and_dtls_offers() {
        let secret_a = [0x11u8; 32];
        let secret_b = [0x22u8; 32];
        let k1 = SdesCryptoAttr::derive_from_secret(
            1,
            SrtpSuite::AesCm128HmacSha1_80,
            &secret_a,
            b"alice-call-1",
        );
        let k2 = SdesCryptoAttr::derive_from_secret(
            1,
            SrtpSuite::AesCm128HmacSha1_80,
            &secret_b,
            b"bob-call-1",
        );
        assert_ne!(k1.key_salt, k2.key_salt);
        let parsed_k1 = SdesCryptoAttr::parse(&k1.to_string()).unwrap();
        assert_eq!(parsed_k1, k1);

        // Lifetime without MKI is accepted; MKI (`|1:4` or `|2^20|1:4`) MUST be rejected.
        let with_lifetime = format!(
            "1 AES_CM_128_HMAC_SHA1_80 inline:{}|2^20",
            k1.inline_base64()
        );
        assert_eq!(SdesCryptoAttr::parse(&with_lifetime).unwrap(), k1);
        let with_mki = format!(
            "1 AES_CM_128_HMAC_SHA1_80 inline:{}|2^20|1:4",
            k1.inline_base64()
        );
        assert!(SdesCryptoAttr::parse(&with_mki).is_err());

        // Offer containing MKI line first and non-MKI line second must automatically pick non-MKI.
        let sdp_with_mki_then_plain = format!(
            "v=0\r\n\
             o=alice 10 10 IN IP4 10.0.0.1\r\n\
             s=Call\r\n\
             c=IN IP4 10.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 40000 RTP/SAVP 0\r\n\
             a=crypto:{with_mki}\r\n\
             a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
            k1.inline_base64()
        );
        let parsed_mki_offer = SdpSession::parse(&sdp_with_mki_then_plain).unwrap();
        assert_eq!(parsed_mki_offer.crypto.len(), 1);
        assert_eq!(parsed_mki_offer.crypto[0].tag, 2);

        let mut offer = SdpSession::new("alice", "10", "10.0.0.1", 40000, vec![RtpCodec::pcmu()]);
        offer.profile = SdpMediaProfile::RtpSavp;
        offer.crypto = vec![k1.clone()];

        let reparsed_offer = SdpSession::parse(&offer.to_string()).unwrap();
        assert_eq!(reparsed_offer.profile, SdpMediaProfile::RtpSavp);
        assert_eq!(reparsed_offer.crypto, vec![k1.clone()]);

        // Disabled mode rejects RTP/SAVP offer.
        assert!(
            negotiate_offer_answer(&reparsed_offer, &[RtpCodec::pcmu()], "10.0.0.2", 50000)
                .is_err()
        );

        // Missing local SDES candidates must error rather than falling back to a hardcoded key.
        assert!(negotiate_offer_answer_with_srtp(
            &reparsed_offer,
            &[RtpCodec::pcmu()],
            "10.0.0.2",
            50000,
            SrtpMode::SdesRequired,
            &[],
        )
        .is_err());

        // SdesRequired mode accepts and produces matching tag/suite with Bob's key_salt.
        let (ans, _, neg_srtp) = negotiate_offer_answer_with_srtp(
            &reparsed_offer,
            &[RtpCodec::pcmu()],
            "10.0.0.2",
            50000,
            SrtpMode::SdesRequired,
            std::slice::from_ref(&k2),
        )
        .unwrap();
        assert_eq!(ans.profile, SdpMediaProfile::RtpSavp);
        assert_eq!(ans.crypto, vec![k2.clone()]);
        assert_eq!(
            neg_srtp,
            Some(NegotiatedSrtp::Sdes {
                suite: SrtpSuite::AesCm128HmacSha1_80,
                local_key_salt: k2.key_salt,
                remote_key_salt: k1.key_salt,
            })
        );

        let resolved_uac =
            resolve_outbound_answer_srtp(&reparsed_offer, &ans, SrtpMode::SdesRequired).unwrap();
        assert_eq!(
            resolved_uac,
            Some(NegotiatedSrtp::Sdes {
                suite: SrtpSuite::AesCm128HmacSha1_80,
                local_key_salt: k1.key_salt,
                remote_key_salt: k2.key_salt,
            })
        );

        // DTLS-SRTP offers (`UDP/TLS/RTP/SAVP`) parse cleanly and are explicitly rejected (488).
        assert!(SrtpMode::parse("dtls").is_err());
        let dtls_raw = "\
            v=0\r\n\
            o=alice 20 20 IN IP4 10.0.0.1\r\n\
            s=Call\r\n\
            c=IN IP4 10.0.0.1\r\n\
            t=0 0\r\n\
            m=audio 40002 UDP/TLS/RTP/SAVPF 0\r\n\
            a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11\r\n\
            a=setup:actpass\r\n";
        let dtls_offer = SdpSession::parse(dtls_raw).unwrap();
        assert_eq!(dtls_offer.profile, SdpMediaProfile::UdpTlsRtpSavp);
        for mode in [
            SrtpMode::Disabled,
            SrtpMode::SdesOptional,
            SrtpMode::SdesRequired,
        ] {
            assert!(negotiate_offer_answer_with_srtp(
                &dtls_offer,
                &[RtpCodec::pcmu()],
                "10.0.0.2",
                50002,
                mode,
                std::slice::from_ref(&k2),
            )
            .is_err());
        }
    }

    #[test]
    fn parses_serializes_and_negotiates_rtcp_port_and_rtcp_mux() {
        let raw = "\
            v=0\r\n\
            o=alice 10 10 IN IP4 192.0.2.10\r\n\
            s=Call\r\n\
            c=IN IP4 192.0.2.10\r\n\
            t=0 0\r\n\
            m=audio 4004 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=rtcp:4009 IN IP4 192.0.2.11\r\n\
            a=rtcp-mux\r\n";
        let offer = SdpSession::parse(raw).unwrap();
        assert_eq!(offer.rtcp_port, Some(4009));
        assert_eq!(offer.rtcp_ip.as_deref(), Some("192.0.2.11"));
        assert!(offer.rtcp_mux);

        let serialized = offer.to_string();
        let reparsed = SdpSession::parse(&serialized).unwrap();
        assert_eq!(reparsed.rtcp_port, Some(4009));
        assert_eq!(reparsed.rtcp_ip.as_deref(), Some("192.0.2.11"));
        assert!(reparsed.rtcp_mux);

        let (ans, _, _) = negotiate_offer_answer_with_srtp(
            &reparsed,
            &[RtpCodec::pcmu()],
            "10.0.0.2",
            50000,
            SrtpMode::Disabled,
            &[],
        )
        .unwrap();
        assert!(ans.rtcp_mux);
        assert_eq!(ans.rtcp_port, None);
    }
}
