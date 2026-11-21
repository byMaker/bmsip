//! MODULE_CONTRACT: Audio SDP session parser/formatter (`SdpSession`) and RFC 3264 Offer/Answer negotiator.
//! INVARIANTS: Populates static RTP payload types (`0` PCMU, `8` PCMA, `3` GSM, `9` G722) if `a=rtpmap` is omitted; `negotiate_offer_answer` preserves offerer payload type numbers and requires at least one non-DTMF audio codec.
//! RFC_REFS: RFC 4566, RFC 3264 Section 6.1, RFC 3551.

use std::fmt;

use crate::error::SipError;

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
    pub direction: Direction,
    pub codecs: Vec<RtpCodec>,
    pub ptime: Option<u32>,
}

impl SdpSession {
    /// Creates a new audio SDP session with `sendrecv` direction and 20 ms ptime.
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
            direction: Direction::SendRecv,
            codecs,
            ptime: Some(20),
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
        let mut audio_ip: Option<String> = None;
        let mut payload_types: Vec<u8> = Vec::new();
        let mut direction = Direction::SendRecv;
        let mut ptime: Option<u32> = None;
        let mut rtpmaps: Vec<(u8, String, u32, Option<u8>)> = Vec::new();
        let mut fmtps: Vec<(u8, String)> = Vec::new();

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
            direction,
            codecs,
            ptime,
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

        write!(f, "m=audio {} RTP/AVP", self.audio_port)?;
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

        if let Some(ptime) = self.ptime {
            write!(f, "a=ptime:{ptime}\r\n")?;
        }
        write!(f, "a={}\r\n", self.direction)?;
        Ok(())
    }
}

/// Performs RFC 3264 Offer/Answer codec and direction negotiation for audio.
///
/// Selects matching audio codecs (using the offer's RTP payload type numbers per RFC 3264),
/// preserves matching `telephone-event` DTMF support, and derives the complementary direction.
pub fn negotiate_offer_answer(
    offer: &SdpSession,
    local_supported: &[RtpCodec],
    local_ip: &str,
    local_port: u16,
) -> Result<(SdpSession, Vec<RtpCodec>), SipError> {
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

    let answer = SdpSession {
        origin_username: "-".to_string(),
        session_id: offer.session_id.clone(),
        session_version: offer.session_version.clone(),
        connection_ip: local_ip.to_string(),
        audio_port: local_port,
        direction: offer.direction.answer_direction(),
        codecs: negotiated.clone(),
        ptime: offer.ptime.or(Some(20)),
    };

    Ok((answer, negotiated))
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
}
