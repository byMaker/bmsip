//! MODULE_CONTRACT: RFC 3550 RTCP compound packet codec (`SR`, `RR`, `BYE`) and receiver stream statistics (`RtpStreamStats`).
//! INVARIANTS: Validates `V=2` and word-aligned RTCP packet bounds; computes RFC 3550 Appendix A.1/A.8 extended sequence, packet loss, and interarrival jitter.
//! RFC_REFS: RFC 3550 Sections 6.1–6.4, Appendix A.1, Appendix A.8.

use crate::error::MediaError;

const PT_SR: u8 = 200;
const PT_RR: u8 = 201;
const PT_BYE: u8 = 203;

/// RTCP reception report block (24 bytes, RFC 3550 Section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceptionReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub cumulative_lost: i32,
    pub extended_highest_seq: u32,
    pub jitter: u32,
    pub lsr: u32,
    pub dlsr: u32,
}

impl ReceptionReportBlock {
    fn parse(raw: &[u8]) -> Result<Self, MediaError> {
        if raw.len() < 24 {
            return Err(MediaError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let fraction_lost = raw[4];
        let lost_u24 = (u32::from(raw[5]) << 16) | (u32::from(raw[6]) << 8) | u32::from(raw[7]);
        let cumulative_lost = if (lost_u24 & 0x0080_0000) != 0 {
            (lost_u24 | 0xff00_0000) as i32
        } else {
            lost_u24 as i32
        };
        let extended_highest_seq = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let jitter = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let lsr = u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]);
        let dlsr = u32::from_be_bytes([raw[20], raw[21], raw[22], raw[23]]);

        Ok(Self {
            ssrc,
            fraction_lost,
            cumulative_lost,
            extended_highest_seq,
            jitter,
            lsr,
            dlsr,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.push(self.fraction_lost);
        let clamped = self.cumulative_lost.clamp(-8_388_608, 8_388_607) as u32;
        out.push(((clamped >> 16) & 0xff) as u8);
        out.push(((clamped >> 8) & 0xff) as u8);
        out.push((clamped & 0xff) as u8);
        out.extend_from_slice(&self.extended_highest_seq.to_be_bytes());
        out.extend_from_slice(&self.jitter.to_be_bytes());
        out.extend_from_slice(&self.lsr.to_be_bytes());
        out.extend_from_slice(&self.dlsr.to_be_bytes());
    }
}

/// RTCP Sender Info block (20 bytes, RFC 3550 Section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpSenderInfo {
    pub ntp_timestamp: u64,
    pub rtp_timestamp: u32,
    pub sender_packet_count: u32,
    pub sender_octet_count: u32,
}

impl RtcpSenderInfo {
    fn parse(raw: &[u8]) -> Result<Self, MediaError> {
        if raw.len() < 20 {
            return Err(MediaError::PacketTooShort);
        }
        let ntp_timestamp = u64::from_be_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
        let rtp_timestamp = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let sender_packet_count = u32::from_be_bytes([raw[12], raw[13], raw[14], raw[15]]);
        let sender_octet_count = u32::from_be_bytes([raw[16], raw[17], raw[18], raw[19]]);
        Ok(Self {
            ntp_timestamp,
            rtp_timestamp,
            sender_packet_count,
            sender_octet_count,
        })
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ntp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.sender_packet_count.to_be_bytes());
        out.extend_from_slice(&self.sender_octet_count.to_be_bytes());
    }
}

/// Supported RTCP packet variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    SenderReport {
        ssrc: u32,
        sender_info: RtcpSenderInfo,
        reports: Vec<ReceptionReportBlock>,
    },
    ReceiverReport {
        ssrc: u32,
        reports: Vec<ReceptionReportBlock>,
    },
    Bye {
        sources: Vec<u32>,
        reason: Option<String>,
    },
    Unknown {
        packet_type: u8,
        report_count: u8,
        payload: Vec<u8>,
    },
}

impl RtcpPacket {
    /// Parses a compound RTCP datagram into individual [`RtcpPacket`] entries.
    pub fn parse_compound(raw: &[u8]) -> Result<Vec<Self>, MediaError> {
        if raw.is_empty() {
            return Err(MediaError::PacketTooShort);
        }
        let mut packets = Vec::new();
        let mut offset = 0usize;

        while offset < raw.len() {
            if raw.len() - offset < 4 {
                return Err(MediaError::PacketTooShort);
            }
            let b0 = raw[offset];
            let version = (b0 >> 6) & 0x03;
            if version != 2 {
                return Err(MediaError::UnsupportedRtpVersion(version));
            }
            let padding = (b0 & 0x20) != 0;
            let count = b0 & 0x1f;
            let pt = raw[offset + 1];
            let len_words = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            let total_bytes = (usize::from(len_words) + 1) * 4;
            if raw.len() - offset < total_bytes {
                return Err(MediaError::PacketTooShort);
            }

            let mut body = &raw[offset + 4..offset + total_bytes];
            if padding {
                let Some(&pad) = body.last() else {
                    return Err(MediaError::InvalidHeader(
                        "RTCP padding bit set on empty body".to_string(),
                    ));
                };
                let pad_len = usize::from(pad);
                if pad_len == 0 || pad_len > body.len() {
                    return Err(MediaError::InvalidHeader(
                        "invalid RTCP padding length".to_string(),
                    ));
                }
                body = &body[..body.len() - pad_len];
            }

            let pkt = match pt {
                PT_SR => {
                    if body.len() < 24 {
                        return Err(MediaError::PacketTooShort);
                    }
                    let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let sender_info = RtcpSenderInfo::parse(&body[4..24])?;
                    let reports = parse_report_blocks(&body[24..], usize::from(count))?;
                    Self::SenderReport {
                        ssrc,
                        sender_info,
                        reports,
                    }
                }
                PT_RR => {
                    if body.len() < 4 {
                        return Err(MediaError::PacketTooShort);
                    }
                    let ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let reports = parse_report_blocks(&body[4..], usize::from(count))?;
                    Self::ReceiverReport { ssrc, reports }
                }
                PT_BYE => {
                    let sc = usize::from(count);
                    if body.len() < sc * 4 {
                        return Err(MediaError::PacketTooShort);
                    }
                    let mut sources = Vec::with_capacity(sc);
                    let mut pos = 0;
                    for _ in 0..sc {
                        sources.push(u32::from_be_bytes([
                            body[pos],
                            body[pos + 1],
                            body[pos + 2],
                            body[pos + 3],
                        ]));
                        pos += 4;
                    }
                    let reason = if pos < body.len() {
                        let rlen = usize::from(body[pos]);
                        pos += 1;
                        if body.len() < pos + rlen {
                            return Err(MediaError::PacketTooShort);
                        }
                        Some(String::from_utf8_lossy(&body[pos..pos + rlen]).to_string())
                    } else {
                        None
                    };
                    Self::Bye { sources, reason }
                }
                other => Self::Unknown {
                    packet_type: other,
                    report_count: count,
                    payload: body.to_vec(),
                },
            };

            packets.push(pkt);
            offset += total_bytes;
        }

        Ok(packets)
    }

    /// Serializes a single [`RtcpPacket`] to word-aligned wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let (pt, count) = match self {
            Self::SenderReport {
                ssrc,
                sender_info,
                reports,
            } => {
                body.extend_from_slice(&ssrc.to_be_bytes());
                sender_info.write_to(&mut body);
                let rc = reports.len().min(31);
                for block in reports.iter().take(rc) {
                    block.write_to(&mut body);
                }
                (PT_SR, rc as u8)
            }
            Self::ReceiverReport { ssrc, reports } => {
                body.extend_from_slice(&ssrc.to_be_bytes());
                let rc = reports.len().min(31);
                for block in reports.iter().take(rc) {
                    block.write_to(&mut body);
                }
                (PT_RR, rc as u8)
            }
            Self::Bye { sources, reason } => {
                let sc = sources.len().min(31);
                for src in sources.iter().take(sc) {
                    body.extend_from_slice(&src.to_be_bytes());
                }
                if let Some(text) = reason {
                    let bytes = text.as_bytes();
                    let rlen = bytes.len().min(255);
                    body.push(rlen as u8);
                    body.extend_from_slice(&bytes[..rlen]);
                    while body.len() % 4 != 0 {
                        body.push(0);
                    }
                }
                (PT_BYE, sc as u8)
            }
            Self::Unknown {
                packet_type,
                report_count,
                payload,
            } => {
                body.extend_from_slice(payload);
                while body.len() % 4 != 0 {
                    body.push(0);
                }
                (*packet_type, *report_count & 0x1f)
            }
        };

        let length_words = (body.len() / 4) as u16;
        let mut out = Vec::with_capacity(4 + body.len());
        out.push((2u8 << 6) | (count & 0x1f));
        out.push(pt);
        out.extend_from_slice(&length_words.to_be_bytes());
        out.extend_from_slice(&body);
        out
    }
}

fn parse_report_blocks(raw: &[u8], count: usize) -> Result<Vec<ReceptionReportBlock>, MediaError> {
    if raw.len() < count * 24 {
        return Err(MediaError::PacketTooShort);
    }
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        blocks.push(ReceptionReportBlock::parse(&raw[i * 24..(i + 1) * 24])?);
    }
    Ok(blocks)
}

/// Receiver RTP sequence, loss, and RFC 3550 §6.4.1 interarrival jitter tracker.
#[derive(Debug, Clone, Default)]
pub struct RtpStreamStats {
    initialized: bool,
    base_seq: u32,
    max_seq: u16,
    cycles: u32,
    received: u32,
    expected_prior: u32,
    received_prior: u32,
    transit: i64,
    jitter: f64,
    last_sr_lsr: u32,
}

impl RtpStreamStats {
    /// Creates zeroed RTP stream statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a received RTP packet and updates loss/jitter estimates per RFC 3550 Appendix A.1/A.8.
    pub fn record_packet(&mut self, seq: u16, rtp_timestamp: u32, arrival_timestamp_samples: u32) {
        if !self.initialized {
            self.initialized = true;
            self.base_seq = u32::from(seq);
            self.max_seq = seq;
            self.cycles = 0;
            self.received = 1;
            self.transit = i64::from(arrival_timestamp_samples) - i64::from(rtp_timestamp);
            self.jitter = 0.0;
            return;
        }

        self.received = self.received.saturating_add(1);
        let udelta = seq.wrapping_sub(self.max_seq);
        if udelta < 32768 {
            if seq < self.max_seq {
                self.cycles = self.cycles.wrapping_add(0x0001_0000);
            }
            self.max_seq = seq;
        }

        let transit = i64::from(arrival_timestamp_samples) - i64::from(rtp_timestamp);
        let d = (transit - self.transit).abs() as f64;
        self.transit = transit;
        self.jitter += (d - self.jitter) / 16.0;
    }

    /// Records NTP timestamp from an inbound RTCP Sender Report (`LSR`).
    pub fn record_sender_report(&mut self, ntp_timestamp: u64) {
        self.last_sr_lsr = ((ntp_timestamp >> 16) & 0xffff_ffff) as u32;
    }

    /// Returns total received RTP packet count.
    pub fn received_count(&self) -> u32 {
        self.received
    }

    /// Returns current RFC 3550 interarrival jitter estimate in RTP timestamp units.
    pub fn jitter(&self) -> u32 {
        self.jitter.round().max(0.0) as u32
    }

    /// Returns cumulative packets lost (`expected - received`).
    pub fn cumulative_lost(&self) -> i32 {
        if !self.initialized {
            return 0;
        }
        let extended_max = self.cycles + u32::from(self.max_seq);
        let expected = extended_max.saturating_sub(self.base_seq) + 1;
        expected as i32 - self.received as i32
    }

    /// Builds a non-mutating [`ReceptionReportBlock`] snapshot for `source_ssrc`.
    pub fn snapshot_reception_report(&self, source_ssrc: u32) -> ReceptionReportBlock {
        let extended_max = if self.initialized {
            self.cycles + u32::from(self.max_seq)
        } else {
            0
        };
        let expected = if self.initialized {
            extended_max.saturating_sub(self.base_seq) + 1
        } else {
            0
        };
        let expected_interval = expected.saturating_sub(self.expected_prior);
        let received_interval = self.received.saturating_sub(self.received_prior);
        let lost_interval = expected_interval as i64 - received_interval as i64;
        let fraction_lost = if expected_interval == 0 || lost_interval <= 0 {
            0
        } else {
            ((lost_interval as u64 * 256) / u64::from(expected_interval)).min(255) as u8
        };

        ReceptionReportBlock {
            ssrc: source_ssrc,
            fraction_lost,
            cumulative_lost: self.cumulative_lost(),
            extended_highest_seq: extended_max,
            jitter: self.jitter(),
            lsr: self.last_sr_lsr,
            dlsr: 0,
        }
    }

    /// Builds a [`ReceptionReportBlock`] and advances interval counters for the next RTCP cycle.
    pub fn build_reception_report(&mut self, source_ssrc: u32) -> ReceptionReportBlock {
        let block = self.snapshot_reception_report(source_ssrc);
        if self.initialized {
            self.expected_prior = block.extended_highest_seq.saturating_sub(self.base_seq) + 1;
            self.received_prior = self.received;
        }
        block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_rtcp_roundtrip() {
        let sr = RtcpPacket::SenderReport {
            ssrc: 0x1122_3344,
            sender_info: RtcpSenderInfo {
                ntp_timestamp: 0x0102_0304_0506_0708,
                rtp_timestamp: 8000,
                sender_packet_count: 50,
                sender_octet_count: 8000,
            },
            reports: vec![ReceptionReportBlock {
                ssrc: 0x5566_7788,
                fraction_lost: 12,
                cumulative_lost: 3,
                extended_highest_seq: 1000,
                jitter: 24,
                lsr: 0x0304_0506,
                dlsr: 100,
            }],
        };
        let bye = RtcpPacket::Bye {
            sources: vec![0x1122_3344],
            reason: Some("call ended".to_string()),
        };

        let mut compound = sr.to_bytes();
        compound.extend_from_slice(&bye.to_bytes());
        let parsed = RtcpPacket::parse_compound(&compound).unwrap();
        assert_eq!(parsed, vec![sr, bye]);
    }

    #[test]
    fn stream_stats_tracks_loss_wraparound_and_jitter() {
        let mut stats = RtpStreamStats::new();
        stats.record_packet(65534, 160, 160);
        stats.record_packet(65535, 320, 320);
        // Drop seq 0, receive seq 1 late by 160 samples
        stats.record_packet(1, 640, 800);

        assert_eq!(stats.received_count(), 3);
        assert_eq!(stats.cumulative_lost(), 1);
        assert_eq!(stats.jitter(), 10);
        let report = stats.build_reception_report(0x9999);
        assert_eq!(report.extended_highest_seq, 65537);
        assert_eq!(report.cumulative_lost, 1);
        assert_eq!(report.fraction_lost, 64);
    }
}
