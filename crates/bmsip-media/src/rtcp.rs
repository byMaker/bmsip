//! MODULE_CONTRACT: RFC 3550 RTCP compound packet codec (`SR`, `RR`, `SDES`, `BYE`) and receiver stream statistics (`RtpStreamStats`).
//! INVARIANTS: Validates `V=2` and word-aligned RTCP packet bounds; computes RFC 3550 Appendix A.1/A.8 extended sequence, packet loss, modular interarrival jitter, and `DLSR`.
//! RFC_REFS: RFC 3550 Sections 6.1–6.5, Appendix A.1, Appendix A.8.

use crate::error::MediaError;

const PT_SR: u8 = 200;
const PT_RR: u8 = 201;
const PT_SDES: u8 = 202;
const PT_BYE: u8 = 203;

/// RFC 3550 §6.5.1 SDES `CNAME` item type (`1`).
pub const SDES_CNAME: u8 = 1;

/// Single RFC 3550 §6.5 RTCP SDES item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesItem {
    pub item_type: u8,
    pub value: String,
}

/// Source description chunk associating an SSRC/CSRC with one or more [`SdesItem`] entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub items: Vec<SdesItem>,
}

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
    Sdes {
        chunks: Vec<SdesChunk>,
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
                PT_SDES => {
                    let chunks = parse_sdes_chunks(body, usize::from(count))?;
                    Self::Sdes { chunks }
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
            Self::Sdes { chunks } => {
                let sc = chunks.len().min(31);
                for chunk in chunks.iter().take(sc) {
                    let chunk_start = body.len();
                    body.extend_from_slice(&chunk.ssrc.to_be_bytes());
                    for item in &chunk.items {
                        if item.item_type == 0 {
                            continue;
                        }
                        let val_bytes = item.value.as_bytes();
                        let len = val_bytes.len().min(255);
                        body.push(item.item_type);
                        body.push(len as u8);
                        body.extend_from_slice(&val_bytes[..len]);
                    }
                    // RFC 3550 §6.5: END item (0) followed by null padding to a 32-bit chunk boundary.
                    body.push(0);
                    while !(body.len() - chunk_start).is_multiple_of(4) {
                        body.push(0);
                    }
                }
                (PT_SDES, sc as u8)
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

fn parse_sdes_chunks(raw: &[u8], count: usize) -> Result<Vec<SdesChunk>, MediaError> {
    let mut chunks = Vec::with_capacity(count);
    let mut pos = 0usize;
    for _ in 0..count {
        if raw.len() - pos < 4 {
            return Err(MediaError::PacketTooShort);
        }
        let chunk_start = pos;
        let ssrc = u32::from_be_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        pos += 4;
        let mut items = Vec::new();
        let mut found_end = false;
        while pos < raw.len() {
            let item_type = raw[pos];
            pos += 1;
            if item_type == 0 {
                while !(pos - chunk_start).is_multiple_of(4) {
                    if pos >= raw.len() {
                        return Err(MediaError::PacketTooShort);
                    }
                    pos += 1;
                }
                found_end = true;
                break;
            }
            if pos >= raw.len() {
                return Err(MediaError::PacketTooShort);
            }
            let len = usize::from(raw[pos]);
            pos += 1;
            if raw.len() - pos < len {
                return Err(MediaError::PacketTooShort);
            }
            let value = String::from_utf8_lossy(&raw[pos..pos + len]).to_string();
            pos += len;
            items.push(SdesItem { item_type, value });
        }
        if !found_end {
            return Err(MediaError::InvalidHeader(
                "RTCP SDES chunk missing END terminator".to_string(),
            ));
        }
        chunks.push(SdesChunk { ssrc, items });
    }
    Ok(chunks)
}

/// Sequence acceptance status returned by [`RtpStreamStats`] per RFC 3550 Appendix A.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqStatus {
    /// Normal in-order, small-reorder, or duplicate packet within acceptable window.
    Accepted,
    /// Large sequence jump confirmed by two sequential packets; sequence domain resynchronized.
    Resynced,
    /// Initial unexpected large sequence jump awaiting a confirming sequential packet.
    ProbationRejected,
}

const MAX_DROPOUT: u16 = 3000;
const MAX_MISORDER: u16 = 100;
const BAD_SEQ_MOD_LIMIT: u16 = u16::MAX - MAX_MISORDER + 1;

/// Receiver RTP sequence, loss, and RFC 3550 §6.4.1 interarrival jitter tracker.
#[derive(Debug, Clone, Default)]
pub struct RtpStreamStats {
    initialized: bool,
    base_seq: u32,
    max_seq: u16,
    bad_seq: Option<u16>,
    cycles: u32,
    received: u32,
    expected_prior: u32,
    received_prior: u32,
    transit: u32,
    transit_initialized: bool,
    jitter: f64,
    last_sr_lsr: u32,
    last_sr_received_at_ms: Option<u64>,
}

impl RtpStreamStats {
    /// Creates zeroed RTP stream statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets all per-SSRC sequence, jitter, and RTCP interval counters.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    fn record_seq(&mut self, seq: u16) -> SeqStatus {
        if !self.initialized {
            self.initialized = true;
            self.base_seq = u32::from(seq);
            self.max_seq = seq;
            self.bad_seq = None;
            self.cycles = 0;
            self.received = 1;
            return SeqStatus::Accepted;
        }
        let udelta = seq.wrapping_sub(self.max_seq);
        if udelta < MAX_DROPOUT {
            if seq < self.max_seq {
                self.cycles = self.cycles.wrapping_add(0x0001_0000);
            }
            self.max_seq = seq;
            self.bad_seq = None;
            self.received = self.received.saturating_add(1);
            SeqStatus::Accepted
        } else if udelta <= BAD_SEQ_MOD_LIMIT {
            if self.bad_seq == Some(seq) {
                // RFC 3550 Appendix A.1: two sequential packets in the new sequence space reset the stream.
                self.base_seq = u32::from(seq);
                self.max_seq = seq;
                self.bad_seq = None;
                self.cycles = 0;
                self.received = 1;
                self.expected_prior = 0;
                self.received_prior = 0;
                self.transit_initialized = false;
                self.jitter = 0.0;
                SeqStatus::Resynced
            } else {
                self.bad_seq = Some(seq.wrapping_add(1));
                SeqStatus::ProbationRejected
            }
        } else {
            // Reordered or duplicate packet within MAX_MISORDER.
            self.bad_seq = None;
            self.received = self.received.saturating_add(1);
            SeqStatus::Accepted
        }
    }

    /// Records a received non-audio RTP packet (DTMF `telephone-event`, Comfort Noise) for sequence/loss tracking without disturbing jitter.
    pub fn record_non_audio_packet(&mut self, seq: u16) -> SeqStatus {
        self.record_seq(seq)
    }

    /// Records a received RTP audio packet and updates loss/jitter estimates per RFC 3550 Appendix A.1/A.8.
    pub fn record_packet(
        &mut self,
        seq: u16,
        rtp_timestamp: u32,
        arrival_timestamp_samples: u32,
    ) -> SeqStatus {
        let status = self.record_seq(seq);
        if status == SeqStatus::ProbationRejected {
            return status;
        }

        let transit = arrival_timestamp_samples.wrapping_sub(rtp_timestamp);
        if !self.transit_initialized {
            self.transit_initialized = true;
            self.transit = transit;
            self.jitter = 0.0;
            return status;
        }

        let d = (transit.wrapping_sub(self.transit) as i32).unsigned_abs() as f64;
        self.transit = transit;
        self.jitter += (d - self.jitter) / 16.0;
        status
    }

    /// Records NTP timestamp from an inbound RTCP Sender Report (`LSR`) without an arrival timestamp (`DLSR = 0`).
    pub fn record_sender_report(&mut self, ntp_timestamp: u64) {
        self.last_sr_lsr = ((ntp_timestamp >> 16) & 0xffff_ffff) as u32;
        self.last_sr_received_at_ms = None;
    }

    /// Records NTP timestamp from an inbound RTCP Sender Report (`LSR`) together with its monotonic arrival timestamp in ms (`DLSR`).
    pub fn record_sender_report_at(&mut self, ntp_timestamp: u64, now_ms: u64) {
        self.last_sr_lsr = ((ntp_timestamp >> 16) & 0xffff_ffff) as u32;
        self.last_sr_received_at_ms = Some(now_ms);
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
        let extended_max = self.cycles.wrapping_add(u32::from(self.max_seq));
        let expected = extended_max.wrapping_sub(self.base_seq).saturating_add(1);
        (i64::from(expected) - i64::from(self.received)).clamp(-8_388_608, 8_388_607) as i32
    }

    /// Builds a non-mutating [`ReceptionReportBlock`] snapshot for `source_ssrc` with `DLSR = 0`.
    pub fn snapshot_reception_report(&self, source_ssrc: u32) -> ReceptionReportBlock {
        self.snapshot_reception_report_at(source_ssrc, None)
    }

    /// Builds a non-mutating [`ReceptionReportBlock`] snapshot for `source_ssrc`, computing `DLSR` when `now_ms` and SR arrival time are present.
    pub fn snapshot_reception_report_at(
        &self,
        source_ssrc: u32,
        now_ms: Option<u64>,
    ) -> ReceptionReportBlock {
        let extended_max = if self.initialized {
            self.cycles.wrapping_add(u32::from(self.max_seq))
        } else {
            0
        };
        let expected = if self.initialized {
            extended_max.wrapping_sub(self.base_seq).saturating_add(1)
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

        let dlsr = match (self.last_sr_lsr != 0, self.last_sr_received_at_ms, now_ms) {
            (true, Some(rx_ms), Some(cur_ms)) => (((cur_ms.saturating_sub(rx_ms) as u128) * 65_536)
                / 1_000)
                .min(u128::from(u32::MAX)) as u32,
            _ => 0,
        };

        ReceptionReportBlock {
            ssrc: source_ssrc,
            fraction_lost,
            cumulative_lost: self.cumulative_lost(),
            extended_highest_seq: extended_max,
            jitter: self.jitter(),
            lsr: self.last_sr_lsr,
            dlsr,
        }
    }

    /// Builds a [`ReceptionReportBlock`] (`DLSR = 0`) and advances interval counters for the next RTCP cycle.
    pub fn build_reception_report(&mut self, source_ssrc: u32) -> ReceptionReportBlock {
        self.build_reception_report_at(source_ssrc, None)
    }

    /// Builds a [`ReceptionReportBlock`] with optional monotonic `now_ms` (`DLSR`) and advances interval counters.
    pub fn build_reception_report_at(
        &mut self,
        source_ssrc: u32,
        now_ms: Option<u64>,
    ) -> ReceptionReportBlock {
        let block = self.snapshot_reception_report_at(source_ssrc, now_ms);
        if self.initialized {
            self.expected_prior = block
                .extended_highest_seq
                .wrapping_sub(self.base_seq)
                .saturating_add(1);
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

    #[test]
    fn sdes_cname_packet_roundtrips() {
        let sdes = RtcpPacket::Sdes {
            chunks: vec![SdesChunk {
                ssrc: 0x1234_5678,
                items: vec![SdesItem {
                    item_type: SDES_CNAME,
                    value: "alice@example.com".to_string(),
                }],
            }],
        };
        let wire = sdes.to_bytes();
        assert_eq!(wire.len() % 4, 0);
        let parsed = RtcpPacket::parse_compound(&wire).unwrap();
        assert_eq!(parsed, vec![sdes]);
    }

    #[test]
    fn stream_stats_handles_32bit_timestamp_wrap_non_audio_and_dlsr() {
        let mut stats = RtpStreamStats::new();
        stats.record_packet(1, u32::MAX - 79, 10_000);
        stats.record_packet(2, 80, 10_160);
        assert_eq!(stats.jitter(), 0);

        stats.record_non_audio_packet(3);
        stats.record_packet(4, 400, 10_480);
        assert_eq!(stats.received_count(), 4);
        assert_eq!(stats.cumulative_lost(), 0);
        assert_eq!(stats.jitter(), 0);

        stats.record_sender_report_at(0x0102_0304_0506_0708, 1_000);
        let report = stats.build_reception_report_at(0x5555, Some(2_500));
        assert_eq!(report.lsr, 0x0304_0506);
        assert_eq!(report.dlsr, 98_304);
    }

    #[test]
    fn stream_stats_cycles_near_u32_max_do_not_overflow_in_debug() {
        let mut stats = RtpStreamStats {
            initialized: true,
            base_seq: 10,
            max_seq: 65_530,
            cycles: u32::MAX - 0x0001_0000,
            received: 1_000,
            ..RtpStreamStats::new()
        };
        // Wraps past u32::MAX cycles without debug panic on +1 or extended_max.
        stats.record_packet(2, 320, 320);
        let report = stats.build_reception_report(0x7777);
        assert_eq!(report.extended_highest_seq, 0x0000_0001);
        let _ = stats.cumulative_lost();
    }

    #[test]
    fn stream_stats_rfc3550_a1_dropout_probation_and_two_packet_resync() {
        let mut stats = RtpStreamStats::new();
        assert_eq!(stats.record_packet(10, 160, 160), SeqStatus::Accepted);
        assert_eq!(stats.record_packet(11, 320, 320), SeqStatus::Accepted);
        assert_eq!(stats.record_packet(12, 480, 480), SeqStatus::Accepted);

        // Single stray packet with large jump (> MAX_DROPOUT) is placed on probation without disturbing max_seq or received count.
        assert_eq!(
            stats.record_packet(20_000, 3_200_000, 640),
            SeqStatus::ProbationRejected
        );
        assert_eq!(stats.received_count(), 3);
        assert_eq!(stats.snapshot_reception_report(1).extended_highest_seq, 12);

        // Next sequential packet after jump (20_001) resynchronizes the sequence domain.
        assert_eq!(
            stats.record_packet(20_001, 3_200_160, 800),
            SeqStatus::Resynced
        );
        assert_eq!(stats.received_count(), 1);
        assert_eq!(
            stats.snapshot_reception_report(1).extended_highest_seq,
            20_001
        );
        assert_eq!(stats.cumulative_lost(), 0);
    }
}
