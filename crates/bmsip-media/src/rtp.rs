//! MODULE_CONTRACT: RFC 3550 RTP packet parser, serializer, and monotonic `RtpPacketizer`.
//! INVARIANTS: Validates `V=2`, CSRC bounds, extension header length, and PKCS-style trailing padding count; lossless round-trip serialization.
//! RFC_REFS: RFC 3550 Sections 5.1, 5.3.1.

use crate::error::MediaError;

/// Optional RTP header extension (`X=1`) per RFC 3550 Section 5.3.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpExtensionHeader {
    pub profile: u16,
    pub data: Vec<u8>,
}

/// Parsed RTP fixed header plus optional CSRC list and header extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extension_header: Option<RtpExtensionHeader>,
}

/// Complete RTP packet (`header` + unpadded `payload`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

/// Borrowed zero-allocation view of a validated wire RTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpPacketRef<'a> {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub payload: &'a [u8],
}

impl<'a> RtpPacketRef<'a> {
    /// Parses and validates raw RTP wire bytes without heap allocations.
    pub fn parse(raw: &'a [u8]) -> Result<Self, MediaError> {
        let (parsed, _) = parse_rtp_bounds(raw)?;
        Ok(parsed)
    }
}

fn parse_rtp_bounds<'a>(raw: &'a [u8]) -> Result<(RtpPacketRef<'a>, usize), MediaError> {
    if raw.len() < 12 {
        return Err(MediaError::PacketTooShort);
    }

    let version = (raw[0] >> 6) & 0x03;
    if version != 2 {
        return Err(MediaError::UnsupportedRtpVersion(version));
    }

    let padding = (raw[0] & 0x20) != 0;
    let extension = (raw[0] & 0x10) != 0;
    let csrc_count = raw[0] & 0x0f;
    let marker = (raw[1] & 0x80) != 0;
    let payload_type = raw[1] & 0x7f;
    let sequence_number = u16::from_be_bytes([raw[2], raw[3]]);
    let timestamp = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);

    let mut offset = 12usize;
    let csrc_bytes = usize::from(csrc_count) * 4;
    if raw.len() < offset + csrc_bytes {
        return Err(MediaError::PacketTooShort);
    }
    offset += csrc_bytes;

    if extension {
        if raw.len() < offset + 4 {
            return Err(MediaError::PacketTooShort);
        }
        let length_words = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
        offset += 4;
        let ext_bytes = usize::from(length_words) * 4;
        if raw.len() < offset + ext_bytes {
            return Err(MediaError::PacketTooShort);
        }
        offset += ext_bytes;
    }

    let raw_payload = &raw[offset..];
    let payload = if padding {
        let Some(&pad_len_byte) = raw_payload.last() else {
            return Err(MediaError::InvalidHeader(
                "RTP padding bit set with empty payload".to_string(),
            ));
        };
        let pad_len = usize::from(pad_len_byte);
        if pad_len == 0 || pad_len > raw_payload.len() {
            return Err(MediaError::InvalidHeader(format!(
                "invalid RTP padding length {pad_len} for payload len {}",
                raw_payload.len()
            )));
        }
        &raw_payload[..raw_payload.len() - pad_len]
    } else {
        raw_payload
    };

    Ok((
        RtpPacketRef {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            payload,
        },
        12 + csrc_bytes,
    ))
}

impl RtpPacket {
    /// Parses raw wire bytes into an [`RtpPacket`], stripping trailing RTP padding if `P=1`.
    pub fn parse(raw: &[u8]) -> Result<Self, MediaError> {
        let (hdr, ext_offset) = parse_rtp_bounds(raw)?;
        let mut csrcs = Vec::with_capacity(usize::from(hdr.csrc_count));
        for i in 0..usize::from(hdr.csrc_count) {
            let off = 12 + i * 4;
            csrcs.push(u32::from_be_bytes([
                raw[off],
                raw[off + 1],
                raw[off + 2],
                raw[off + 3],
            ]));
        }

        let extension_header = if hdr.extension {
            let profile = u16::from_be_bytes([raw[ext_offset], raw[ext_offset + 1]]);
            let length_words = u16::from_be_bytes([raw[ext_offset + 2], raw[ext_offset + 3]]);
            let ext_bytes = usize::from(length_words) * 4;
            let data = raw[ext_offset + 4..ext_offset + 4 + ext_bytes].to_vec();
            Some(RtpExtensionHeader { profile, data })
        } else {
            None
        };

        Ok(Self {
            header: RtpHeader {
                version: hdr.version,
                padding: hdr.padding,
                extension: hdr.extension,
                csrc_count: hdr.csrc_count,
                marker: hdr.marker,
                payload_type: hdr.payload_type,
                sequence_number: hdr.sequence_number,
                timestamp: hdr.timestamp,
                ssrc: hdr.ssrc,
                csrcs,
                extension_header,
            },
            payload: hdr.payload.to_vec(),
        })
    }

    /// Serializes the [`RtpPacket`] into wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let csrc_count = self.header.csrcs.len().min(15) as u8;
        let has_ext = self.header.extension_header.is_some();
        let b0 = ((self.header.version & 0x03) << 6)
            | (u8::from(self.header.padding) << 5)
            | (u8::from(has_ext) << 4)
            | (csrc_count & 0x0f);
        let b1 = (u8::from(self.header.marker) << 7) | (self.header.payload_type & 0x7f);

        let mut out = Vec::with_capacity(12 + self.payload.len() + 16);
        out.push(b0);
        out.push(b1);
        out.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.header.timestamp.to_be_bytes());
        out.extend_from_slice(&self.header.ssrc.to_be_bytes());

        for csrc in self.header.csrcs.iter().take(15) {
            out.extend_from_slice(&csrc.to_be_bytes());
        }

        if let Some(ext) = &self.header.extension_header {
            let word_count = ext.data.len().div_ceil(4) as u16;
            out.extend_from_slice(&ext.profile.to_be_bytes());
            out.extend_from_slice(&word_count.to_be_bytes());
            out.extend_from_slice(&ext.data);
            let padded_len = usize::from(word_count) * 4;
            out.resize(out.len() + (padded_len - ext.data.len()), 0);
        }

        out.extend_from_slice(&self.payload);
        if self.header.padding {
            // Append minimal 1-byte self-describing padding so parse() recovers exact payload.
            out.push(1);
        }
        out
    }
}

/// Generates sequential RTP packets for an outbound media stream.
#[derive(Debug, Clone)]
pub struct RtpPacketizer {
    ssrc: u32,
    payload_type: u8,
    sequence_number: u16,
    timestamp: u32,
    first_packet: bool,
}

impl RtpPacketizer {
    /// Creates an [`RtpPacketizer`] starting at `initial_seq` and `initial_timestamp`.
    pub fn new(ssrc: u32, payload_type: u8, initial_seq: u16, initial_timestamp: u32) -> Self {
        Self {
            ssrc,
            payload_type,
            sequence_number: initial_seq,
            timestamp: initial_timestamp,
            first_packet: true,
        }
    }

    /// Returns the stream SSRC.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Returns the configured RTP payload type.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns the next timestamp to be stamped.
    pub fn current_timestamp(&self) -> u32 {
        self.timestamp
    }

    /// Returns the next sequence number to be stamped.
    pub fn current_sequence(&self) -> u16 {
        self.sequence_number
    }

    /// Builds an RTP packet with the current sequence/timestamp and advances both counters.
    pub fn next_packet(
        &mut self,
        payload: Vec<u8>,
        samples_advanced: u32,
        marker: bool,
    ) -> RtpPacket {
        let m = self.first_packet || marker;
        self.first_packet = false;

        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: m,
                payload_type: self.payload_type,
                sequence_number: self.sequence_number,
                timestamp: self.timestamp,
                ssrc: self.ssrc,
                csrcs: Vec::new(),
                extension_header: None,
            },
            payload,
        };

        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(samples_advanced);
        pkt
    }

    /// Serializes the next RTP packet directly into wire bytes without intermediate allocations.
    pub fn next_packet_bytes(
        &mut self,
        payload: &[u8],
        samples_advanced: u32,
        marker: bool,
    ) -> Vec<u8> {
        let m = self.first_packet || marker;
        self.first_packet = false;
        let out = serialize_simple_rtp(
            self.payload_type,
            m,
            self.sequence_number,
            self.timestamp,
            self.ssrc,
            payload,
        );
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(samples_advanced);
        out
    }

    /// Builds an RTP packet with an alternate payload type (e.g. RFC 4733 DTMF) without advancing main media clock unless requested.
    pub fn build_custom_packet(
        &mut self,
        payload_type: u8,
        timestamp: u32,
        marker: bool,
        payload: Vec<u8>,
    ) -> RtpPacket {
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker,
                payload_type,
                sequence_number: self.sequence_number,
                timestamp,
                ssrc: self.ssrc,
                csrcs: Vec::new(),
                extension_header: None,
            },
            payload,
        };
        self.sequence_number = self.sequence_number.wrapping_add(1);
        pkt
    }

    /// Serializes an alternate payload-type RTP packet directly to wire bytes.
    pub fn build_custom_packet_bytes(
        &mut self,
        payload_type: u8,
        timestamp: u32,
        marker: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let out = serialize_simple_rtp(
            payload_type,
            marker,
            self.sequence_number,
            timestamp,
            self.ssrc,
            payload,
        );
        self.sequence_number = self.sequence_number.wrapping_add(1);
        out
    }
}

fn serialize_simple_rtp(
    payload_type: u8,
    marker: bool,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.push(0x80); // V=2, P=0, X=0, CC=0
    out.push((u8::from(marker) << 7) | (payload_type & 0x7f));
    out.extend_from_slice(&sequence_number.to_be_bytes());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&ssrc.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_roundtrip_with_csrc_extension_and_padding() {
        let pkt = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: true,
                extension: true,
                csrc_count: 2,
                marker: true,
                payload_type: 0,
                sequence_number: 4201,
                timestamp: 160_000,
                ssrc: 0xdead_beef,
                csrcs: vec![0x1111_2222, 0x3333_4444],
                extension_header: Some(RtpExtensionHeader {
                    profile: 0xbede,
                    data: vec![1, 2, 3, 4],
                }),
            },
            payload: vec![0x7f; 160],
        };

        let wire = pkt.to_bytes();
        let parsed = RtpPacket::parse(&wire).unwrap();
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn rejects_invalid_rtp_packets() {
        assert_eq!(RtpPacket::parse(&[0u8; 5]), Err(MediaError::PacketTooShort));
        let mut bad_ver = [0u8; 12];
        bad_ver[0] = 0x40; // V=1
        assert_eq!(
            RtpPacket::parse(&bad_ver),
            Err(MediaError::UnsupportedRtpVersion(1))
        );
    }
}
