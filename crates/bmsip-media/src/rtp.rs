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

impl RtpPacket {
    /// Parses raw wire bytes into an [`RtpPacket`], stripping trailing RTP padding if `P=1`.
    pub fn parse(raw: &[u8]) -> Result<Self, MediaError> {
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
        let mut csrcs = Vec::with_capacity(usize::from(csrc_count));
        for _ in 0..csrc_count {
            let val = u32::from_be_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]);
            csrcs.push(val);
            offset += 4;
        }

        let extension_header = if extension {
            if raw.len() < offset + 4 {
                return Err(MediaError::PacketTooShort);
            }
            let profile = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
            let length_words = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]);
            offset += 4;
            let ext_bytes = usize::from(length_words) * 4;
            if raw.len() < offset + ext_bytes {
                return Err(MediaError::PacketTooShort);
            }
            let data = raw[offset..offset + ext_bytes].to_vec();
            offset += ext_bytes;
            Some(RtpExtensionHeader { profile, data })
        } else {
            None
        };

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
            raw_payload[..raw_payload.len() - pad_len].to_vec()
        } else {
            raw_payload.to_vec()
        };

        Ok(Self {
            header: RtpHeader {
                version,
                padding,
                extension,
                csrc_count,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrcs,
                extension_header,
            },
            payload,
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
