//! MODULE_CONTRACT: Pure-Rust `#![forbid(unsafe_code)]` RFC 3711 SRTP & SRTCP cryptographic engine (`AES_CM_128_HMAC_SHA1_80` / `AES_CM_128_HMAC_SHA1_32`) and RFC 5764 key material splitter.
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero external crate dependencies; implements FIPS 197 AES-128, FIPS 180-4 SHA-1, RFC 2104 HMAC-SHA1, RFC 3711 §4.3.1 KDF, per-SSRC 48-bit ROC & 64-packet sliding replay window (authenticated before state mutation), RFC 3711 §9.2 key lifetime enforcement, constant-time MAC verification, and zeroization of key material on `Drop`.
//! RFC_REFS: FIPS 197 (AES-128), FIPS 180-4 (SHA-1), RFC 2104 (HMAC), RFC 3711 (SRTP/SRTCP), RFC 4568 (SDES), RFC 5764 (DTLS-SRTP).

use bmsip_core::sdp::SrtpSuite;

use crate::error::MediaError;

const MAX_TRACKED_SSRCS: usize = 16;
const MAX_SRTP_PACKETS: u64 = (1u64 << 48) - 1;
const MAX_SRTCP_INDEX: u32 = 0x7fff_ffff;

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(buf);
}

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const AES_RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const LABEL_SRTP_ENC: u8 = 0x00;
const LABEL_SRTP_AUTH: u8 = 0x01;
const LABEL_SRTP_SALT: u8 = 0x02;
const LABEL_SRTCP_ENC: u8 = 0x03;
const LABEL_SRTCP_AUTH: u8 = 0x04;
const LABEL_SRTCP_SALT: u8 = 0x05;

/// 30-byte SRTP master key (16 bytes) and master salt (14 bytes). Wiped on [`Drop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpKeyMaterial {
    pub master_key: [u8; 16],
    pub master_salt: [u8; 14],
}

impl Drop for SrtpKeyMaterial {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.master_key);
        zeroize_bytes(&mut self.master_salt);
    }
}

impl SrtpKeyMaterial {
    /// Creates [`SrtpKeyMaterial`] from a concatenated 30-byte `master_key[16] || master_salt[14]` array.
    pub fn from_key_salt(key_salt: &[u8; 30]) -> Self {
        let mut master_key = [0u8; 16];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&key_salt[..16]);
        master_salt.copy_from_slice(&key_salt[16..30]);
        Self {
            master_key,
            master_salt,
        }
    }

    /// Concatenates `master_key` and `master_salt` into a 30-byte array.
    pub fn to_key_salt(&self) -> [u8; 30] {
        let mut out = [0u8; 30];
        out[..16].copy_from_slice(&self.master_key);
        out[16..30].copy_from_slice(&self.master_salt);
        out
    }

    /// Splits a 60-byte RFC 5764 §4.2 `"EXTRACTOR-dtls_srtp"` exporter buffer into `(tx_material, rx_material)`
    /// for either the DTLS client (`is_client = true`, `a=setup:active`) or DTLS server (`is_client = false`, `a=setup:passive`).
    pub fn from_dtls_exporter_output(
        exported: &[u8],
        is_client: bool,
    ) -> Result<(Self, Self), MediaError> {
        if exported.len() < 60 {
            return Err(MediaError::SrtpError(format!(
                "DTLS-SRTP exporter buffer too short: expected >= 60 bytes, got {}",
                exported.len()
            )));
        }
        let mut client_key = [0u8; 16];
        let mut server_key = [0u8; 16];
        let mut client_salt = [0u8; 14];
        let mut server_salt = [0u8; 14];
        client_key.copy_from_slice(&exported[0..16]);
        server_key.copy_from_slice(&exported[16..32]);
        client_salt.copy_from_slice(&exported[32..46]);
        server_salt.copy_from_slice(&exported[46..60]);

        let client_mat = Self {
            master_key: client_key,
            master_salt: client_salt,
        };
        let server_mat = Self {
            master_key: server_key,
            master_salt: server_salt,
        };
        if is_client {
            Ok((client_mat, server_mat))
        } else {
            Ok((server_mat, client_mat))
        }
    }
}

/// Derived RFC 3711 §4.3 session keys for one direction (TX or RX). Wiped on [`Drop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedSrtpKeys {
    pub rtp_cipher_key: [u8; 16],
    pub rtp_auth_key: [u8; 20],
    pub rtp_salt: [u8; 14],
    pub rtcp_cipher_key: [u8; 16],
    pub rtcp_auth_key: [u8; 20],
    pub rtcp_salt: [u8; 14],
}

impl Drop for DerivedSrtpKeys {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.rtp_cipher_key);
        zeroize_bytes(&mut self.rtp_auth_key);
        zeroize_bytes(&mut self.rtp_salt);
        zeroize_bytes(&mut self.rtcp_cipher_key);
        zeroize_bytes(&mut self.rtcp_auth_key);
        zeroize_bytes(&mut self.rtcp_salt);
    }
}

/// Derives SRTP and SRTCP session encryption, authentication, and salt keys per RFC 3711 §4.3.1 & §4.3.2.
pub fn derive_srtp_session_keys(material: &SrtpKeyMaterial) -> DerivedSrtpKeys {
    let mut rtp_cipher_key = [0u8; 16];
    let mut rtp_auth_key = [0u8; 20];
    let mut rtp_salt = [0u8; 14];
    let mut rtcp_cipher_key = [0u8; 16];
    let mut rtcp_auth_key = [0u8; 20];
    let mut rtcp_salt = [0u8; 14];

    kdf_prf_aes128(
        &material.master_key,
        &material.master_salt,
        LABEL_SRTP_ENC,
        &mut rtp_cipher_key,
    );
    kdf_prf_aes128(
        &material.master_key,
        &material.master_salt,
        LABEL_SRTP_AUTH,
        &mut rtp_auth_key,
    );
    kdf_prf_aes128(
        &material.master_key,
        &material.master_salt,
        LABEL_SRTP_SALT,
        &mut rtp_salt,
    );
    kdf_prf_aes128(
        &material.master_key,
        &material.master_salt,
        LABEL_SRTCP_ENC,
        &mut rtcp_cipher_key,
    );
    kdf_prf_aes128(
        &material.master_key,
        &material.master_salt,
        LABEL_SRTCP_AUTH,
        &mut rtcp_auth_key,
    );
    kdf_prf_aes128(
        &material.master_key,
        &material.master_salt,
        LABEL_SRTCP_SALT,
        &mut rtcp_salt,
    );

    DerivedSrtpKeys {
        rtp_cipher_key,
        rtp_auth_key,
        rtp_salt,
        rtcp_cipher_key,
        rtcp_auth_key,
        rtcp_salt,
    }
}

#[derive(Debug, Clone)]
struct SsrcStreamState {
    ssrc: u32,
    roc: u32,
    highest_seq: Option<u16>,
    rtp_replay_window: u64,
    highest_rtp_index: Option<u64>,
    rtp_packets_processed: u64,
    srtcp_index: u32,
    rtcp_replay_window: u64,
    highest_rtcp_index: Option<u32>,
    last_used_tick: u64,
}

impl SsrcStreamState {
    fn new(ssrc: u32, tick: u64) -> Self {
        Self {
            ssrc,
            roc: 0,
            highest_seq: None,
            rtp_replay_window: 0,
            highest_rtp_index: None,
            rtp_packets_processed: 0,
            srtcp_index: 0,
            rtcp_replay_window: 0,
            highest_rtcp_index: None,
            last_used_tick: tick,
        }
    }

    fn estimate_packet_index(&self, seq: u16) -> Result<(u32, u64), MediaError> {
        let Some(s_l) = self.highest_seq else {
            let idx = (u64::from(self.roc) << 16) | u64::from(seq);
            return Ok((self.roc, idx));
        };

        // RFC 3711 Appendix A: estimate v (candidate ROC) from s_l and seq.
        let v = if s_l < 32_768 {
            if seq > s_l && (seq - s_l) > 32_768 {
                if self.roc == 0 {
                    return Err(MediaError::SrtpError(
                        "SRTP packet precedes initial ROC=0 window".to_string(),
                    ));
                }
                self.roc - 1
            } else {
                self.roc
            }
        } else if s_l >= 32_768 && (s_l - 32_768) > seq {
            self.roc.checked_add(1).ok_or(MediaError::SrtpKeyExpired)?
        } else {
            self.roc
        };
        let idx = (u64::from(v) << 16) | u64::from(seq);
        Ok((v, idx))
    }

    fn advance_seq_state(&mut self, seq: u16, est_roc: u32, pkt_index: u64) {
        if self.highest_rtp_index.is_none_or(|prev| pkt_index > prev) {
            self.highest_seq = Some(seq);
            self.roc = est_roc;
        }
        self.commit_rtp_replay(pkt_index);
    }

    fn check_rtp_replay(&self, pkt_index: u64) -> Result<(), MediaError> {
        let Some(top) = self.highest_rtp_index else {
            return Ok(());
        };
        if pkt_index > top {
            return Ok(());
        }
        let delta = top - pkt_index;
        if delta >= 64 {
            return Err(MediaError::SrtpError(
                "SRTP packet outside 64-packet replay window".to_string(),
            ));
        }
        if (self.rtp_replay_window & (1u64 << delta)) != 0 {
            return Err(MediaError::SrtpError(
                "replayed SRTP packet detected".to_string(),
            ));
        }
        Ok(())
    }

    fn commit_rtp_replay(&mut self, pkt_index: u64) {
        match self.highest_rtp_index {
            None => {
                self.highest_rtp_index = Some(pkt_index);
                self.rtp_replay_window = 1;
            }
            Some(top) if pkt_index > top => {
                let shift = pkt_index - top;
                if shift >= 64 {
                    self.rtp_replay_window = 1;
                } else {
                    self.rtp_replay_window = (self.rtp_replay_window << shift) | 1;
                }
                self.highest_rtp_index = Some(pkt_index);
            }
            Some(top) => {
                let delta = top - pkt_index;
                if delta < 64 {
                    self.rtp_replay_window |= 1u64 << delta;
                }
            }
        }
    }

    fn check_rtcp_replay(&self, idx: u32) -> Result<(), MediaError> {
        let Some(top) = self.highest_rtcp_index else {
            return Ok(());
        };
        if idx > top {
            return Ok(());
        }
        let delta = top - idx;
        if delta >= 64 {
            return Err(MediaError::SrtpError(
                "SRTCP packet outside 64-packet replay window".to_string(),
            ));
        }
        if (self.rtcp_replay_window & (1u64 << delta)) != 0 {
            return Err(MediaError::SrtpError(
                "replayed SRTCP packet detected".to_string(),
            ));
        }
        Ok(())
    }

    fn commit_rtcp_replay(&mut self, idx: u32) {
        match self.highest_rtcp_index {
            None => {
                self.highest_rtcp_index = Some(idx);
                self.rtcp_replay_window = 1;
            }
            Some(top) if idx > top => {
                let shift = idx - top;
                if shift >= 64 {
                    self.rtcp_replay_window = 1;
                } else {
                    self.rtcp_replay_window = (self.rtcp_replay_window << shift) | 1;
                }
                self.highest_rtcp_index = Some(idx);
            }
            Some(top) => {
                let delta = top - idx;
                if delta < 64 {
                    self.rtcp_replay_window |= 1u64 << delta;
                }
            }
        }
    }
}

/// Stateful RFC 3711 SRTP & SRTCP cryptographic context for one stream direction with per-SSRC ROC and replay tracking.
#[derive(Debug, Clone)]
pub struct SrtpContext {
    suite: SrtpSuite,
    keys: DerivedSrtpKeys,
    rtp_round_keys: [[u8; 16]; 11],
    rtcp_round_keys: [[u8; 16]; 11],
    streams: Vec<SsrcStreamState>,
    access_tick: u64,
    last_active_ssrc: Option<u32>,
}

impl Drop for SrtpContext {
    fn drop(&mut self) {
        for rk in &mut self.rtp_round_keys {
            zeroize_bytes(rk);
        }
        for rk in &mut self.rtcp_round_keys {
            zeroize_bytes(rk);
        }
    }
}

impl SrtpContext {
    /// Initializes an [`SrtpContext`] from [`SrtpSuite`] and [`SrtpKeyMaterial`].
    pub fn new(suite: SrtpSuite, material: SrtpKeyMaterial) -> Self {
        let keys = derive_srtp_session_keys(&material);
        let rtp_round_keys = aes128_expand_key(&keys.rtp_cipher_key);
        let rtcp_round_keys = aes128_expand_key(&keys.rtcp_cipher_key);
        Self {
            suite,
            keys,
            rtp_round_keys,
            rtcp_round_keys,
            streams: Vec::new(),
            access_tick: 0,
            last_active_ssrc: None,
        }
    }

    /// Initializes an [`SrtpContext`] directly from a 30-byte `master_key || master_salt` array.
    pub fn from_key_salt(suite: SrtpSuite, key_salt: &[u8; 30]) -> Self {
        Self::new(suite, SrtpKeyMaterial::from_key_salt(key_salt))
    }

    /// Returns the configured [`SrtpSuite`].
    pub fn suite(&self) -> SrtpSuite {
        self.suite
    }

    /// Returns the 32-bit SRTP Rollover Counter (`ROC`) of the most recently active SSRC (or `0` if none).
    pub fn roc(&self) -> u32 {
        self.last_active_ssrc
            .and_then(|ssrc| self.roc_for_ssrc(ssrc))
            .unwrap_or(0)
    }

    /// Returns the 32-bit SRTP Rollover Counter (`ROC`) tracked for a specific `ssrc`, if known.
    pub fn roc_for_ssrc(&self, ssrc: u32) -> Option<u32> {
        self.streams.iter().find(|s| s.ssrc == ssrc).map(|s| s.roc)
    }

    /// Returns the number of distinct authenticated SSRCs currently tracked in this context.
    pub fn tracked_ssrc_count(&self) -> usize {
        self.streams.len()
    }

    fn find_or_insert_stream(&mut self, ssrc: u32) -> &mut SsrcStreamState {
        self.access_tick = self.access_tick.saturating_add(1);
        let tick = self.access_tick;
        self.last_active_ssrc = Some(ssrc);

        if let Some(pos) = self.streams.iter().position(|s| s.ssrc == ssrc) {
            self.streams[pos].last_used_tick = tick;
            return &mut self.streams[pos];
        }

        if self.streams.len() >= MAX_TRACKED_SSRCS {
            if let Some((evict_idx, _)) = self
                .streams
                .iter()
                .enumerate()
                .min_by_key(|(_, s)| s.last_used_tick)
            {
                self.streams.swap_remove(evict_idx);
            }
        }
        self.streams.push(SsrcStreamState::new(ssrc, tick));
        let idx = self.streams.len() - 1;
        &mut self.streams[idx]
    }

    /// Encrypts and authenticates an outbound RTP packet into an SRTP wire packet (RFC 3711 §3.3).
    pub fn protect_rtp(&mut self, rtp_packet: &[u8]) -> Result<Vec<u8>, MediaError> {
        let header_len = rtp_header_len(rtp_packet)?;
        let seq = u16::from_be_bytes([rtp_packet[2], rtp_packet[3]]);
        let ssrc =
            u32::from_be_bytes([rtp_packet[8], rtp_packet[9], rtp_packet[10], rtp_packet[11]]);

        let (est_roc, pkt_index) = {
            let stream = self.find_or_insert_stream(ssrc);
            if stream.rtp_packets_processed >= MAX_SRTP_PACKETS {
                return Err(MediaError::SrtpKeyExpired);
            }
            let (est_roc, pkt_index) = stream.estimate_packet_index(seq)?;
            stream.advance_seq_state(seq, est_roc, pkt_index);
            stream.rtp_packets_processed = stream.rtp_packets_processed.saturating_add(1);
            (est_roc, pkt_index)
        };

        let tag_len = self.suite.rtp_auth_tag_len();
        let mut out = Vec::with_capacity(rtp_packet.len() + tag_len);
        out.extend_from_slice(rtp_packet);

        aes128_cm_xor(
            &self.rtp_round_keys,
            &self.keys.rtp_salt,
            ssrc,
            pkt_index,
            &mut out[header_len..],
        );

        let tag = compute_srtp_auth_tag(&self.keys.rtp_auth_key, &out, est_roc);
        out.extend_from_slice(&tag[..tag_len]);
        Ok(out)
    }

    /// Verifies per-SSRC replay window, authenticates HMAC-SHA1 tag, and decrypts an inbound SRTP packet into a plaintext RTP packet.
    ///
    /// New SSRC entries are allocated strictly after HMAC authentication succeeds so forged SSRCs cannot evict active streams.
    pub fn unprotect_rtp(&mut self, srtp_packet: &[u8]) -> Result<Vec<u8>, MediaError> {
        let tag_len = self.suite.rtp_auth_tag_len();
        if srtp_packet.len() < 12 + tag_len {
            return Err(MediaError::PacketTooShort);
        }
        let signed_len = srtp_packet.len() - tag_len;
        let signed_portion = &srtp_packet[..signed_len];
        let wire_tag = &srtp_packet[signed_len..];

        let header_len = rtp_header_len(signed_portion)?;
        let seq = u16::from_be_bytes([signed_portion[2], signed_portion[3]]);
        let ssrc = u32::from_be_bytes([
            signed_portion[8],
            signed_portion[9],
            signed_portion[10],
            signed_portion[11],
        ]);

        let (est_roc, pkt_index) =
            if let Some(stream) = self.streams.iter().find(|s| s.ssrc == ssrc) {
                if stream.rtp_packets_processed >= MAX_SRTP_PACKETS {
                    return Err(MediaError::SrtpKeyExpired);
                }
                let (est_roc, pkt_index) = stream.estimate_packet_index(seq)?;
                stream.check_rtp_replay(pkt_index)?;
                (est_roc, pkt_index)
            } else {
                // RFC 3711 §3.3.1: newly observed SSRC begins at ROC = 0.
                (0u32, u64::from(seq))
            };

        let expected_tag = compute_srtp_auth_tag(&self.keys.rtp_auth_key, signed_portion, est_roc);
        if !constant_time_eq(wire_tag, &expected_tag[..tag_len]) {
            return Err(MediaError::SrtpError(
                "SRTP authentication tag verification failed".to_string(),
            ));
        }

        let stream = self.find_or_insert_stream(ssrc);
        stream.advance_seq_state(seq, est_roc, pkt_index);
        stream.rtp_packets_processed = stream.rtp_packets_processed.saturating_add(1);

        let mut out = signed_portion.to_vec();
        aes128_cm_xor(
            &self.rtp_round_keys,
            &self.keys.rtp_salt,
            ssrc,
            pkt_index,
            &mut out[header_len..],
        );
        Ok(out)
    }

    /// Encrypts and authenticates an outbound compound RTCP packet into an SRTCP packet (RFC 3711 §3.4).
    pub fn protect_rtcp(&mut self, rtcp_packet: &[u8]) -> Result<Vec<u8>, MediaError> {
        if rtcp_packet.len() < 8 {
            return Err(MediaError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([
            rtcp_packet[4],
            rtcp_packet[5],
            rtcp_packet[6],
            rtcp_packet[7],
        ]);
        let idx = {
            let stream = self.find_or_insert_stream(ssrc);
            if stream.srtcp_index >= MAX_SRTCP_INDEX {
                return Err(MediaError::SrtpKeyExpired);
            }
            stream.srtcp_index += 1;
            stream.srtcp_index
        };

        let tag_len = self.suite.rtcp_auth_tag_len();
        let mut out = Vec::with_capacity(rtcp_packet.len() + 4 + tag_len);
        out.extend_from_slice(rtcp_packet);

        // RFC 3711 §3.4: first 8 bytes (RTCP fixed header + sender SSRC) stay in the clear;
        // remaining compound RTCP bytes are encrypted with AES-CM.
        aes128_cm_xor(
            &self.rtcp_round_keys,
            &self.keys.rtcp_salt,
            ssrc,
            u64::from(idx),
            &mut out[8..],
        );

        let e_and_index = 0x8000_0000u32 | idx;
        out.extend_from_slice(&e_and_index.to_be_bytes());
        let tag = hmac_sha1(&self.keys.rtcp_auth_key, &out);
        out.extend_from_slice(&tag[..tag_len]);
        Ok(out)
    }

    /// Verifies per-SSRC replay window, authenticates HMAC-SHA1 tag, and decrypts an inbound SRTCP packet into a compound RTCP packet.
    pub fn unprotect_rtcp(&mut self, srtcp_packet: &[u8]) -> Result<Vec<u8>, MediaError> {
        let tag_len = self.suite.rtcp_auth_tag_len();
        if srtcp_packet.len() < 8 + 4 + tag_len {
            return Err(MediaError::PacketTooShort);
        }
        let signed_len = srtcp_packet.len() - tag_len;
        let rtcp_len = signed_len - 4;
        let signed_portion = &srtcp_packet[..signed_len];
        let wire_tag = &srtcp_packet[signed_len..];

        let ssrc = u32::from_be_bytes([
            signed_portion[4],
            signed_portion[5],
            signed_portion[6],
            signed_portion[7],
        ]);
        let e_and_index = u32::from_be_bytes([
            signed_portion[rtcp_len],
            signed_portion[rtcp_len + 1],
            signed_portion[rtcp_len + 2],
            signed_portion[rtcp_len + 3],
        ]);
        let is_encrypted = (e_and_index & 0x8000_0000) != 0;
        let idx = e_and_index & 0x7fff_ffff;

        if let Some(stream) = self.streams.iter().find(|s| s.ssrc == ssrc) {
            stream.check_rtcp_replay(idx)?;
        }

        let expected_tag = hmac_sha1(&self.keys.rtcp_auth_key, signed_portion);
        if !constant_time_eq(wire_tag, &expected_tag[..tag_len]) {
            return Err(MediaError::SrtpError(
                "SRTCP authentication tag verification failed".to_string(),
            ));
        }

        let stream = self.find_or_insert_stream(ssrc);
        stream.commit_rtcp_replay(idx);

        let mut out = signed_portion[..rtcp_len].to_vec();
        if is_encrypted {
            aes128_cm_xor(
                &self.rtcp_round_keys,
                &self.keys.rtcp_salt,
                ssrc,
                u64::from(idx),
                &mut out[8..],
            );
        }
        Ok(out)
    }
}

fn rtp_header_len(raw: &[u8]) -> Result<usize, MediaError> {
    if raw.len() < 12 {
        return Err(MediaError::PacketTooShort);
    }
    let version = (raw[0] >> 6) & 0x03;
    if version != 2 {
        return Err(MediaError::UnsupportedRtpVersion(version));
    }
    let extension = (raw[0] & 0x10) != 0;
    let csrc_count = usize::from(raw[0] & 0x0f);
    let mut offset = 12 + csrc_count * 4;
    if raw.len() < offset {
        return Err(MediaError::PacketTooShort);
    }
    if extension {
        if raw.len() < offset + 4 {
            return Err(MediaError::PacketTooShort);
        }
        let ext_words = usize::from(u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]));
        offset += 4 + ext_words * 4;
        if raw.len() < offset {
            return Err(MediaError::PacketTooShort);
        }
    }
    Ok(offset)
}

fn kdf_prf_aes128(master_key: &[u8; 16], master_salt: &[u8; 14], label: u8, out: &mut [u8]) {
    let mut round_keys = aes128_expand_key(master_key);
    let mut x = *master_salt;
    // RFC 3711 §4.3.1: key_id = <label> || r (r = 0 for k_dr = 0), XORed at byte 7 (48 bits from right).
    x[7] ^= label;

    let mut block_num = 0u16;
    let mut written = 0usize;
    while written < out.len() {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&x);
        iv[14..16].copy_from_slice(&block_num.to_be_bytes());
        let mut keystream = aes128_encrypt_with_round_keys(&round_keys, &iv);
        let take = (out.len() - written).min(16);
        out[written..written + take].copy_from_slice(&keystream[..take]);
        zeroize_bytes(&mut keystream);
        written += take;
        block_num = block_num.wrapping_add(1);
    }
    for rk in &mut round_keys {
        zeroize_bytes(rk);
    }
    zeroize_bytes(&mut x);
}

fn aes128_cm_xor(
    round_keys: &[[u8; 16]; 11],
    session_salt: &[u8; 14],
    ssrc: u32,
    pkt_index_48: u64,
    payload: &mut [u8],
) {
    // RFC 3711 §4.1.1: IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16).
    let mut base_iv = [0u8; 16];
    base_iv[..14].copy_from_slice(session_salt);
    let ssrc_be = ssrc.to_be_bytes();
    for i in 0..4 {
        base_iv[4 + i] ^= ssrc_be[i];
    }
    let idx_be = pkt_index_48.to_be_bytes();
    for i in 0..6 {
        base_iv[8 + i] ^= idx_be[2 + i];
    }

    for (blk_idx, chunk) in payload.chunks_mut(16).enumerate() {
        let mut counter_block = base_iv;
        counter_block[14..16].copy_from_slice(&(blk_idx as u16).to_be_bytes());
        let keystream = aes128_encrypt_with_round_keys(round_keys, &counter_block);
        for (b, k) in chunk.iter_mut().zip(keystream.iter()) {
            *b ^= *k;
        }
    }
}

/// Encrypts a single 16-byte block with AES-128 (FIPS 197).
pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let round_keys = aes128_expand_key(key);
    aes128_encrypt_with_round_keys(&round_keys, block)
}

fn aes128_expand_key(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut w = [0u8; 176];
    w[..16].copy_from_slice(key);

    for i in 4..44 {
        let prev_off = (i - 1) * 4;
        let mut temp = [
            w[prev_off],
            w[prev_off + 1],
            w[prev_off + 2],
            w[prev_off + 3],
        ];
        if i % 4 == 0 {
            temp = [
                AES_SBOX[usize::from(temp[1])] ^ AES_RCON[(i / 4) - 1],
                AES_SBOX[usize::from(temp[2])],
                AES_SBOX[usize::from(temp[3])],
                AES_SBOX[usize::from(temp[0])],
            ];
        }
        let back_off = (i - 4) * 4;
        let cur_off = i * 4;
        for j in 0..4 {
            w[cur_off + j] = w[back_off + j] ^ temp[j];
        }
    }

    let mut round_keys = [[0u8; 16]; 11];
    for (r, rk) in round_keys.iter_mut().enumerate() {
        rk.copy_from_slice(&w[r * 16..(r + 1) * 16]);
    }
    zeroize_bytes(&mut w);
    round_keys
}

#[inline]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ if (x & 0x80) != 0 { 0x1b } else { 0x00 }
}

fn aes128_encrypt_with_round_keys(round_keys: &[[u8; 16]; 11], block: &[u8; 16]) -> [u8; 16] {
    let mut s = *block;
    for i in 0..16 {
        s[i] ^= round_keys[0][i];
    }

    for rk in round_keys.iter().take(10).skip(1) {
        for b in &mut s {
            *b = AES_SBOX[usize::from(*b)];
        }
        s = [
            s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12],
            s[1], s[6], s[11],
        ];
        for col in 0..4 {
            let c = col * 4;
            let (s0, s1, s2, s3) = (s[c], s[c + 1], s[c + 2], s[c + 3]);
            let t = s0 ^ s1 ^ s2 ^ s3;
            s[c] ^= t ^ xtime(s0 ^ s1);
            s[c + 1] ^= t ^ xtime(s1 ^ s2);
            s[c + 2] ^= t ^ xtime(s2 ^ s3);
            s[c + 3] ^= t ^ xtime(s3 ^ s0);
        }
        for i in 0..16 {
            s[i] ^= rk[i];
        }
    }

    for b in &mut s {
        *b = AES_SBOX[usize::from(*b)];
    }
    s = [
        s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1],
        s[6], s[11],
    ];
    for i in 0..16 {
        s[i] ^= round_keys[10][i];
    }
    s
}

/// Computes the 20-byte SHA-1 digest (FIPS 180-4) of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_len = (data.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xefcdab89;
    let mut h2: u32 = 0x98badcfe;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xc3d2e1f0;

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word_bytes) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word_bytes);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdcu32),
                _ => (b ^ c ^ d, 0xca62c1d6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Computes the 20-byte RFC 2104 HMAC-SHA1 of `data` under `key`.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha1(key);
        k_block[..20].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(64 + data.len());
    for &b in &k_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner_hash = sha1(&inner);

    let mut outer = [0u8; 64 + 20];
    for (i, &b) in k_block.iter().enumerate() {
        outer[i] = b ^ 0x5c;
    }
    outer[64..84].copy_from_slice(&inner_hash);
    let mac = sha1(&outer);
    zeroize_bytes(&mut k_block);
    zeroize_bytes(&mut inner);
    zeroize_bytes(&mut outer);
    mac
}

fn compute_srtp_auth_tag(auth_key: &[u8; 20], packet: &[u8], roc: u32) -> [u8; 20] {
    let mut auth_input = Vec::with_capacity(packet.len() + 4);
    auth_input.extend_from_slice(packet);
    auth_input.extend_from_slice(&roc.to_be_bytes());
    hmac_sha1(auth_key, &auth_input)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtcp::RtcpPacket;
    use crate::rtp::RtpPacketizer;

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let clean: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        clean
            .chunks(2)
            .map(|pair| {
                let s = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(s, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn verifies_fips197_aes128_and_rfc2202_hmac_sha1_vectors() {
        let key: [u8; 16] = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
            .try_into()
            .unwrap();
        let pt: [u8; 16] = hex_to_bytes("3243f6a8885a308d313198a2e0370734")
            .try_into()
            .unwrap();
        let expected_ct: [u8; 16] = hex_to_bytes("3925841d02dc09fbdc118597196a0b32")
            .try_into()
            .unwrap();
        assert_eq!(aes128_encrypt_block(&key, &pt), expected_ct);

        let mac = hmac_sha1(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.as_slice(),
            hex_to_bytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").as_slice()
        );
    }

    #[test]
    fn verifies_rfc3711_appendix_b3_kdf_test_vectors() {
        let master_key: [u8; 16] = hex_to_bytes("E1F97A0D3E018BE0D64FA32C06DE4139")
            .try_into()
            .unwrap();
        let master_salt: [u8; 14] = hex_to_bytes("0EC675AD498AFEEBB6960B3AABE6")
            .try_into()
            .unwrap();
        let derived = derive_srtp_session_keys(&SrtpKeyMaterial {
            master_key,
            master_salt,
        });

        assert_eq!(
            derived.rtp_cipher_key.as_slice(),
            hex_to_bytes("C61E7A93744F39EE10734AFE3FF7A087").as_slice()
        );
        assert_eq!(
            derived.rtp_salt.as_slice(),
            hex_to_bytes("30CBBC08863D8C85D49DB34A9AE1").as_slice()
        );
        assert_eq!(
            derived.rtp_auth_key.as_slice(),
            hex_to_bytes("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4").as_slice()
        );
    }

    #[test]
    fn srtp_and_srtcp_roundtrip_rollover_and_replay_rejection() {
        for suite in [
            SrtpSuite::AesCm128HmacSha1_80,
            SrtpSuite::AesCm128HmacSha1_32,
        ] {
            let key_salt = [0x42u8; 30];
            let mut tx = SrtpContext::from_key_salt(suite, &key_salt);
            let mut rx = SrtpContext::from_key_salt(suite, &key_salt);

            // Start near 16-bit sequence wraparound (65534 -> 65535 -> 0 -> 1) to verify ROC advancement.
            let mut packetizer = RtpPacketizer::new(0x1234_5678, 0, 65_534, 160);
            let mut history: Vec<Vec<u8>> = Vec::new();
            for step in 0..5 {
                let plain = packetizer.next_packet_bytes(&[step as u8; 160], 160, false);
                let encrypted = tx.protect_rtp(&plain).unwrap();
                assert_eq!(encrypted.len(), plain.len() + suite.rtp_auth_tag_len());
                assert_ne!(
                    &encrypted[12..12 + 160],
                    &plain[12..12 + 160],
                    "SRTP payload must be encrypted"
                );

                let decrypted = rx.unprotect_rtp(&encrypted).unwrap();
                assert_eq!(decrypted, plain);

                // Replay of the current or any earlier SRTP packet in the 64-packet window must be rejected.
                assert!(rx.unprotect_rtp(&encrypted).is_err());
                for earlier in &history {
                    assert!(
                        rx.unprotect_rtp(earlier.as_slice()).is_err(),
                        "older packet replay in sliding window must be rejected"
                    );
                }
                history.push(encrypted.clone());

                // Tampering with ciphertext or auth tag must be rejected.
                let mut tampered = encrypted.clone();
                tampered[20] ^= 0x01;
                assert!(rx.unprotect_rtp(&tampered).is_err());
            }
            assert_eq!(tx.roc(), 1);
            assert_eq!(rx.roc(), 1);

            // Verify SRTCP encryption, authentication, and replay protection.
            let rtcp_plain = RtcpPacket::ReceiverReport {
                ssrc: 0x1234_5678,
                reports: Vec::new(),
            }
            .to_bytes();
            let srtcp = tx.protect_rtcp(&rtcp_plain).unwrap();
            assert_eq!(srtcp.len(), rtcp_plain.len() + 4 + 10);
            let rtcp_dec = rx.unprotect_rtcp(&srtcp).unwrap();
            assert_eq!(rtcp_dec, rtcp_plain);
            assert!(rx.unprotect_rtcp(&srtcp).is_err());
        }
    }

    #[test]
    fn per_ssrc_srtp_survives_mid_call_ssrc_switch_and_resists_forged_ssrc_flood() {
        let key_salt = [0x77u8; 30];
        let mut tx_a = SrtpContext::from_key_salt(SrtpSuite::AesCm128HmacSha1_80, &key_salt);
        let mut tx_b = SrtpContext::from_key_salt(SrtpSuite::AesCm128HmacSha1_80, &key_salt);
        let mut rx = SrtpContext::from_key_salt(SrtpSuite::AesCm128HmacSha1_80, &key_salt);

        // Stream A (e.g., IVR / MOH) advances to high sequence number 45_000.
        let mut pkt_a = RtpPacketizer::new(0xAAAA_0001, 0, 45_000, 160);
        for i in 0..3 {
            let plain = pkt_a.next_packet_bytes(&[i as u8; 160], 160, false);
            let enc = tx_a.protect_rtp(&plain).unwrap();
            assert_eq!(rx.unprotect_rtp(&enc).unwrap(), plain);
        }
        assert_eq!(rx.roc_for_ssrc(0xAAAA_0001), Some(0));

        // Attacker floods 64 bogus SSRCs with invalid HMAC tags: MUST NOT evict or pollute SSRC table.
        for bogus in 1..=64u32 {
            let mut forged = RtpPacketizer::new(0xDEAD_0000 + bogus, 0, 1, 160).next_packet_bytes(
                &[0x55; 160],
                160,
                false,
            );
            forged.extend_from_slice(&[0x00; 10]);
            assert!(rx.unprotect_rtp(&forged).is_err());
        }
        assert_eq!(
            rx.tracked_ssrc_count(),
            1,
            "unauthenticated SSRCs must not enter SSRC state table"
        );

        // Stream B (e.g., agent after PBX bridge/transfer) starts at low sequence 100:
        // must NOT falsely increment ROC due to Stream A's seq 45_002!
        let mut pkt_b = RtpPacketizer::new(0xBBBB_0002, 0, 100, 160);
        for i in 0..3 {
            let plain = pkt_b.next_packet_bytes(&[(i + 10) as u8; 160], 160, false);
            let enc = tx_b.protect_rtp(&plain).unwrap();
            assert_eq!(rx.unprotect_rtp(&enc).unwrap(), plain);
        }
        assert_eq!(rx.roc_for_ssrc(0xBBBB_0002), Some(0));
        assert_eq!(rx.tracked_ssrc_count(), 2);

        // Interleaved packets from Stream A still decrypt cleanly too.
        let plain_a_next = pkt_a.next_packet_bytes(&[0x33; 160], 160, false);
        let enc_a_next = tx_a.protect_rtp(&plain_a_next).unwrap();
        assert_eq!(rx.unprotect_rtp(&enc_a_next).unwrap(), plain_a_next);
    }

    #[test]
    fn enforces_rfc3711_key_lifetime_limit_on_srtcp_index_exhaustion() {
        let mut ctx = SrtpContext::from_key_salt(SrtpSuite::AesCm128HmacSha1_80, &[0x12u8; 30]);
        let rtcp_plain = RtcpPacket::ReceiverReport {
            ssrc: 0x0102_0304,
            reports: Vec::new(),
        }
        .to_bytes();
        let _ = ctx.protect_rtcp(&rtcp_plain).unwrap();
        // Fast-forward SRTCP index to maximum 31-bit boundary (2^31 - 1) to verify hard KeyExpired error.
        ctx.streams[0].srtcp_index = MAX_SRTCP_INDEX;
        assert_eq!(
            ctx.protect_rtcp(&rtcp_plain),
            Err(MediaError::SrtpKeyExpired)
        );
    }
}
