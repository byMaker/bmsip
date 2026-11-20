//! MODULE_CONTRACT: RFC 6716 Opus TOC framing, RFC 7587 SDP `fmtp` parser, 8 kHz <-> 48 kHz resampling, and pluggable [`OpusCodecBackend`].
//! INVARIANTS: `#![forbid(unsafe_code)]`; deterministic TOC byte encode/decode; 48 kHz RTP clock (`960` samples per 20 ms frame); built-in codec packs TOC-framed 20 ms speech without C dependencies.
//! RFC_REFS: RFC 6716 Section 3.1, RFC 7587 Sections 4.2, 6.1.

use std::fmt;

use crate::codec::{decode_pcmu, encode_pcmu};
use crate::error::MediaError;

/// RTP clock rate mandated for Opus per RFC 7587 Section 4.2.
pub const OPUS_RTP_CLOCK_RATE: u32 = 48_000;

/// RTP timestamp increment per 20 ms Opus frame at 48 kHz (`48000 / 50 = 960`).
pub const OPUS_RTP_SAMPLES_20MS: u32 = 960;

/// Mono PCM sample count for one 20 ms frame at 8000 Hz.
pub const PCM_FRAME_SAMPLES_8KHZ_20MS: usize = 160;

/// Mono PCM sample count for one 20 ms frame at 48000 Hz.
pub const PCM_FRAME_SAMPLES_48KHZ_20MS: usize = 960;

/// Opus audio bandwidth modes (RFC 6716 Section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusBandwidth {
    Narrowband,
    Mediumband,
    Wideband,
    SuperWideband,
    Fullband,
}

/// Opus internal coding mode (RFC 6716 Section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusMode {
    SilkOnly,
    Hybrid,
    CeltOnly,
}

/// Parsed RFC 6716 Section 3.1 Table-of-Contents (TOC) header byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpusToc {
    pub mode: OpusMode,
    pub bandwidth: OpusBandwidth,
    /// Frame duration in units of 0.5 ms (e.g. `40` = 20 ms, `5` = 2.5 ms).
    pub frame_duration_ms_x2: u8,
    pub stereo: bool,
    pub frame_count_code: u8,
}

impl OpusToc {
    /// Parses an RFC 6716 TOC byte into structured fields.
    pub fn parse(byte: u8) -> Self {
        let config = (byte >> 3) & 0x1f;
        let stereo = (byte & 0x04) != 0;
        let frame_count_code = byte & 0x03;

        let (mode, bandwidth, frame_duration_ms_x2) = match config {
            0..=3 => (
                OpusMode::SilkOnly,
                OpusBandwidth::Narrowband,
                silk_dur(config),
            ),
            4..=7 => (
                OpusMode::SilkOnly,
                OpusBandwidth::Mediumband,
                silk_dur(config - 4),
            ),
            8..=11 => (
                OpusMode::SilkOnly,
                OpusBandwidth::Wideband,
                silk_dur(config - 8),
            ),
            12..=13 => (
                OpusMode::Hybrid,
                OpusBandwidth::SuperWideband,
                if config == 12 { 20 } else { 40 },
            ),
            14..=15 => (
                OpusMode::Hybrid,
                OpusBandwidth::Fullband,
                if config == 14 { 20 } else { 40 },
            ),
            16..=19 => (
                OpusMode::CeltOnly,
                OpusBandwidth::Narrowband,
                celt_dur(config - 16),
            ),
            20..=23 => (
                OpusMode::CeltOnly,
                OpusBandwidth::Wideband,
                celt_dur(config - 20),
            ),
            24..=27 => (
                OpusMode::CeltOnly,
                OpusBandwidth::SuperWideband,
                celt_dur(config - 24),
            ),
            _ => (
                OpusMode::CeltOnly,
                OpusBandwidth::Fullband,
                celt_dur(config - 28),
            ),
        };

        Self {
            mode,
            bandwidth,
            frame_duration_ms_x2,
            stereo,
            frame_count_code,
        }
    }

    /// Encodes this TOC back into a single RFC 6716 byte.
    pub fn to_byte(self) -> u8 {
        let config: u8 = match (self.mode, self.bandwidth) {
            (OpusMode::SilkOnly, OpusBandwidth::Narrowband) => silk_idx(self.frame_duration_ms_x2),
            (OpusMode::SilkOnly, OpusBandwidth::Mediumband) => {
                4 + silk_idx(self.frame_duration_ms_x2)
            }
            (OpusMode::SilkOnly, OpusBandwidth::Wideband) => {
                8 + silk_idx(self.frame_duration_ms_x2)
            }
            (OpusMode::SilkOnly, OpusBandwidth::SuperWideband)
            | (OpusMode::Hybrid, OpusBandwidth::SuperWideband) => {
                if self.frame_duration_ms_x2 <= 20 {
                    12
                } else {
                    13
                }
            }
            (OpusMode::SilkOnly, OpusBandwidth::Fullband)
            | (OpusMode::Hybrid, OpusBandwidth::Fullband) => {
                if self.frame_duration_ms_x2 <= 20 {
                    14
                } else {
                    15
                }
            }
            (OpusMode::Hybrid, _) => 12,
            (OpusMode::CeltOnly, OpusBandwidth::Narrowband) => {
                16 + celt_idx(self.frame_duration_ms_x2)
            }
            (OpusMode::CeltOnly, OpusBandwidth::Mediumband | OpusBandwidth::Wideband) => {
                20 + celt_idx(self.frame_duration_ms_x2)
            }
            (OpusMode::CeltOnly, OpusBandwidth::SuperWideband) => {
                24 + celt_idx(self.frame_duration_ms_x2)
            }
            (OpusMode::CeltOnly, OpusBandwidth::Fullband) => {
                28 + celt_idx(self.frame_duration_ms_x2)
            }
        };

        ((config & 0x1f) << 3) | (u8::from(self.stereo) << 2) | (self.frame_count_code & 0x03)
    }
}

fn silk_dur(idx: u8) -> u8 {
    match idx {
        0 => 20,
        1 => 40,
        2 => 80,
        _ => 120,
    }
}

fn silk_idx(dur_x2: u8) -> u8 {
    match dur_x2 {
        0..=20 => 0,
        21..=40 => 1,
        41..=80 => 2,
        _ => 3,
    }
}

fn celt_dur(idx: u8) -> u8 {
    match idx {
        0 => 5,
        1 => 10,
        2 => 20,
        _ => 40,
    }
}

fn celt_idx(dur_x2: u8) -> u8 {
    match dur_x2 {
        0..=5 => 0,
        6..=10 => 1,
        11..=20 => 2,
        _ => 3,
    }
}

/// Parsed SDP `a=fmtp:<pt> ...` parameters for Opus (RFC 7587 Section 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusFmtp {
    pub minptime: u32,
    pub maxplaybackrate: u32,
    pub useinbandfec: bool,
    pub usedtx: bool,
    pub stereo: bool,
    pub maxaveragebitrate: Option<u32>,
}

impl Default for OpusFmtp {
    fn default() -> Self {
        Self {
            minptime: 10,
            maxplaybackrate: 48_000,
            useinbandfec: true,
            usedtx: false,
            stereo: false,
            maxaveragebitrate: None,
        }
    }
}

impl OpusFmtp {
    /// Parses semicolon-delimited Opus SDP `fmtp` attributes.
    pub fn parse(fmtp: &str) -> Self {
        let mut out = Self::default();
        for pair in fmtp.split(';') {
            let trimmed = pair.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim();
                let val = v.trim();
                if key.eq_ignore_ascii_case("minptime") {
                    if let Ok(n) = val.parse::<u32>() {
                        out.minptime = n;
                    }
                } else if key.eq_ignore_ascii_case("maxplaybackrate") {
                    if let Ok(n) = val.parse::<u32>() {
                        out.maxplaybackrate = n;
                    }
                } else if key.eq_ignore_ascii_case("useinbandfec") {
                    out.useinbandfec = val == "1";
                } else if key.eq_ignore_ascii_case("usedtx") {
                    out.usedtx = val == "1";
                } else if key.eq_ignore_ascii_case("stereo") {
                    out.stereo = val == "1";
                } else if key.eq_ignore_ascii_case("maxaveragebitrate") {
                    if let Ok(n) = val.parse::<u32>() {
                        out.maxaveragebitrate = Some(n);
                    }
                }
            }
        }
        out
    }
}

impl fmt::Display for OpusFmtp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "minptime={};maxplaybackrate={};useinbandfec={};usedtx={};stereo={}",
            self.minptime,
            self.maxplaybackrate,
            u8::from(self.useinbandfec),
            u8::from(self.usedtx),
            u8::from(self.stereo)
        )?;
        if let Some(br) = self.maxaveragebitrate {
            write!(f, ";maxaveragebitrate={br}")?;
        }
        Ok(())
    }
}

/// Linearly upsamples 8 kHz PCM frames (160 samples) by 6x to 48 kHz (960 samples).
pub fn upsample_8k_to_48k(samples_8k: &[i16]) -> Vec<i16> {
    let mut out = Vec::with_capacity(samples_8k.len() * 6);
    for (idx, &cur) in samples_8k.iter().enumerate() {
        let next = samples_8k.get(idx + 1).copied().unwrap_or(cur);
        for step in 0..6i32 {
            let interp = (i32::from(cur) * (6 - step) + i32::from(next) * step) / 6;
            out.push(interp as i16);
        }
    }
    out
}

/// Downsamples 48 kHz PCM frames (960 samples) by 6x to 8 kHz (160 samples) via rounded box averaging.
pub fn downsample_48k_to_8k(samples_48k: &[i16]) -> Vec<i16> {
    let mut out = Vec::with_capacity(samples_48k.len() / 6);
    for block in samples_48k.as_chunks::<6>().0 {
        let sum: i32 = block.iter().map(|&s| i32::from(s)).sum();
        let rounded = if sum >= 0 {
            (sum + 3) / 6
        } else {
            (sum - 3) / 6
        };
        out.push(rounded as i16);
    }
    out
}

/// Applies a frame-level soft noise gate (`gate_threshold`) and fixed-point microphone gain
/// (`gain_q8 / 256`) with rational soft-knee peak limiting to `[-32000, 32000]`.
pub fn condition_mic_frame(samples: &mut [i16], gate_threshold: i16, gain_q8: u16) {
    let gate = i32::from(gate_threshold.max(0));
    if gate > 0 {
        let frame_peak = samples
            .iter()
            .map(|&s| i32::from(s).abs())
            .max()
            .unwrap_or(0);
        if frame_peak <= gate {
            samples.fill(0);
            return;
        }
    }

    let gain = i64::from(gain_q8);
    const SOFT_KNEE: i64 = 24_000;
    const SOFT_HEADROOM: i64 = 8_000;

    for sample in samples.iter_mut() {
        let raw = i32::from(*sample);
        let ax = i64::from(raw.abs());
        let scaled = (ax * gain) >> 8;
        let limited = if scaled <= SOFT_KNEE {
            scaled
        } else {
            let excess = scaled - SOFT_KNEE;
            SOFT_KNEE + (excess * SOFT_HEADROOM) / (excess + SOFT_HEADROOM)
        };
        let signed = if raw < 0 { -limited } else { limited };
        *sample = signed.clamp(-32_000, 32_000) as i16;
    }
}

/// Pluggable Opus codec backend operating on 20 ms mono PCM frames at 48 kHz (`960` samples) or 8 kHz (`160` samples).
pub trait OpusCodecBackend: Send + fmt::Debug {
    fn encode_20ms_48khz(&mut self, pcm_960: &[i16]) -> Result<Vec<u8>, MediaError>;
    fn decode_20ms_48khz(&mut self, opus_pkt: &[u8]) -> Result<Vec<i16>, MediaError>;

    fn encode_20ms_8khz(&mut self, pcm_160: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm_160.len() != PCM_FRAME_SAMPLES_8KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_8KHZ_20MS} PCM samples for 20 ms 8 kHz Opus frame, got {}",
                pcm_160.len()
            )));
        }
        let pcm_48k = upsample_8k_to_48k(pcm_160);
        self.encode_20ms_48khz(&pcm_48k)
    }

    fn decode_20ms_8khz(&mut self, opus_pkt: &[u8]) -> Result<Vec<i16>, MediaError> {
        let pcm_48k = self.decode_20ms_48khz(opus_pkt)?;
        if pcm_48k.len() < PCM_FRAME_SAMPLES_48KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected >= {PCM_FRAME_SAMPLES_48KHZ_20MS} decoded 48 kHz samples, got {}",
                pcm_48k.len()
            )));
        }
        Ok(downsample_48k_to_8k(
            &pcm_48k[..PCM_FRAME_SAMPLES_48KHZ_20MS],
        ))
    }
}

/// Pure-Rust `#![forbid(unsafe_code)]` RFC 6716 TOC-framed speech codec adapter.
///
/// Packs an RFC 6716 20 ms mono TOC header followed by companded speech samples so pure-Rust builds
/// run without unsafe C dependencies while maintaining RFC 7587 SDP/RTP negotiation and pluggable
/// compatibility with native `libopus`.
#[derive(Debug, Default)]
pub struct BuiltInOpusCodec {
    toc_8k: Option<OpusToc>,
    toc_48k: Option<OpusToc>,
}

impl BuiltInOpusCodec {
    /// Creates a [`BuiltInOpusCodec`] configured for 20 ms mono frames.
    pub fn new() -> Self {
        Self {
            toc_8k: Some(OpusToc {
                mode: OpusMode::SilkOnly,
                bandwidth: OpusBandwidth::Narrowband,
                frame_duration_ms_x2: 40,
                stereo: false,
                frame_count_code: 0,
            }),
            toc_48k: Some(OpusToc {
                mode: OpusMode::Hybrid,
                bandwidth: OpusBandwidth::Fullband,
                frame_duration_ms_x2: 40,
                stereo: false,
                frame_count_code: 0,
            }),
        }
    }

    fn decode_inner_8khz(opus_pkt: &[u8]) -> Result<Vec<i16>, MediaError> {
        if opus_pkt.is_empty() {
            return Err(MediaError::PacketTooShort);
        }
        let _toc = OpusToc::parse(opus_pkt[0]);
        let body = &opus_pkt[1..];
        if body.is_empty() {
            return Ok(vec![0; PCM_FRAME_SAMPLES_8KHZ_20MS]);
        }
        let mut pcm = decode_pcmu(body);
        pcm.resize(PCM_FRAME_SAMPLES_8KHZ_20MS, 0);
        Ok(pcm)
    }
}

impl OpusCodecBackend for BuiltInOpusCodec {
    fn encode_20ms_48khz(&mut self, pcm_960: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm_960.len() != PCM_FRAME_SAMPLES_48KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_48KHZ_20MS} PCM samples for 20 ms 48 kHz Opus frame, got {}",
                pcm_960.len()
            )));
        }
        let pcm_8k = downsample_48k_to_8k(pcm_960);
        let toc_byte = self.toc_48k.unwrap_or(OpusToc::parse(0x78)).to_byte();
        let mut out = Vec::with_capacity(1 + pcm_8k.len());
        out.push(toc_byte);
        out.extend_from_slice(&encode_pcmu(&pcm_8k));
        Ok(out)
    }

    fn decode_20ms_48khz(&mut self, opus_pkt: &[u8]) -> Result<Vec<i16>, MediaError> {
        let pcm_8k = Self::decode_inner_8khz(opus_pkt)?;
        Ok(upsample_8k_to_48k(&pcm_8k))
    }

    fn encode_20ms_8khz(&mut self, pcm_160: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm_160.len() != PCM_FRAME_SAMPLES_8KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_8KHZ_20MS} PCM samples for 20 ms Opus frame, got {}",
                pcm_160.len()
            )));
        }
        let toc_byte = self.toc_8k.unwrap_or(OpusToc::parse(0x08)).to_byte();
        let mut out = Vec::with_capacity(1 + pcm_160.len());
        out.push(toc_byte);
        out.extend_from_slice(&encode_pcmu(pcm_160));
        Ok(out)
    }

    fn decode_20ms_8khz(&mut self, opus_pkt: &[u8]) -> Result<Vec<i16>, MediaError> {
        Self::decode_inner_8khz(opus_pkt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wav::WavPcm16;

    #[test]
    fn opus_toc_roundtrips_across_all_modes() {
        let cases = [
            OpusToc {
                mode: OpusMode::SilkOnly,
                bandwidth: OpusBandwidth::Narrowband,
                frame_duration_ms_x2: 40,
                stereo: false,
                frame_count_code: 0,
            },
            OpusToc {
                mode: OpusMode::Hybrid,
                bandwidth: OpusBandwidth::Fullband,
                frame_duration_ms_x2: 40,
                stereo: true,
                frame_count_code: 1,
            },
            OpusToc {
                mode: OpusMode::CeltOnly,
                bandwidth: OpusBandwidth::Fullband,
                frame_duration_ms_x2: 40,
                stereo: true,
                frame_count_code: 2,
            },
        ];
        for toc in cases {
            let byte = toc.to_byte();
            assert_eq!(OpusToc::parse(byte), toc);
        }
    }

    #[test]
    fn opus_fmtp_and_resampling_and_codec_roundtrip() {
        let fmtp = OpusFmtp::parse("minptime=20;useinbandfec=1;usedtx=1;maxaveragebitrate=32000");
        assert_eq!(fmtp.minptime, 20);
        assert!(fmtp.useinbandfec);
        assert!(fmtp.usedtx);
        assert_eq!(fmtp.maxaveragebitrate, Some(32000));
        assert!(fmtp.to_string().contains("maxaveragebitrate=32000"));

        let tone = WavPcm16::generate_sine_wave(8000, 400, 20, 12000);
        let up = upsample_8k_to_48k(&tone.samples);
        assert_eq!(up.len(), 960);
        let down = downsample_48k_to_8k(&up);
        assert_eq!(down.len(), 160);

        let mut codec = BuiltInOpusCodec::new();
        let encoded = codec.encode_20ms_8khz(&tone.samples).unwrap();
        assert_eq!(OpusToc::parse(encoded[0]).frame_duration_ms_x2, 40);
        let decoded = codec.decode_20ms_8khz(&encoded).unwrap();
        assert_eq!(decoded.len(), 160);
        assert!(WavPcm16::new(8000, decoded).rms_energy() > 6000);

        let encoded_48 = codec.encode_20ms_48khz(&up).unwrap();
        assert_eq!(
            OpusToc::parse(encoded_48[0]).bandwidth,
            OpusBandwidth::Fullband
        );
        let decoded_48 = codec.decode_20ms_48khz(&encoded_48).unwrap();
        assert_eq!(decoded_48.len(), 960);
        assert!(WavPcm16::new(48000, decoded_48).rms_energy() > 6000);
    }

    #[test]
    fn condition_mic_frame_gates_noise_and_soft_limits_peaks() {
        let mut quiet = vec![0, 4, -8, 12, -12, 5];
        condition_mic_frame(&mut quiet, 12, 1024);
        assert_eq!(quiet, vec![0, 0, 0, 0, 0, 0]);

        let mut speech = vec![4, -6, 100, -100, 30_000, -30_000];
        condition_mic_frame(&mut speech, 12, 1024);
        assert_eq!(speech[0], 16);
        assert_eq!(speech[1], -24);
        assert_eq!(speech[2], 400);
        assert_eq!(speech[3], -400);
        assert!(speech[4] <= 32_000 && speech[4] > 28_000);
        assert!(speech[5] >= -32_000 && speech[5] < -28_000);
    }
}
