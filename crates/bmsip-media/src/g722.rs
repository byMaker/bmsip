//! MODULE_CONTRACT: Pure-Rust ITU-T G.722 (64 kbps Mode 1) 16 kHz wideband SB-ADPCM codec and multi-rate 20 ms PCM resamplers (`8`/`16`/`48` kHz).
//! INVARIANTS: `#![forbid(unsafe_code)]`; deterministic integer QMF + 2-pole/6-zero ARMA predictor matching ITU-T G.722 tables; RFC 3551 Section 4.5.2 historical 8 kHz RTP clock (`160` timestamp ticks per 20 ms `320`-sample 16 kHz frame).
//! RFC_REFS: ITU-T G.722, RFC 3551 Section 4.5.2 (static PT 9).

use crate::error::MediaError;
use crate::opus::{
    downsample_48k_to_8k, upsample_8k_to_48k, PCM_FRAME_SAMPLES_48KHZ_20MS,
    PCM_FRAME_SAMPLES_8KHZ_20MS,
};
use crate::plugin::{AudioCodecDescriptor, AudioCodecPlugin};

/// Static RTP payload type assigned to G.722 (RFC 3551 Section 4.5.2).
pub const G722_PAYLOAD_TYPE: u8 = 9;

/// Historical RTP timestamp clock rate mandated for G.722 by RFC 3551 Section 4.5.2.
pub const G722_RTP_CLOCK_RATE: u32 = 8_000;

/// True audio sampling rate of G.722 wideband PCM frames.
pub const G722_SAMPLE_RATE_HZ: u32 = 16_000;

/// RTP timestamp increment per 20 ms G.722 packet (`8000 / 50 = 160`).
pub const G722_RTP_SAMPLES_20MS: u32 = 160;

/// Mono PCM sample count for one 20 ms wideband frame at 16000 Hz.
pub const PCM_FRAME_SAMPLES_16KHZ_20MS: usize = 320;

/// Encoded G.722 payload byte count for one 20 ms Mode 1 (64 kbps) frame (`320 / 2`).
pub const G722_FRAME_BYTES_20MS: usize = 160;

// ITU-T G.722 24-tap QMF prototype half-filter coefficients (even taps 0..22).
const QMF_COEFFS: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

// ITU-T G.722 inverse logarithmic step-size table (Table 6/G.722).
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];

// Lower-band log-scale step adaptation table (Table 5/G.722).
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];

// 4-bit code to WL index mapping.
const RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];

// Lower-band 4-bit inverse quantizer for predictor feedback (QM4).
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];

// Lower-band 6-bit inverse quantizer for Mode 1 reconstruction (QM6).
const QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];

// Lower-band 6-bit decision thresholds (Q6).
const Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];

// Lower-band negative error code mapping (ILN).
const ILN: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];

// Lower-band positive error code mapping (ILP).
const ILP: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];

// Upper-band log-scale step adaptation table (WH).
const WH: [i32; 3] = [0, -214, 798];

// Upper-band 2-bit code to WH index mapping.
const RH2: [i32; 4] = [2, 1, 2, 1];

// Upper-band 2-bit inverse quantizer (QM2).
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];

/// Linearly upsamples 8 kHz mono PCM frames (160 samples) by 2x to 16 kHz (320 samples).
pub fn upsample_8k_to_16k(samples_8k: &[i16]) -> Vec<i16> {
    let mut out = Vec::with_capacity(samples_8k.len() * 2);
    for (idx, &cur) in samples_8k.iter().enumerate() {
        let next = samples_8k.get(idx + 1).copied().unwrap_or(cur);
        out.push(cur);
        out.push(((i32::from(cur) + i32::from(next)) / 2) as i16);
    }
    out
}

/// Downsamples 16 kHz mono PCM frames (320 samples) by 2x to 8 kHz (160 samples) using a 3-tap `[1, 2, 1]/4` low-pass FIR filter.
pub fn downsample_16k_to_8k(samples_16k: &[i16]) -> Vec<i16> {
    let block_count = samples_16k.len() / 2;
    if samples_16k.is_empty() || block_count == 0 {
        return Vec::new();
    }
    let last_idx = samples_16k.len() - 1;
    let mut out = Vec::with_capacity(block_count);
    for b in 0..block_count {
        let center = b * 2;
        let prev = i32::from(samples_16k[center.saturating_sub(1)]);
        let cur = i32::from(samples_16k[center]);
        let next = i32::from(samples_16k[(center + 1).min(last_idx)]);
        let acc = prev + (cur * 2) + next;
        let rounded = if acc >= 0 {
            (acc + 2) / 4
        } else {
            (acc - 2) / 4
        };
        out.push(rounded.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16);
    }
    out
}

/// Linearly upsamples 16 kHz mono PCM frames (320 samples) by 3x to 48 kHz (960 samples).
pub fn upsample_16k_to_48k(samples_16k: &[i16]) -> Vec<i16> {
    let mut out = Vec::with_capacity(samples_16k.len() * 3);
    for (idx, &cur) in samples_16k.iter().enumerate() {
        let next = samples_16k.get(idx + 1).copied().unwrap_or(cur);
        for step in 0..3i32 {
            let interp = (i32::from(cur) * (3 - step) + i32::from(next) * step) / 3;
            out.push(interp as i16);
        }
    }
    out
}

/// Downsamples 48 kHz mono PCM frames (960 samples) by 3x to 16 kHz (320 samples) using a 5-tap `[1, 2, 3, 2, 1]/9` low-pass FIR filter.
pub fn downsample_48k_to_16k(samples_48k: &[i16]) -> Vec<i16> {
    const TAPS: [i32; 5] = [1, 2, 3, 2, 1];
    const WEIGHT_SUM: i32 = 9;

    let block_count = samples_48k.len() / 3;
    if samples_48k.is_empty() || block_count == 0 {
        return Vec::new();
    }
    let last_idx = (samples_48k.len() - 1) as isize;
    let mut out = Vec::with_capacity(block_count);

    for b in 0..block_count {
        let center = (b * 3 + 1) as isize;
        let mut acc = 0i32;
        for (tap_idx, &weight) in TAPS.iter().enumerate() {
            let offset = tap_idx as isize - 2;
            let idx = (center + offset).clamp(0, last_idx) as usize;
            acc += i32::from(samples_48k[idx]) * weight;
        }
        let rounded = if acc >= 0 {
            (acc + 4) / WEIGHT_SUM
        } else {
            (acc - 4) / WEIGHT_SUM
        };
        out.push(rounded.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16);
    }
    out
}

/// Adapts a 20 ms mono PCM frame across supported voice sample rates (`8`/`16`/`48` kHz).
pub fn resample_pcm_20ms(src: &[i16], target_samples: usize) -> Result<Vec<i16>, MediaError> {
    if src.len() == target_samples {
        return Ok(src.to_vec());
    }
    match (src.len(), target_samples) {
        (PCM_FRAME_SAMPLES_8KHZ_20MS, PCM_FRAME_SAMPLES_16KHZ_20MS) => Ok(upsample_8k_to_16k(src)),
        (PCM_FRAME_SAMPLES_8KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS) => Ok(upsample_8k_to_48k(src)),
        (PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS) => {
            Ok(downsample_16k_to_8k(src))
        }
        (PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS) => {
            Ok(upsample_16k_to_48k(src))
        }
        (PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS) => {
            Ok(downsample_48k_to_8k(src))
        }
        (PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_16KHZ_20MS) => {
            Ok(downsample_48k_to_16k(src))
        }
        _ => Err(MediaError::BufferError(format!(
            "unsupported 20 ms PCM resample conversion {} -> {} samples",
            src.len(),
            target_samples
        ))),
    }
}

/// Resamples a mono PCM frame of arbitrary packet duration (`2.5`–`120` ms) from `src_rate_hz` to `dst_rate_hz`.
pub fn resample_pcm_by_rate(
    src: &[i16],
    src_rate_hz: u32,
    dst_rate_hz: u32,
) -> Result<Vec<i16>, MediaError> {
    if src_rate_hz == 0 || dst_rate_hz == 0 {
        return Err(MediaError::BufferError(format!(
            "invalid PCM sample rate conversion {src_rate_hz} Hz -> {dst_rate_hz} Hz"
        )));
    }
    if src.is_empty() || src_rate_hz == dst_rate_hz {
        return Ok(src.to_vec());
    }
    match (src_rate_hz, dst_rate_hz) {
        (8_000, 16_000) => Ok(upsample_8k_to_16k(src)),
        (8_000, 48_000) => Ok(upsample_8k_to_48k(src)),
        (16_000, 48_000) => Ok(upsample_16k_to_48k(src)),
        (16_000, 8_000) => Ok(downsample_16k_to_8k(src)),
        (48_000, 16_000) => Ok(downsample_48k_to_16k(src)),
        (48_000, 8_000) => Ok(downsample_48k_to_8k(src)),
        _ => Ok(resample_linear_arbitrary(
            src,
            src_rate_hz,
            dst_rate_hz,
            None,
        )),
    }
}

fn resample_linear_arbitrary(
    src: &[i16],
    src_rate_hz: u32,
    dst_rate_hz: u32,
    prev_last: Option<i16>,
) -> Vec<i16> {
    if src.is_empty() || src_rate_hz == 0 || dst_rate_hz == 0 {
        return Vec::new();
    }
    let out_len = (((src.len() as u64) * u64::from(dst_rate_hz) + u64::from(src_rate_hz / 2))
        / u64::from(src_rate_hz))
    .max(1) as usize;
    let mut out = Vec::with_capacity(out_len);
    let last_idx = src.len() - 1;
    let prev = prev_last.unwrap_or(src[0]);

    for out_idx in 0..out_len {
        // Map output sample `(out_idx + 1)` across `[-1, src.len() - 1]` so `prev` bridges `out_idx = 0`.
        let num = (out_idx as u64 + 1) * u64::from(src_rate_hz);
        let pos_q16 = (num << 16) / u64::from(dst_rate_hz);
        let whole = (pos_q16 >> 16) as usize;
        let frac = (pos_q16 & 0xffff) as i64;
        let (s0, s1) = if whole == 0 {
            (i64::from(prev), i64::from(src[0]))
        } else {
            let i0 = (whole - 1).min(last_idx);
            let i1 = whole.min(last_idx);
            (i64::from(src[i0]), i64::from(src[i1]))
        };
        let interp = ((s0 * (65_536 - frac)) + (s1 * frac)) >> 16;
        out.push(interp.clamp(i64::from(i16::MIN), i64::from(i16::MAX)) as i16);
    }
    out
}

/// Stateful cross-frame PCM resampler eliminating slope discontinuities across RTP packet boundaries.
#[derive(Debug, Clone, Default)]
pub struct StreamResampler {
    prev_last: Option<i16>,
}

impl StreamResampler {
    /// Creates a new [`StreamResampler`] with cleared frame boundary state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears cross-frame boundary state (e.g., after a mid-call codec, SSRC, or sequence jump).
    pub fn reset(&mut self) {
        self.prev_last = None;
    }

    /// Resamples a mono PCM packet of arbitrary duration (`2.5`–`120` ms) from `src_rate_hz` to `dst_rate_hz`,
    /// preserving waveform continuity across sequential packet boundaries.
    pub fn resample_by_rate(
        &mut self,
        src: &[i16],
        src_rate_hz: u32,
        dst_rate_hz: u32,
    ) -> Result<Vec<i16>, MediaError> {
        if src_rate_hz == 0 || dst_rate_hz == 0 {
            return Err(MediaError::BufferError(format!(
                "invalid PCM sample rate conversion {src_rate_hz} Hz -> {dst_rate_hz} Hz"
            )));
        }
        if src.is_empty() {
            return Ok(Vec::new());
        }
        if src_rate_hz == dst_rate_hz {
            self.prev_last = src.last().copied();
            return Ok(src.to_vec());
        }

        let upsample_ratio = match (src_rate_hz, dst_rate_hz) {
            (8_000, 16_000) => Some(2usize),
            (16_000, 48_000) => Some(3usize),
            (8_000, 48_000) => Some(6usize),
            _ if dst_rate_hz > src_rate_hz && dst_rate_hz.is_multiple_of(src_rate_hz) => {
                Some((dst_rate_hz / src_rate_hz) as usize)
            }
            _ => None,
        };

        if let Some(ratio) = upsample_ratio {
            let out = if let Some(mut prev) = self.prev_last {
                let ratio_i32 = ratio as i32;
                let mut buf = Vec::with_capacity(src.len() * ratio);
                for &cur in src {
                    for step in 1..=ratio_i32 {
                        let interp = (i32::from(prev) * (ratio_i32 - step) + i32::from(cur) * step)
                            / ratio_i32;
                        buf.push(interp as i16);
                    }
                    prev = cur;
                }
                buf
            } else {
                let ratio_i32 = ratio as i32;
                let mut buf = Vec::with_capacity(src.len() * ratio);
                for (idx, &cur) in src.iter().enumerate() {
                    let next = src.get(idx + 1).copied().unwrap_or(cur);
                    for step in 0..ratio_i32 {
                        let interp = (i32::from(cur) * (ratio_i32 - step) + i32::from(next) * step)
                            / ratio_i32;
                        buf.push(interp as i16);
                    }
                }
                buf
            };
            self.prev_last = src.last().copied();
            return Ok(out);
        }

        let out = match (src_rate_hz, dst_rate_hz) {
            (16_000, 8_000) if src.len() >= 2 => downsample_16k_to_8k(src),
            (48_000, 16_000) if src.len() >= 3 => downsample_48k_to_16k(src),
            (48_000, 8_000) if src.len() >= 6 => downsample_48k_to_8k(src),
            _ => resample_linear_arbitrary(src, src_rate_hz, dst_rate_hz, self.prev_last),
        };
        self.prev_last = src.last().copied();
        Ok(out)
    }

    /// Resamples one 20 ms frame to `target_samples`, interpolating smoothly across the previous frame tail.
    pub fn resample_20ms(
        &mut self,
        src: &[i16],
        target_samples: usize,
    ) -> Result<Vec<i16>, MediaError> {
        let rates = match (src.len(), target_samples) {
            (PCM_FRAME_SAMPLES_8KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS) => Some((8_000, 8_000)),
            (PCM_FRAME_SAMPLES_8KHZ_20MS, PCM_FRAME_SAMPLES_16KHZ_20MS) => Some((8_000, 16_000)),
            (PCM_FRAME_SAMPLES_8KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS) => Some((8_000, 48_000)),
            (PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS) => Some((16_000, 8_000)),
            (PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_16KHZ_20MS) => Some((16_000, 16_000)),
            (PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS) => Some((16_000, 48_000)),
            (PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS) => Some((48_000, 8_000)),
            (PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_16KHZ_20MS) => Some((48_000, 16_000)),
            (PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS) => Some((48_000, 48_000)),
            _ => None,
        };
        if let Some((src_rate, dst_rate)) = rates {
            return self.resample_by_rate(src, src_rate, dst_rate);
        }
        self.prev_last = src.last().copied();
        resample_pcm_20ms(src, target_samples)
    }
}

#[inline]
fn saturate16(x: i32) -> i32 {
    x.clamp(-32_768, 32_767)
}

#[inline]
fn saturate_subband(x: i32) -> i32 {
    x.clamp(-16_384, 16_383)
}

#[inline]
fn sgn_neg(x: i32) -> i32 {
    if x < 0 {
        -1
    } else {
        0
    }
}

#[derive(Debug, Clone)]
struct G722Band {
    s: i32,
    sp: i32,
    sz: i32,
    r: [i32; 3],
    a: [i32; 3],
    ap: [i32; 3],
    p: [i32; 3],
    d: [i32; 7],
    b: [i32; 7],
    bp: [i32; 7],
    sg: [i32; 7],
    nb: i32,
    det: i32,
}

impl G722Band {
    fn new(initial_det: i32) -> Self {
        Self {
            s: 0,
            sp: 0,
            sz: 0,
            r: [0; 3],
            a: [0; 3],
            ap: [0; 3],
            p: [0; 3],
            d: [0; 7],
            b: [0; 7],
            bp: [0; 7],
            sg: [0; 7],
            nb: 0,
            det: initial_det,
        }
    }

    fn block4(&mut self, d: i32) {
        self.d[0] = d;
        self.r[0] = saturate16(self.s + d);
        self.p[0] = saturate16(self.sz + d);

        let sg0 = sgn_neg(self.p[0]);
        let sg1 = sgn_neg(self.p[1]);
        let sg2 = sgn_neg(self.p[2]);

        // UPPOL2: 2nd-order pole predictor update.
        let wd1_2 = saturate16(self.ap[1] << 2);
        let wd2_2 = if sg0 == sg1 { -wd1_2 } else { wd1_2 };
        let wd2_scaled = wd2_2 >> 7;
        let wd3_2 = if sg0 == sg2 {
            wd2_scaled + 128
        } else {
            wd2_scaled - 128
        };
        let wd4_2 = wd3_2 + ((self.ap[2] * 32_512) >> 15);
        self.a[2] = wd4_2.clamp(-12_288, 12_288);

        // UPPOL1: 1st-order pole predictor update.
        let wd1_1 = if sg0 == sg1 { 192 } else { -192 };
        let wd2_1 = (self.ap[1] * 32_640) >> 15;
        let bound = 15_360 - self.a[2];
        self.a[1] = (wd1_1 + wd2_1).clamp(-bound, bound);

        // UPZERO: 6th-order zero predictor update.
        let wd1_z = if d == 0 { 0 } else { 128 };
        let sg_d0 = sgn_neg(d);
        self.sg[0] = sg_d0;
        for i in 1..=6 {
            let sg_i = sgn_neg(self.d[i]);
            let wd2_z = if sg_d0 == sg_i { wd1_z } else { -wd1_z };
            let wd3_z = (self.bp[i] * 32_640) >> 15;
            self.b[i] = saturate16(wd2_z + wd3_z);
        }

        // Shift state delay lines.
        self.d.copy_within(0..6, 1);
        self.sg.copy_within(0..6, 1);
        self.r[2] = self.r[1];
        self.r[1] = self.r[0];
        self.p[2] = self.p[1];
        self.p[1] = self.p[0];
        self.ap = self.a;
        self.bp = self.b;

        // FILTE / FILTD: compute zero and pole predictions for next sample.
        let mut sz = 0i32;
        for i in 1..=6 {
            let wd = saturate16(self.d[i] << 1);
            sz += (self.b[i] * wd) >> 15;
        }
        self.sz = saturate16(sz);

        let r1_2 = saturate16(self.r[1] << 1);
        let r2_2 = saturate16(self.r[2] << 1);
        self.sp = ((self.a[1] * r1_2) >> 15) + ((self.a[2] * r2_2) >> 15);
        self.s = saturate16(self.sp + self.sz);
    }

    fn adapt_lower_step(&mut self, il4: usize) {
        self.nb = (((self.nb * 127) >> 7) + WL[RL42[il4 & 0x0f] as usize]).clamp(0, 18_432);
        let wd1 = ((self.nb >> 6) & 31) as usize;
        let wd2 = 8 - (self.nb >> 11);
        self.det = if wd2 < 0 {
            (ILB[wd1] << 1) << 2
        } else {
            (ILB[wd1] >> wd2) << 2
        };
    }

    fn adapt_upper_step(&mut self, ih: usize) {
        self.nb = (((self.nb * 127) >> 7) + WH[RH2[ih & 0x03] as usize]).clamp(0, 22_528);
        let wd1 = ((self.nb >> 6) & 31) as usize;
        let wd2 = 10 - (self.nb >> 11);
        self.det = if wd2 < 0 {
            (ILB[wd1] << 1) << 2
        } else {
            (ILB[wd1] >> wd2) << 2
        };
    }
}

/// Stateful ITU-T G.722 Mode 1 (64 kbps) encoder for 16 kHz PCM16 audio.
#[derive(Debug, Clone)]
pub struct G722Encoder {
    x: [i32; 24],
    band_l: G722Band,
    band_h: G722Band,
}

impl Default for G722Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Encoder {
    /// Creates a reset ITU-T G.722 64 kbps encoder.
    pub fn new() -> Self {
        Self {
            x: [0; 24],
            band_l: G722Band::new(32),
            band_h: G722Band::new(8),
        }
    }

    /// Encodes an even-length slice of 16 kHz mono PCM16 samples into 64 kbps G.722 bytes.
    pub fn encode(&mut self, pcm_16k: &[i16]) -> Vec<u8> {
        let mut out = Vec::with_capacity(pcm_16k.len() / 2);
        for pair in pcm_16k.as_chunks::<2>().0 {
            out.push(self.encode_pair(pair[0], pair[1]));
        }
        out
    }

    fn encode_pair(&mut self, s0: i16, s1: i16) -> u8 {
        self.x.copy_within(2..24, 0);
        self.x[22] = i32::from(s0);
        self.x[23] = i32::from(s1);

        let mut acca = 0i32;
        let mut accb = 0i32;
        for i in 0..12 {
            acca += self.x[2 * i] * QMF_COEFFS[i];
            accb += self.x[2 * i + 1] * QMF_COEFFS[11 - i];
        }
        let xlow = (acca + accb) >> 14;
        let xhigh = (accb - acca) >> 14;

        // Quantize lower subband (6 bits).
        let el = saturate16(xlow - self.band_l.s);
        let wd = if el >= 0 { el } else { !el };
        let mut idx = 1usize;
        while idx < 30 {
            let thresh = (Q6[idx] * self.band_l.det) >> 12;
            if wd < thresh {
                break;
            }
            idx += 1;
        }
        let il = if el < 0 { ILP[idx] } else { ILN[idx] };
        let il4 = (il >> 2) as usize;
        let dlowt = (QM4[il4] * self.band_l.det) >> 15;
        self.band_l.block4(dlowt);
        self.band_l.adapt_lower_step(il4);

        // Quantize upper subband (2 bits).
        let eh = saturate16(xhigh - self.band_h.s);
        let wd_h = if eh >= 0 { eh } else { !eh };
        let thresh_h = (564 * self.band_h.det) >> 12;
        let ih = if wd_h >= thresh_h {
            if eh < 0 {
                0
            } else {
                2
            }
        } else if eh < 0 {
            1
        } else {
            3
        };
        let dhigh = (QM2[ih] * self.band_h.det) >> 15;
        self.band_h.block4(dhigh);
        self.band_h.adapt_upper_step(ih);

        (((ih as u8) & 0x03) << 6) | ((il as u8) & 0x3f)
    }
}

/// Stateful ITU-T G.722 Mode 1 (64 kbps) decoder producing 16 kHz PCM16 audio.
#[derive(Debug, Clone)]
pub struct G722Decoder {
    rx: [i32; 24],
    band_l: G722Band,
    band_h: G722Band,
}

impl Default for G722Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Decoder {
    /// Creates a reset ITU-T G.722 64 kbps decoder.
    pub fn new() -> Self {
        Self {
            rx: [0; 24],
            band_l: G722Band::new(32),
            band_h: G722Band::new(8),
        }
    }

    /// Decodes 64 kbps G.722 bytes into 16 kHz mono PCM16 samples (`2` samples per byte).
    pub fn decode(&mut self, encoded: &[u8]) -> Vec<i16> {
        let mut out = Vec::with_capacity(encoded.len() * 2);
        for &byte in encoded {
            let (s0, s1) = self.decode_byte(byte);
            out.push(s0);
            out.push(s1);
        }
        out
    }

    fn decode_byte(&mut self, code: u8) -> (i16, i16) {
        let il = usize::from(code & 0x3f);
        let ih = usize::from((code >> 6) & 0x03);

        // Reconstruct lower band output using full 6-bit QM6 table, adapt predictor with 4-bit QM4.
        let dlowt6 = (QM6[il] * self.band_l.det) >> 15;
        let rlow = saturate_subband(self.band_l.s + dlowt6);
        let il4 = il >> 2;
        let dlowt4 = (QM4[il4] * self.band_l.det) >> 15;
        self.band_l.block4(dlowt4);
        self.band_l.adapt_lower_step(il4);

        // Reconstruct upper band output.
        let dhigh = (QM2[ih] * self.band_h.det) >> 15;
        let rhigh = saturate_subband(self.band_h.s + dhigh);
        self.band_h.block4(dhigh);
        self.band_h.adapt_upper_step(ih);

        // QMF synthesis back to 16 kHz sample pair.
        self.rx.copy_within(2..24, 0);
        self.rx[22] = rlow + rhigh;
        self.rx[23] = rlow - rhigh;

        let mut acca = 0i32;
        let mut accb = 0i32;
        for i in 0..12 {
            acca += self.rx[2 * i] * QMF_COEFFS[i];
            accb += self.rx[2 * i + 1] * QMF_COEFFS[11 - i];
        }
        let s0 = (accb >> 11).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        let s1 = (acca >> 11).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
        (s0, s1)
    }
}

/// Combined bidirectional G.722 Mode 1 codec implementing [`AudioCodecPlugin`].
#[derive(Debug)]
pub struct G722Codec {
    encoder: G722Encoder,
    decoder: G722Decoder,
    descriptor: AudioCodecDescriptor,
}

impl Default for G722Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Codec {
    /// Returns the standard SDP/RTP descriptor for ITU-T G.722 (`G722/8000` RTP, `16000` Hz PCM).
    pub fn default_descriptor() -> AudioCodecDescriptor {
        AudioCodecDescriptor::new(
            G722_PAYLOAD_TYPE,
            "G722",
            G722_RTP_CLOCK_RATE,
            G722_SAMPLE_RATE_HZ,
        )
    }

    /// Creates a bidirectional stateful [`G722Codec`] for 20 ms 16 kHz wideband calls.
    pub fn new() -> Self {
        Self {
            encoder: G722Encoder::new(),
            decoder: G722Decoder::new(),
            descriptor: Self::default_descriptor(),
        }
    }

    /// Encodes one 20 ms 16 kHz frame (`320` PCM samples) into a `160`-byte G.722 RTP payload.
    pub fn encode_16khz(&mut self, pcm_320: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm_320.len() != PCM_FRAME_SAMPLES_16KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_16KHZ_20MS} PCM samples for 20 ms 16 kHz G.722 frame, got {}",
                pcm_320.len()
            )));
        }
        Ok(self.encoder.encode(pcm_320))
    }

    /// Decodes a G.722 RTP payload (`160` bytes for 20 ms) into 16 kHz PCM samples (`320` samples).
    pub fn decode_16khz(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
        if payload.is_empty() {
            return Err(MediaError::PacketTooShort);
        }
        Ok(self.decoder.decode(payload))
    }
}

impl AudioCodecPlugin for G722Codec {
    fn descriptor(&self) -> &AudioCodecDescriptor {
        &self.descriptor
    }

    fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        self.encode_16khz(pcm)
    }

    fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
        self.decode_16khz(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wav::WavPcm16;

    #[test]
    fn g722_roundtrips_lowband_and_highband_wideband_tones_at_unity_gain() {
        let mut codec = G722Codec::new();
        for freq_hz in [440u32, 3_000, 5_500] {
            let wav = WavPcm16::generate_sine_wave(16_000, freq_hz, 300, 12_000);
            let mut decoded_all = Vec::new();
            for frame in wav.samples.as_chunks::<PCM_FRAME_SAMPLES_16KHZ_20MS>().0 {
                let encoded = codec.encode_16khz(frame).unwrap();
                assert_eq!(encoded.len(), G722_FRAME_BYTES_20MS);
                let decoded = codec.decode_16khz(&encoded).unwrap();
                assert_eq!(decoded.len(), PCM_FRAME_SAMPLES_16KHZ_20MS);
                decoded_all.extend_from_slice(&decoded);
            }
            let steady = WavPcm16::new(16_000, decoded_all[1600..].to_vec());
            let rms = steady.rms_energy();
            assert!(
                (7_000..=10_000).contains(&rms),
                "expected near-unity RMS (~8485) for G.722 {freq_hz} Hz tone, got {rms}"
            );
        }
    }

    #[test]
    fn resample_pcm_20ms_handles_all_standard_rates() {
        let f8 = vec![1000i16; 160];
        assert_eq!(resample_pcm_20ms(&f8, 320).unwrap().len(), 320);
        assert_eq!(resample_pcm_20ms(&f8, 960).unwrap().len(), 960);

        let f16 = vec![1000i16; 320];
        assert_eq!(resample_pcm_20ms(&f16, 160).unwrap().len(), 160);
        assert_eq!(resample_pcm_20ms(&f16, 960).unwrap().len(), 960);

        let f48 = vec![1000i16; 960];
        assert_eq!(resample_pcm_20ms(&f48, 160).unwrap().len(), 160);
        assert_eq!(resample_pcm_20ms(&f48, 320).unwrap().len(), 320);
    }

    #[test]
    fn g722_nyquist_highband_polarity_matches_itut_qmf() {
        // Nyquist alternating input [+A, -A, +A, -A, ...]:
        // With ITU-T G.722 QMF xhigh = (accb - acca) >> 14, every even sample (+A) enters acca
        // and odd sample (-A) enters accb, so steady xhigh is negative (eh < 0 -> ih in {0, 1}),
        // and decoding into rx[22]=rlow+rhigh, rx[23]=rlow-rhigh preserves (+, -) polarity.
        let mut enc = G722Encoder::new();
        let mut dec = G722Decoder::new();
        let mut nyquist = [0i16; 320];
        for (i, s) in nyquist.iter_mut().enumerate() {
            *s = if i % 2 == 0 { 12_000 } else { -12_000 };
        }
        let encoded = enc.encode(&nyquist);
        for &byte in &encoded[24..80] {
            let ih = (byte >> 6) & 0x03;
            assert!(
                ih <= 1,
                "expected negative high-band quantizer code ih in {{0,1}} for [+A,-A] Nyquist, got ih={ih}"
            );
        }
        let decoded = dec.decode(&encoded);
        for pair in decoded[64..200].as_chunks::<2>().0 {
            assert!(
                pair[0] > 2_000 && pair[1] < -2_000,
                "expected preserved [+,-] Nyquist polarity after G.722 QMF decode, got {:?}",
                pair
            );
        }
    }

    #[test]
    fn stream_resampler_by_rate_preserves_pitch_across_10ms_30ms_and_40ms_packets() {
        // 10 ms at 16 kHz has 160 samples (same count as 20 ms at 8 kHz): `resample_by_rate`
        // must upsample 3x -> 480 samples (10 ms @ 48 kHz), never 6x -> 960 samples!
        let mut res = StreamResampler::new();
        let wav_16k = WavPcm16::generate_sine_wave(16_000, 1_000, 200, 12_000);
        let mut out_48k = Vec::new();
        for pkt_10ms in wav_16k.samples.chunks(160) {
            let chunk = res.resample_by_rate(pkt_10ms, 16_000, 48_000).unwrap();
            assert_eq!(chunk.len(), 480);
            out_48k.extend_from_slice(&chunk);
        }
        assert_eq!(out_48k.len(), 9_600);
        // Zero-crossing frequency at 48 kHz must remain ~1000 Hz (40 crossings per 20 ms = 960 samples).
        let zc = out_48k[960..5760]
            .windows(2)
            .filter(|w| (w[0] < 0) != (w[1] < 0))
            .count();
        let est_hz = (zc as f64 * 48_000.0) / (2.0 * 4_800.0);
        assert!(
            (980.0..=1_020.0).contains(&est_hz),
            "expected ~1000 Hz after 10 ms 16->48 kHz resampling, got {est_hz:.1} Hz"
        );

        // 30 ms (240 samples) and 40 ms (320 samples) at 8 kHz -> 6x at 48 kHz (1440 / 1920 samples).
        res.reset();
        assert_eq!(
            res.resample_by_rate(&vec![1000i16; 240], 8_000, 48_000)
                .unwrap()
                .len(),
            1_440
        );
        assert_eq!(
            res.resample_by_rate(&vec![1000i16; 320], 8_000, 48_000)
                .unwrap()
                .len(),
            1_920
        );
        // Non-standard 24 kHz -> 48 kHz arbitrary rate fallback.
        res.reset();
        assert_eq!(
            res.resample_by_rate(&vec![1000i16; 480], 24_000, 48_000)
                .unwrap()
                .len(),
            960
        );
    }
}
