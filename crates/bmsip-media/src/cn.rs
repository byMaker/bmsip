//! MODULE_CONTRACT: RFC 3389 Comfort Noise (CN, static payload type 13, 8000 Hz RTP clock) SID encoding and comfort noise synthesis (`ComfortNoisePacket`, `ComfortNoiseGenerator`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; deterministic PRNG state (no system clock or OS entropy calls); zero `.unwrap()`/`.expect()` outside tests.
//! RFC_REFS: RFC 3389 Sections 3.1–3.2 (RTP Payload Format for Comfort Noise).

use crate::error::MediaError;

/// RFC 3389 static RTP payload type for Comfort Noise (`CN`).
pub const CN_PAYLOAD_TYPE: u8 = 13;

/// RFC 3389 nominal RTP clock rate in Hz for narrowband `CN`.
pub const CN_RTP_CLOCK_RATE: u32 = 8_000;

/// Parsed or serialized RFC 3389 Silence Insertion Descriptor (SID) RTP payload.
///
/// Byte `0` stores the noise level in `-dBov` (`0..=127`, bit 7 reserved `0`).
/// Optional bytes `1..` encode quantized LPC reflection coefficients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComfortNoisePacket {
    /// Background noise level in `-dBov` (`0` = loudest, `127` = silence).
    pub noise_level_dbov: u8,
    /// Optional spectral reflection coefficients (`N` bytes following byte 0).
    pub spectral_params: Vec<u8>,
}

impl ComfortNoisePacket {
    /// Constructs a comfort noise SID packet with level clamped to `0..=127` (`-dBov`).
    pub fn new(noise_level_dbov: u8) -> Self {
        Self {
            noise_level_dbov: noise_level_dbov.min(127),
            spectral_params: Vec::new(),
        }
    }

    /// Attaches optional RFC 3389 spectral reflection parameters.
    pub fn with_spectral_params(mut self, params: Vec<u8>) -> Self {
        self.spectral_params = params;
        self
    }

    /// Parses an RFC 3389 wire payload (minimum 1 byte).
    pub fn parse(raw: &[u8]) -> Result<Self, MediaError> {
        let Some((&first, rest)) = raw.split_first() else {
            return Err(MediaError::PacketTooShort);
        };
        Ok(Self {
            noise_level_dbov: first & 0x7f,
            spectral_params: rest.to_vec(),
        })
    }

    /// Encodes this SID packet into wire bytes (`noise_level_dbov & 0x7f` followed by `spectral_params`).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.spectral_params.len());
        out.push(self.noise_level_dbov & 0x7f);
        out.extend_from_slice(&self.spectral_params);
        out
    }

    /// Estimates an RFC 3389 `-dBov` noise level from a 20 ms linear PCM frame.
    pub fn from_pcm_frame(pcm: &[i16]) -> Self {
        if pcm.is_empty() {
            return Self::new(127);
        }
        let mut sum_sq = 0.0f64;
        for &s in pcm {
            let f = f64::from(s);
            sum_sq += f * f;
        }
        let rms = (sum_sq / (pcm.len() as f64)).sqrt();
        if rms < 0.5 {
            return Self::new(127);
        }
        let dbov = (-20.0 * (rms / 32_767.0).log10()).round().clamp(0.0, 127.0) as u8;
        Self::new(dbov)
    }
}

/// Stateful RFC 3389 comfort noise synthesizer for DTX/VAD pauses.
#[derive(Debug, Clone)]
pub struct ComfortNoiseGenerator {
    active: bool,
    noise_level_dbov: u8,
    spectral_params: Vec<u8>,
    smoothed_rms: f64,
    prng_state: u64,
    lp_state: f64,
}

impl Default for ComfortNoiseGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ComfortNoiseGenerator {
    /// Creates an inactive comfort noise generator seeded deterministically.
    pub fn new() -> Self {
        Self {
            active: false,
            noise_level_dbov: 127,
            spectral_params: Vec::new(),
            smoothed_rms: 0.0,
            prng_state: 0x5d1e_3389_9e37_79b9,
            lp_state: 0.0,
        }
    }

    /// Updates target noise floor & spectral parameters from an inbound RFC 3389 SID packet and activates CN synthesis.
    pub fn update_from_packet(&mut self, pkt: &ComfortNoisePacket) {
        self.active = true;
        self.noise_level_dbov = pkt.noise_level_dbov.min(127);
        self.spectral_params = pkt.spectral_params.clone();
    }

    /// Deactivates comfort noise synthesis when active voice RTP packets resume.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.smoothed_rms = 0.0;
        self.lp_state = 0.0;
    }

    /// Returns `true` while DTX comfort noise generation is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the most recently updated noise level in `-dBov` (`0..=127`).
    pub fn noise_level_dbov(&self) -> u8 {
        self.noise_level_dbov
    }

    /// Synthesizes one comfort noise PCM frame containing `frame_samples` mono 16-bit samples.
    pub fn generate_frame(&mut self, frame_samples: usize) -> Vec<i16> {
        if frame_samples == 0 {
            return Vec::new();
        }
        if !self.active {
            return vec![0i16; frame_samples];
        }
        let target_rms = if self.noise_level_dbov >= 127 {
            0.0
        } else {
            32_767.0 * 10.0_f64.powf(-(f64::from(self.noise_level_dbov)) / 20.0)
        };
        if self.smoothed_rms <= 0.0 {
            self.smoothed_rms = target_rms;
        } else {
            self.smoothed_rms = self.smoothed_rms * 0.5 + target_rms * 0.5;
        }
        if self.smoothed_rms < 0.5 {
            return vec![0i16; frame_samples];
        }

        let alpha = self
            .spectral_params
            .first()
            .map_or(0.50, |&p0| 0.30 + (f64::from(p0) / 255.0) * 0.45);
        let beta = 1.0 - alpha;

        let mut raw = Vec::with_capacity(frame_samples);
        let mut sum_sq = 0.0f64;
        for _ in 0..frame_samples {
            let white = (self.next_unit_f64() + self.next_unit_f64()) * 0.5;
            self.lp_state = self.lp_state * alpha + white * beta;
            raw.push(self.lp_state);
            sum_sq += self.lp_state * self.lp_state;
        }

        let raw_rms = (sum_sq / (frame_samples as f64)).sqrt().max(1e-6);
        let scale = self.smoothed_rms / raw_rms;

        raw.into_iter()
            .map(|x| (x * scale).round().clamp(-32_767.0, 32_767.0) as i16)
            .collect()
    }

    fn next_unit_f64(&mut self) -> f64 {
        let mut x = self.prng_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.prng_state = x.max(1);
        // Map top 32 bits linearly into [-1.0, 1.0).
        let bits = (x >> 32) as u32;
        (f64::from(bits) / (f64::from(u32::MAX) * 0.5)) - 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wav::WavPcm16;

    #[test]
    fn comfort_noise_packet_roundtrips_and_estimates_dbov_monotonically() {
        let pkt = ComfortNoisePacket::new(48).with_spectral_params(vec![0x80, 0x40]);
        let wire = pkt.to_bytes();
        assert_eq!(wire, vec![48, 0x80, 0x40]);
        assert_eq!(ComfortNoisePacket::parse(&wire).unwrap(), pkt);
        assert!(ComfortNoisePacket::parse(&[]).is_err());

        // High-bit in byte 0 is reserved and masked off per RFC 3389 §3.1.
        let masked = ComfortNoisePacket::parse(&[0x80 | 55]).unwrap();
        assert_eq!(masked.noise_level_dbov, 55);

        let loud = ComfortNoisePacket::from_pcm_frame(&[4000i16; 160]);
        let quiet = ComfortNoisePacket::from_pcm_frame(&[250i16; 160]);
        let silence = ComfortNoisePacket::from_pcm_frame(&[0i16; 160]);
        assert!(loud.noise_level_dbov < quiet.noise_level_dbov);
        assert_eq!(silence.noise_level_dbov, 127);
    }

    #[test]
    fn comfort_noise_generator_synthesizes_bounded_frames_at_all_sample_rates() {
        let mut gen = ComfortNoiseGenerator::new();
        assert!(!gen.is_active());
        assert_eq!(gen.generate_frame(160), vec![0i16; 160]);

        gen.update_from_packet(&ComfortNoisePacket::new(42).with_spectral_params(vec![160]));
        assert!(gen.is_active());
        assert_eq!(gen.noise_level_dbov(), 42);

        for n in [160usize, 320, 960] {
            let frame = gen.generate_frame(n);
            assert_eq!(frame.len(), n);
            let rms = WavPcm16::new(8000, frame).rms_energy();
            assert!(
                rms > 50 && rms < 2000,
                "expected moderate -42 dBov comfort noise RMS for {n} samples, got {rms}"
            );
        }

        gen.deactivate();
        assert!(!gen.is_active());
        assert_eq!(gen.generate_frame(160), vec![0i16; 160]);
    }
}
