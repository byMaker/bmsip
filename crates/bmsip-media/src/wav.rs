//! MODULE_CONTRACT: In-memory RIFF/WAVE 16-bit mono PCM encoder/decoder and test-tone synthesizer.
//! INVARIANTS: Zero filesystem I/O (`std::fs` forbidden); validates RIFF/WAVE headers, `PCM=1`, `channels=1`, `bits_per_sample=16`.
//! RFC_REFS: Microsoft RIFF/WAVE PCM specification.

use crate::error::MediaError;

/// In-memory 16-bit mono PCM audio clip with WAV serialization helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WavPcm16 {
    pub sample_rate: u32,
    pub samples: Vec<i16>,
}

impl WavPcm16 {
    /// Creates a new [`WavPcm16`] clip.
    pub fn new(sample_rate: u32, samples: Vec<i16>) -> Self {
        Self {
            sample_rate,
            samples,
        }
    }

    /// Synthesizes a mono sine wave tone for automated testing.
    pub fn generate_sine_wave(
        sample_rate: u32,
        freq_hz: u32,
        duration_ms: u32,
        amplitude: i16,
    ) -> Self {
        let total_samples = (u64::from(sample_rate) * u64::from(duration_ms) / 1000) as usize;
        let mut samples = Vec::with_capacity(total_samples);
        let two_pi = std::f64::consts::TAU;
        let sr = f64::from(sample_rate.max(1));
        let freq = f64::from(freq_hz);
        let amp = f64::from(amplitude);

        for i in 0..total_samples {
            let phase = two_pi * freq * (i as f64) / sr;
            let val = (phase.sin() * amp).round() as i16;
            samples.push(val);
        }

        Self {
            sample_rate,
            samples,
        }
    }

    /// Computes integer Root-Mean-Square (RMS) signal amplitude across all samples.
    pub fn rms_energy(&self) -> u32 {
        if self.samples.is_empty() {
            return 0;
        }
        let sum_sq: f64 = self
            .samples
            .iter()
            .map(|&s| {
                let v = f64::from(s);
                v * v
            })
            .sum();
        (sum_sq / (self.samples.len() as f64)).sqrt().round() as u32
    }

    /// Encodes the PCM clip into canonical 44-byte header RIFF/WAVE bytes.
    pub fn encode(&self) -> Vec<u8> {
        let data_bytes = (self.samples.len() * 2) as u32;
        let riff_size = 36u32.saturating_add(data_bytes);
        let byte_rate = self.sample_rate.saturating_mul(2);

        let mut out = Vec::with_capacity(44 + data_bytes as usize);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&riff_size.to_le_bytes());
        out.extend_from_slice(b"WAVE");
        out.extend_from_slice(b"fmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&1u16.to_le_bytes()); // mono
        out.extend_from_slice(&self.sample_rate.to_le_bytes());
        out.extend_from_slice(&byte_rate.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // block align
        out.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_bytes.to_le_bytes());

        for &sample in &self.samples {
            out.extend_from_slice(&sample.to_le_bytes());
        }
        out
    }

    /// Decodes mono 16-bit PCM RIFF/WAVE bytes into [`WavPcm16`].
    pub fn decode(bytes: &[u8]) -> Result<Self, MediaError> {
        if bytes.len() < 12 || &bytes[0..4] != b"RIFF" || &bytes[8..12] != b"WAVE" {
            return Err(MediaError::InvalidWav(
                "missing RIFF/WAVE header".to_string(),
            ));
        }

        let mut pos = 12usize;
        let mut sample_rate: Option<u32> = None;
        let mut data_slice: Option<&[u8]> = None;

        while pos + 8 <= bytes.len() {
            let chunk_id = &bytes[pos..pos + 4];
            let chunk_len = u32::from_le_bytes([
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
                bytes[pos + 7],
            ]) as usize;
            pos += 8;
            if bytes.len() < pos + chunk_len {
                return Err(MediaError::InvalidWav("truncated WAV chunk".to_string()));
            }
            let chunk = &bytes[pos..pos + chunk_len];

            if chunk_id == b"fmt " {
                if chunk.len() < 16 {
                    return Err(MediaError::InvalidWav("fmt chunk too short".to_string()));
                }
                let format = u16::from_le_bytes([chunk[0], chunk[1]]);
                let channels = u16::from_le_bytes([chunk[2], chunk[3]]);
                let sr = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                let bits = u16::from_le_bytes([chunk[14], chunk[15]]);
                if format != 1 || channels != 1 || bits != 16 {
                    return Err(MediaError::InvalidWav(format!(
                        "unsupported WAV format={format} channels={channels} bits={bits}"
                    )));
                }
                sample_rate = Some(sr);
            } else if chunk_id == b"data" {
                data_slice = Some(chunk);
            }

            pos += chunk_len + (chunk_len % 2);
        }

        let sr =
            sample_rate.ok_or_else(|| MediaError::InvalidWav("missing fmt chunk".to_string()))?;
        let data =
            data_slice.ok_or_else(|| MediaError::InvalidWav("missing data chunk".to_string()))?;

        let mut samples = Vec::with_capacity(data.len() / 2);
        for pair in data.as_chunks::<2>().0 {
            samples.push(i16::from_le_bytes(*pair));
        }

        Ok(Self {
            sample_rate: sr,
            samples,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wav_sine_wave_encode_decode_roundtrip() {
        let wav = WavPcm16::generate_sine_wave(8000, 400, 100, 12000);
        assert_eq!(wav.samples.len(), 800);
        assert!(wav.rms_energy() > 8000);

        let bytes = wav.encode();
        let decoded = WavPcm16::decode(&bytes).unwrap();
        assert_eq!(decoded, wav);
    }
}
