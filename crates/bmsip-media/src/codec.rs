//! MODULE_CONTRACT: ITU-T G.711 μ-law (`PCMU`) and A-law (`PCMA`) 8 kHz audio codecs.
//! INVARIANTS: `#![forbid(unsafe_code)]`; pure table-free integer bit manipulation; matches G.711 zero-code (`0xFF` PCMU, `0xD5` PCMA) and symmetric companding curves.
//! RFC_REFS: ITU-T G.711, RFC 3551 Section 4.5.14 (PT 0 PCMU, PT 8 PCMA).

const ULAW_BIAS: i32 = 0x84;
const ULAW_CLIP: i32 = 32635;

/// Supported G.711 companding variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G711Kind {
    /// μ-law (RTP payload type 0).
    Pcmu,
    /// A-law (RTP payload type 8).
    Pcma,
}

impl G711Kind {
    /// Returns the static RTP payload type number (`0` for PCMU, `8` for PCMA).
    pub fn payload_type(self) -> u8 {
        match self {
            Self::Pcmu => 0,
            Self::Pcma => 8,
        }
    }

    /// Resolves a static RTP payload type into a [`G711Kind`].
    pub fn from_payload_type(pt: u8) -> Option<Self> {
        match pt {
            0 => Some(Self::Pcmu),
            8 => Some(Self::Pcma),
            _ => None,
        }
    }

    /// Encodes 16-bit linear PCM samples to G.711 bytes.
    pub fn encode(self, pcm: &[i16]) -> Vec<u8> {
        match self {
            Self::Pcmu => encode_pcmu(pcm),
            Self::Pcma => encode_pcma(pcm),
        }
    }

    /// Decodes G.711 bytes into 16-bit linear PCM samples.
    pub fn decode(self, encoded: &[u8]) -> Vec<i16> {
        match self {
            Self::Pcmu => decode_pcmu(encoded),
            Self::Pcma => decode_pcma(encoded),
        }
    }
}

/// Encodes one 16-bit linear PCM sample using ITU-T G.711 μ-law.
pub fn ulaw_encode_sample(sample: i16) -> u8 {
    let mut pcm = i32::from(sample);
    let sign = if pcm < 0 {
        pcm = pcm.saturating_neg();
        0x80u8
    } else {
        0x00u8
    };
    if pcm > ULAW_CLIP {
        pcm = ULAW_CLIP;
    }
    pcm += ULAW_BIAS;

    let mut exponent = 7u8;
    let mut mask = 0x4000;
    while exponent > 0 && (pcm & mask) == 0 {
        exponent -= 1;
        mask >>= 1;
    }
    let mantissa = ((pcm >> (exponent + 3)) & 0x0f) as u8;
    !(sign | (exponent << 4) | mantissa)
}

/// Decodes one ITU-T G.711 μ-law byte to a 16-bit linear PCM sample.
pub fn ulaw_decode_sample(code: u8) -> i16 {
    let val = !code;
    let sign = val & 0x80;
    let exponent = (val >> 4) & 0x07;
    let mantissa = i32::from(val & 0x0f);
    let magnitude = ((mantissa << 3) + ULAW_BIAS) << exponent;
    let linear = magnitude - ULAW_BIAS;
    if sign != 0 {
        -(linear as i16)
    } else {
        linear as i16
    }
}

/// Encodes one 16-bit linear PCM sample using ITU-T G.711 A-law.
pub fn alaw_encode_sample(sample: i16) -> u8 {
    let mut pcm = i32::from(sample);
    let sign = if pcm >= 0 {
        0x80u8
    } else {
        pcm = -pcm - 1;
        0x00u8
    };
    let clamped = pcm.min(32767);

    let (exponent, mantissa) = if clamped < 256 {
        (0u8, (clamped >> 4) as u8)
    } else {
        let mut exp = 7u8;
        let mut mask = 0x4000;
        while exp > 1 && (clamped & mask) == 0 {
            exp -= 1;
            mask >>= 1;
        }
        (exp, ((clamped >> (exp + 3)) & 0x0f) as u8)
    };

    (sign | (exponent << 4) | mantissa) ^ 0x55
}

/// Decodes one ITU-T G.711 A-law byte to a 16-bit linear PCM sample.
pub fn alaw_decode_sample(code: u8) -> i16 {
    let val = code ^ 0x55;
    let sign = val & 0x80;
    let exponent = (val >> 4) & 0x07;
    let mantissa = i32::from(val & 0x0f);

    let magnitude = if exponent == 0 {
        (mantissa << 4) + 8
    } else {
        ((mantissa << 4) + 0x108) << (exponent - 1)
    };

    if sign != 0 {
        magnitude as i16
    } else {
        -(magnitude as i16)
    }
}

/// Encodes a slice of 16-bit linear PCM samples to G.711 μ-law (`PCMU`).
pub fn encode_pcmu(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().copied().map(ulaw_encode_sample).collect()
}

/// Decodes G.711 μ-law (`PCMU`) bytes into 16-bit linear PCM samples.
pub fn decode_pcmu(encoded: &[u8]) -> Vec<i16> {
    encoded.iter().copied().map(ulaw_decode_sample).collect()
}

/// Encodes a slice of 16-bit linear PCM samples to G.711 A-law (`PCMA`).
pub fn encode_pcma(pcm: &[i16]) -> Vec<u8> {
    pcm.iter().copied().map(alaw_encode_sample).collect()
}

/// Decodes G.711 A-law (`PCMA`) bytes into 16-bit linear PCM samples.
pub fn decode_pcma(encoded: &[u8]) -> Vec<i16> {
    encoded.iter().copied().map(alaw_decode_sample).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_zero_codes_and_dynamic_range_roundtrip() {
        assert_eq!(ulaw_encode_sample(0), 0xff);
        assert_eq!(ulaw_decode_sample(0xff), 0);
        assert_eq!(alaw_encode_sample(0), 0xd5);
        assert_eq!(alaw_decode_sample(0xd5), 8);

        for &sample in &[-32000i16, -12000, -2500, -300, 0, 300, 2500, 12000, 32000] {
            let mu = ulaw_decode_sample(ulaw_encode_sample(sample));
            let err_mu = (i32::from(mu) - i32::from(sample)).abs();
            assert!(
                err_mu <= (i32::from(sample.abs()) / 12) + 32,
                "PCMU error too large for {sample}: got {mu}"
            );

            let al = alaw_decode_sample(alaw_encode_sample(sample));
            let err_al = (i32::from(al) - i32::from(sample)).abs();
            assert!(
                err_al <= (i32::from(sample.abs()) / 12) + 32,
                "PCMA error too large for {sample}: got {al}"
            );
        }
    }

    #[test]
    fn frame_encode_decode_preserves_sample_count() {
        let samples: Vec<i16> = (0..160).map(|i| ((i - 80) * 300) as i16).collect();
        let mu = encode_pcmu(&samples);
        assert_eq!(mu.len(), 160);
        assert_eq!(decode_pcmu(&mu).len(), 160);

        let al = encode_pcma(&samples);
        assert_eq!(al.len(), 160);
        assert_eq!(decode_pcma(&al).len(), 160);
    }
}
