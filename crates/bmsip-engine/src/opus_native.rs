#![allow(unsafe_code)]

//! MODULE_CONTRACT: Safe Rust RAII bindings to system `libopus` implementing [`bmsip_media::OpusCodecBackend`] for RFC 6716 48 kHz mono VoIP audio.
//! INVARIANTS: Encapsulates all `unsafe` FFI calls strictly inside this module; drops C encoder/decoder state deterministically via RAII; zero `.unwrap()`/`.expect()` outside tests.
//! RFC_REFS: RFC 6716, RFC 7587.

use std::ffi::{c_char, c_int, CStr};
use std::fmt;
use std::ptr::NonNull;

use bmsip_media::{MediaError, OpusCodecBackend, PCM_FRAME_SAMPLES_48KHZ_20MS};

const OPUS_OK: c_int = 0;
const OPUS_APPLICATION_VOIP: c_int = 2048;
const OPUS_MAX_PACKET_BYTES: usize = 1275;

#[repr(C)]
struct OpusEncoderOpaque {
    _private: [u8; 0],
}

#[repr(C)]
struct OpusDecoderOpaque {
    _private: [u8; 0],
}

extern "C" {
    fn opus_encoder_create(
        fs: i32,
        channels: c_int,
        application: c_int,
        error: *mut c_int,
    ) -> *mut OpusEncoderOpaque;
    fn opus_encode(
        st: *mut OpusEncoderOpaque,
        pcm: *const i16,
        frame_size: c_int,
        data: *mut u8,
        max_data_bytes: i32,
    ) -> i32;
    fn opus_encoder_destroy(st: *mut OpusEncoderOpaque);

    fn opus_decoder_create(fs: i32, channels: c_int, error: *mut c_int) -> *mut OpusDecoderOpaque;
    fn opus_decode(
        st: *mut OpusDecoderOpaque,
        data: *const u8,
        len: i32,
        pcm: *mut i16,
        frame_size: c_int,
        decode_fec: c_int,
    ) -> c_int;
    fn opus_decoder_destroy(st: *mut OpusDecoderOpaque);

    fn opus_get_version_string() -> *const c_char;
}

struct OpusEncoderHandle(NonNull<OpusEncoderOpaque>);

// SAFETY: `OpusEncoder` has no shared global mutable state; all operations require `&mut self`.
unsafe impl Send for OpusEncoderHandle {}

impl OpusEncoderHandle {
    fn new(sample_rate_hz: i32, channels: c_int, application: c_int) -> Result<Self, MediaError> {
        let mut err: c_int = OPUS_OK;
        // SAFETY: Valid output pointer `err`; libopus returns null on failure and initializes `err`.
        let ptr = unsafe { opus_encoder_create(sample_rate_hz, channels, application, &mut err) };
        if err != OPUS_OK {
            if !ptr.is_null() {
                // SAFETY: `ptr` was allocated by `opus_encoder_create`.
                unsafe { opus_encoder_destroy(ptr) };
            }
            return Err(MediaError::UnsupportedCodec(format!(
                "opus_encoder_create failed with code {err}"
            )));
        }
        NonNull::new(ptr).map(Self).ok_or_else(|| {
            MediaError::UnsupportedCodec("opus_encoder_create returned null".to_string())
        })
    }

    fn encode(&mut self, pcm: &[i16], frame_size: usize) -> Result<Vec<u8>, MediaError> {
        let mut out = vec![0u8; OPUS_MAX_PACKET_BYTES];
        // SAFETY: `self.0` is live for `&mut self`, `pcm` has `frame_size` samples, and `out` fits `OPUS_MAX_PACKET_BYTES`.
        let written = unsafe {
            opus_encode(
                self.0.as_ptr(),
                pcm.as_ptr(),
                frame_size as c_int,
                out.as_mut_ptr(),
                out.len() as i32,
            )
        };
        if written < 0 {
            return Err(MediaError::BufferError(format!(
                "opus_encode failed with code {written}"
            )));
        }
        out.truncate(written as usize);
        Ok(out)
    }
}

impl Drop for OpusEncoderHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was created by `opus_encoder_create` and is destroyed once on drop.
        unsafe { opus_encoder_destroy(self.0.as_ptr()) };
    }
}

struct OpusDecoderHandle(NonNull<OpusDecoderOpaque>);

// SAFETY: `OpusDecoder` has no shared global mutable state; all operations require `&mut self`.
unsafe impl Send for OpusDecoderHandle {}

impl OpusDecoderHandle {
    fn new(sample_rate_hz: i32, channels: c_int) -> Result<Self, MediaError> {
        let mut err: c_int = OPUS_OK;
        // SAFETY: Valid output pointer `err`; libopus returns null on failure and initializes `err`.
        let ptr = unsafe { opus_decoder_create(sample_rate_hz, channels, &mut err) };
        if err != OPUS_OK {
            if !ptr.is_null() {
                // SAFETY: `ptr` was allocated by `opus_decoder_create`.
                unsafe { opus_decoder_destroy(ptr) };
            }
            return Err(MediaError::UnsupportedCodec(format!(
                "opus_decoder_create failed with code {err}"
            )));
        }
        NonNull::new(ptr).map(Self).ok_or_else(|| {
            MediaError::UnsupportedCodec("opus_decoder_create returned null".to_string())
        })
    }

    fn decode(&mut self, packet: &[u8], frame_size: usize) -> Result<Vec<i16>, MediaError> {
        let pkt_len = i32::try_from(packet.len())
            .map_err(|_| MediaError::BufferError("opus packet exceeds i32 length".to_string()))?;
        let mut out = vec![0i16; frame_size];
        // SAFETY: `self.0` is live for `&mut self`, `packet` is valid for `pkt_len` bytes, and `out` has capacity `frame_size`.
        let decoded_samples = unsafe {
            opus_decode(
                self.0.as_ptr(),
                packet.as_ptr(),
                pkt_len,
                out.as_mut_ptr(),
                frame_size as c_int,
                0,
            )
        };
        if decoded_samples < 0 {
            return Err(MediaError::BufferError(format!(
                "opus_decode failed with code {decoded_samples}"
            )));
        }
        out.truncate(decoded_samples as usize);
        Ok(out)
    }
}

impl Drop for OpusDecoderHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was created by `opus_decoder_create` and is destroyed once on drop.
        unsafe { opus_decoder_destroy(self.0.as_ptr()) };
    }
}

/// Returns the linked `libopus` version string.
pub fn libopus_version() -> &'static str {
    // SAFETY: `opus_get_version_string` returns a static null-terminated ASCII C string.
    let ptr = unsafe { opus_get_version_string() };
    if ptr.is_null() {
        return "libopus-unknown";
    }
    // SAFETY: Non-null static string returned by `libopus`.
    unsafe { CStr::from_ptr(ptr) }.to_str().unwrap_or("libopus")
}

/// Native `libopus` 48 kHz mono VoIP codec backend implementing [`OpusCodecBackend`].
pub struct LibOpusCodec {
    encoder: OpusEncoderHandle,
    decoder: OpusDecoderHandle,
}

impl LibOpusCodec {
    /// Allocates a 48 kHz mono VoIP `libopus` encoder and decoder pair.
    pub fn new() -> Result<Self, MediaError> {
        let encoder = OpusEncoderHandle::new(48_000, 1, OPUS_APPLICATION_VOIP)?;
        let decoder = OpusDecoderHandle::new(48_000, 1)?;
        Ok(Self { encoder, decoder })
    }
}

impl fmt::Debug for LibOpusCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LibOpusCodec")
            .field("sample_rate_hz", &48_000)
            .field("channels", &1)
            .field("version", &libopus_version())
            .finish()
    }
}

impl OpusCodecBackend for LibOpusCodec {
    fn encode_20ms_48khz(&mut self, pcm_960: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm_960.len() != PCM_FRAME_SAMPLES_48KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_48KHZ_20MS} PCM samples for 20 ms 48 kHz Opus frame, got {}",
                pcm_960.len()
            )));
        }
        self.encoder.encode(pcm_960, PCM_FRAME_SAMPLES_48KHZ_20MS)
    }

    fn decode_20ms_48khz(&mut self, opus_pkt: &[u8]) -> Result<Vec<i16>, MediaError> {
        if opus_pkt.is_empty() {
            return Err(MediaError::PacketTooShort);
        }
        self.decoder.decode(opus_pkt, PCM_FRAME_SAMPLES_48KHZ_20MS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bmsip_media::WavPcm16;

    #[test]
    fn libopus_version_and_48khz_roundtrip() {
        let ver = libopus_version();
        assert!(ver.contains("opus"), "unexpected libopus version: {ver}");

        let mut codec = LibOpusCodec::new().expect("create LibOpusCodec");
        let tone_48k = WavPcm16::generate_sine_wave(48_000, 440, 200, 12_000);

        let mut decoded_all = Vec::new();
        for frame in tone_48k.samples.as_chunks::<960>().0 {
            let encoded = codec.encode_20ms_48khz(frame).expect("encode 48 kHz Opus");
            assert!(
                !encoded.is_empty() && encoded.len() < 250,
                "unexpected Opus packet size: {}",
                encoded.len()
            );
            let decoded = codec
                .decode_20ms_48khz(&encoded)
                .expect("decode 48 kHz Opus");
            assert_eq!(decoded.len(), 960);
            decoded_all.extend_from_slice(&decoded);
        }

        let decoded_wav = WavPcm16::new(48_000, decoded_all);
        assert!(
            decoded_wav.rms_energy() > 4000,
            "decoded 48 kHz Opus RMS too low: {}",
            decoded_wav.rms_energy()
        );
    }

    #[test]
    fn libopus_8khz_convenience_roundtrip() {
        let mut codec = LibOpusCodec::new().expect("create LibOpusCodec");
        let tone_8k = WavPcm16::generate_sine_wave(8_000, 440, 100, 12_000);
        let mut decoded_all = Vec::new();
        for frame in tone_8k.samples.as_chunks::<160>().0 {
            let encoded = codec
                .encode_20ms_8khz(frame)
                .expect("encode 8 kHz via Opus");
            let decoded = codec
                .decode_20ms_8khz(&encoded)
                .expect("decode 8 kHz via Opus");
            assert_eq!(decoded.len(), 160);
            decoded_all.extend_from_slice(&decoded);
        }
        assert!(WavPcm16::new(8_000, decoded_all).rms_energy() > 3000);
    }
}
