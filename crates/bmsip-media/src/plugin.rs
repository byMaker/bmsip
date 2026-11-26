//! MODULE_CONTRACT: Universal pluggable audio codec descriptor, plugin trait, factory, and runtime [`CodecRegistry`].
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero OS audio APIs; operates on 20 ms mono PCM frames with automatic rate adaptation across 8 kHz, 16 kHz, and 48 kHz.
//! RFC_REFS: RFC 3551, RFC 4566, RFC 3264.

use std::fmt;
use std::sync::Arc;

use bmsip_core::sdp::RtpCodec;

use crate::codec::G711Kind;
use crate::error::MediaError;
use crate::g722::{resample_pcm_20ms, resample_pcm_by_rate, G722Codec, StreamResampler};
use crate::opus::{
    OpusCodecBackend, OPUS_RTP_CLOCK_RATE, PCM_FRAME_SAMPLES_48KHZ_20MS,
    PCM_FRAME_SAMPLES_8KHZ_20MS,
};

/// Metadata describing an audio codec's SDP parameters, RTP clock rate, and native PCM rate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioCodecDescriptor {
    pub payload_type: u8,
    pub encoding_name: String,
    pub rtp_clock_rate_hz: u32,
    pub pcm_sample_rate_hz: u32,
    pub channels: Option<u8>,
    pub fmtp: Option<String>,
}

impl AudioCodecDescriptor {
    /// Creates a new [`AudioCodecDescriptor`] with explicit RTP clock and native PCM sample rates.
    pub fn new(
        payload_type: u8,
        encoding_name: impl Into<String>,
        rtp_clock_rate_hz: u32,
        pcm_sample_rate_hz: u32,
    ) -> Self {
        Self {
            payload_type,
            encoding_name: encoding_name.into(),
            rtp_clock_rate_hz,
            pcm_sample_rate_hz,
            channels: None,
            fmtp: None,
        }
    }

    /// Sets the SDP channel count attribute (`a=rtpmap:.../<ch>`).
    pub fn with_channels(mut self, channels: u8) -> Self {
        self.channels = Some(channels);
        self
    }

    /// Sets the SDP `a=fmtp` format parameter line.
    pub fn with_fmtp(mut self, fmtp: impl Into<String>) -> Self {
        self.fmtp = Some(fmtp.into());
        self
    }

    /// Converts this descriptor into an SDP [`RtpCodec`] entry.
    pub fn to_rtp_codec(&self) -> RtpCodec {
        RtpCodec {
            payload_type: self.payload_type,
            encoding_name: self.encoding_name.clone(),
            clock_rate: self.rtp_clock_rate_hz,
            channels: self.channels,
            fmtp: self.fmtp.clone(),
        }
    }

    /// Returns the RTP timestamp advance for a single 20 ms packet (`rtp_clock_rate_hz / 50`).
    pub fn rtp_timestamp_increment_20ms(&self) -> u32 {
        (self.rtp_clock_rate_hz / 50).max(1)
    }

    /// Returns the native mono PCM sample count for one 20 ms frame (`pcm_sample_rate_hz / 50`).
    pub fn native_frame_samples_20ms(&self) -> usize {
        ((self.pcm_sample_rate_hz / 50) as usize).max(1)
    }

    /// Checks whether this descriptor matches a negotiated SDP [`RtpCodec`].
    pub fn matches_rtp_codec(&self, codec: &RtpCodec) -> bool {
        self.encoding_name
            .eq_ignore_ascii_case(&codec.encoding_name)
            && self.rtp_clock_rate_hz == codec.clock_rate
            && self.channels.unwrap_or(1) == codec.channels.unwrap_or(1)
    }
}

/// Pluggable stateful audio codec operating on 20 ms mono PCM frames.
pub trait AudioCodecPlugin: Send + fmt::Debug {
    /// Returns the descriptor identifying this codec's SDP format and native PCM rate.
    fn descriptor(&self) -> &AudioCodecDescriptor;

    /// Encodes one 20 ms mono PCM frame sampled at `descriptor().pcm_sample_rate_hz`.
    fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError>;

    /// Decodes one RTP payload into a 20 ms mono PCM frame at `descriptor().pcm_sample_rate_hz`.
    fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError>;

    /// Encodes a 20 ms PCM frame from any supported [`AudioPort`] sample rate (`8`/`16`/`48` kHz).
    fn encode_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        let native_len = self.descriptor().native_frame_samples_20ms();
        if pcm.len() == native_len {
            self.encode_native_20ms(pcm)
        } else {
            let adapted = resample_pcm_20ms(pcm, native_len)?;
            self.encode_native_20ms(&adapted)
        }
    }

    /// Decodes an RTP payload and adapts the resulting 20 ms PCM frame to `target_frame_samples`.
    fn decode_20ms(
        &mut self,
        payload: &[u8],
        target_frame_samples: usize,
    ) -> Result<Vec<i16>, MediaError> {
        let native = self.decode_native_20ms(payload)?;
        let dst_rate_hz = (target_frame_samples as u32).saturating_mul(50);
        let src_rate_hz = self.descriptor().pcm_sample_rate_hz;
        if native.len() == target_frame_samples && src_rate_hz == dst_rate_hz {
            Ok(native)
        } else if dst_rate_hz > 0 {
            resample_pcm_by_rate(&native, src_rate_hz, dst_rate_hz)
        } else {
            resample_pcm_20ms(&native, target_frame_samples)
        }
    }

    /// Decodes an RTP payload of arbitrary duration (`ptime`) and resamples continuously to `target_rate_hz`.
    fn decode_to_rate(
        &mut self,
        payload: &[u8],
        target_rate_hz: u32,
        resampler: &mut StreamResampler,
    ) -> Result<Vec<i16>, MediaError> {
        let native = self.decode_native_20ms(payload)?;
        resampler.resample_by_rate(
            &native,
            self.descriptor().pcm_sample_rate_hz,
            target_rate_hz,
        )
    }
}

/// Built-in [`AudioCodecPlugin`] implementation for ITU-T G.711 (`PCMU` / `PCMA`).
#[derive(Debug)]
pub struct G711CodecPlugin {
    kind: G711Kind,
    descriptor: AudioCodecDescriptor,
}

impl G711CodecPlugin {
    /// Creates a plugin wrapper for either `PCMU` (PT `0`) or `PCMA` (PT `8`).
    pub fn new(kind: G711Kind) -> Self {
        let (pt, name) = match kind {
            G711Kind::Pcmu => (0, "PCMU"),
            G711Kind::Pcma => (8, "PCMA"),
        };
        Self {
            kind,
            descriptor: AudioCodecDescriptor::new(pt, name, 8_000, 8_000),
        }
    }
}

impl AudioCodecPlugin for G711CodecPlugin {
    fn descriptor(&self) -> &AudioCodecDescriptor {
        &self.descriptor
    }

    fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm.len() != PCM_FRAME_SAMPLES_8KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_8KHZ_20MS} PCM samples for G.711 frame, got {}",
                pcm.len()
            )));
        }
        Ok(self.kind.encode(pcm))
    }

    fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
        if payload.is_empty() {
            return Err(MediaError::PacketTooShort);
        }
        Ok(self.kind.decode(payload))
    }
}

/// Adapter exposing any [`OpusCodecBackend`] (native `LibOpusCodec` or [`BuiltInOpusCodec`]) as an [`AudioCodecPlugin`].
#[derive(Debug)]
pub struct OpusPluginAdapter {
    backend: Box<dyn OpusCodecBackend>,
    descriptor: AudioCodecDescriptor,
}

impl OpusPluginAdapter {
    /// Wraps an [`OpusCodecBackend`] with RFC 7587 `opus/48000/2` SDP metadata.
    pub fn new(backend: Box<dyn OpusCodecBackend>) -> Self {
        Self {
            backend,
            descriptor: AudioCodecDescriptor::new(111, "opus", OPUS_RTP_CLOCK_RATE, 48_000)
                .with_channels(2)
                .with_fmtp("minptime=10;useinbandfec=1"),
        }
    }
}

impl AudioCodecPlugin for OpusPluginAdapter {
    fn descriptor(&self) -> &AudioCodecDescriptor {
        &self.descriptor
    }

    fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
        if pcm.len() != PCM_FRAME_SAMPLES_48KHZ_20MS {
            return Err(MediaError::BufferError(format!(
                "expected {PCM_FRAME_SAMPLES_48KHZ_20MS} PCM samples for 48 kHz Opus frame, got {}",
                pcm.len()
            )));
        }
        self.backend.encode_20ms_48khz(pcm)
    }

    fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
        self.backend.decode_20ms_48khz(payload)
    }
}

/// Thread-safe factory instantiating a fresh per-call [`AudioCodecPlugin`] instance.
pub trait AudioCodecFactory: Send + Sync + fmt::Debug {
    /// Returns the codec descriptor advertised in SDP and matched during negotiation.
    fn descriptor(&self) -> &AudioCodecDescriptor;

    /// Constructs a stateful encoder/decoder instance for one SIP call.
    fn create(&self) -> Box<dyn AudioCodecPlugin>;
}

/// Closure-backed [`AudioCodecFactory`] helper for ergonomic external codec registration.
pub struct FnCodecFactory {
    descriptor: AudioCodecDescriptor,
    constructor: Box<dyn Fn() -> Box<dyn AudioCodecPlugin> + Send + Sync>,
}

impl FnCodecFactory {
    /// Wraps an [`AudioCodecDescriptor`] and per-call constructor closure into an [`AudioCodecFactory`].
    pub fn new<F>(descriptor: AudioCodecDescriptor, constructor: F) -> Self
    where
        F: Fn() -> Box<dyn AudioCodecPlugin> + Send + Sync + 'static,
    {
        Self {
            descriptor,
            constructor: Box::new(constructor),
        }
    }
}

impl fmt::Debug for FnCodecFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FnCodecFactory")
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

impl AudioCodecFactory for FnCodecFactory {
    fn descriptor(&self) -> &AudioCodecDescriptor {
        &self.descriptor
    }

    fn create(&self) -> Box<dyn AudioCodecPlugin> {
        (self.constructor)()
    }
}

/// Runtime registry mapping negotiated SDP codecs to stateful [`AudioCodecPlugin`] factories.
#[derive(Clone, Default)]
pub struct CodecRegistry {
    factories: Vec<Arc<dyn AudioCodecFactory>>,
}

impl CodecRegistry {
    /// Creates an empty [`CodecRegistry`].
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
        }
    }

    /// Creates a [`CodecRegistry`] pre-populated with built-in pure-Rust `PCMU`, `PCMA`, and `G722` plugins.
    pub fn with_builtin_codecs() -> Self {
        let mut reg = Self::new();
        reg.register_fn(G722Codec::default_descriptor(), || {
            Box::new(G722Codec::new())
        });
        reg.register_fn(AudioCodecDescriptor::new(0, "PCMU", 8_000, 8_000), || {
            Box::new(G711CodecPlugin::new(G711Kind::Pcmu))
        });
        reg.register_fn(AudioCodecDescriptor::new(8, "PCMA", 8_000, 8_000), || {
            Box::new(G711CodecPlugin::new(G711Kind::Pcma))
        });
        reg
    }

    /// Registers or replaces a codec factory matching the same encoding name, RTP clock rate, and channel count.
    pub fn register(&mut self, factory: Arc<dyn AudioCodecFactory>) {
        let rtp = factory.descriptor().to_rtp_codec();
        self.factories
            .retain(|existing| !existing.descriptor().matches_rtp_codec(&rtp));
        self.factories.push(factory);
    }

    /// Registers a closure-backed codec factory in one call.
    pub fn register_fn<F>(&mut self, descriptor: AudioCodecDescriptor, constructor: F)
    where
        F: Fn() -> Box<dyn AudioCodecPlugin> + Send + Sync + 'static,
    {
        self.register(Arc::new(FnCodecFactory::new(descriptor, constructor)));
    }

    /// Instantiates a registered plugin matching the negotiated SDP `codec`, if available.
    pub fn instantiate(&self, codec: &RtpCodec) -> Option<Box<dyn AudioCodecPlugin>> {
        self.factories
            .iter()
            .find(|factory| factory.descriptor().matches_rtp_codec(codec))
            .map(|factory| factory.create())
    }

    /// Returns copies of all registered codec descriptors.
    pub fn descriptors(&self) -> Vec<AudioCodecDescriptor> {
        self.factories
            .iter()
            .map(|f| f.descriptor().clone())
            .collect()
    }
}

impl fmt::Debug for CodecRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<String> = self
            .factories
            .iter()
            .map(|fact| {
                let d = fact.descriptor();
                format!(
                    "{}/{}@{}",
                    d.encoding_name, d.rtp_clock_rate_hz, d.payload_type
                )
            })
            .collect();
        f.debug_struct("CodecRegistry")
            .field("codecs", &names)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockL16Codec {
        desc: AudioCodecDescriptor,
    }

    impl MockL16Codec {
        fn new() -> Self {
            Self {
                desc: AudioCodecDescriptor::new(98, "L16", 16_000, 16_000),
            }
        }
    }

    impl AudioCodecPlugin for MockL16Codec {
        fn descriptor(&self) -> &AudioCodecDescriptor {
            &self.desc
        }

        fn encode_native_20ms(&mut self, pcm: &[i16]) -> Result<Vec<u8>, MediaError> {
            let mut out = Vec::with_capacity(pcm.len() * 2);
            for &s in pcm {
                out.extend_from_slice(&s.to_be_bytes());
            }
            Ok(out)
        }

        fn decode_native_20ms(&mut self, payload: &[u8]) -> Result<Vec<i16>, MediaError> {
            let mut out = Vec::with_capacity(payload.len() / 2);
            for chunk in payload.as_chunks::<2>().0 {
                out.push(i16::from_be_bytes([chunk[0], chunk[1]]));
            }
            Ok(out)
        }
    }

    #[test]
    fn registry_registers_custom_codec_and_adapts_sample_rates() {
        let mut reg = CodecRegistry::with_builtin_codecs();
        reg.register_fn(AudioCodecDescriptor::new(98, "L16", 16_000, 16_000), || {
            Box::new(MockL16Codec::new())
        });

        let negotiated = RtpCodec {
            payload_type: 98,
            encoding_name: "l16".to_string(),
            clock_rate: 16_000,
            channels: None,
            fmtp: None,
        };
        let mut plugin = reg.instantiate(&negotiated).expect("custom L16 plugin");
        assert_eq!(plugin.descriptor().native_frame_samples_20ms(), 320);

        // Feed 48 kHz audio (960 samples); plugin automatically adapts 48k -> 16k -> 48k.
        let frame_48k: Vec<i16> = (0..960).map(|i| ((i * 53) % 10_000) as i16).collect();
        let encoded = plugin.encode_20ms(&frame_48k).unwrap();
        assert_eq!(encoded.len(), 640);
        let decoded_48k = plugin.decode_20ms(&encoded, 960).unwrap();
        assert_eq!(decoded_48k.len(), 960);
    }
}
