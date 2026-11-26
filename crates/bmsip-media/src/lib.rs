#![forbid(unsafe_code)]

//! MODULE_CONTRACT: Hardware-agnostic RTP/RTCP, RFC 3711 SRTP/SRTCP, G.711/G.722/Opus codecs, RFC 4733 DTMF, RFC 3389 Comfort Noise, adaptive jitter buffer, and in-memory WAV pipeline (`bmsip-media`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero OS audio device APIs (ALSA, PipeWire, CoreAudio, Oboe); zero `std::net`, `std::thread`, `std::fs`, `Instant::now()`, or `SystemTime::now()`; no `.unwrap()`/`.expect()` outside tests.
//! RFC_REFS: RFC 3389 (Comfort Noise), RFC 3550 (RTP/RTCP), RFC 3551 (G.711/G.722), RFC 3711 (SRTP/SRTCP), RFC 4733 (DTMF), RFC 5764 (DTLS-SRTP), RFC 6716 / RFC 7587 (Opus).

pub mod cn;
pub mod codec;
pub mod dtmf;
pub mod error;
pub mod g722;
pub mod jitter;
pub mod opus;
pub mod plugin;
pub mod rtcp;
pub mod rtp;
pub mod session;
pub mod srtp;
pub mod wav;

pub use bmsip_core::core_version;
pub use cn::{ComfortNoiseGenerator, ComfortNoisePacket, CN_PAYLOAD_TYPE, CN_RTP_CLOCK_RATE};
pub use codec::{
    alaw_decode_sample, alaw_encode_sample, decode_pcma, decode_pcmu, encode_pcma, encode_pcmu,
    ulaw_decode_sample, ulaw_encode_sample, G711Kind,
};
pub use dtmf::{DtmfDetector, DtmfDigit, DtmfEventPayload, DtmfSender};
pub use error::MediaError;
pub use g722::{
    downsample_16k_to_8k, downsample_48k_to_16k, resample_pcm_20ms, resample_pcm_by_rate,
    upsample_16k_to_48k, upsample_8k_to_16k, G722Codec, G722Decoder, G722Encoder, StreamResampler,
    G722_FRAME_BYTES_20MS, G722_PAYLOAD_TYPE, G722_RTP_CLOCK_RATE, G722_RTP_SAMPLES_20MS,
    G722_SAMPLE_RATE_HZ, PCM_FRAME_SAMPLES_16KHZ_20MS,
};
pub use jitter::{AdaptiveJitterBuffer, JitterBufferConfig, PlayoutFrame};
pub use opus::{
    condition_mic_frame, downsample_48k_to_8k, upsample_8k_to_48k, BuiltInOpusCodec, OpusBandwidth,
    OpusCodecBackend, OpusFmtp, OpusMode, OpusToc, OPUS_MAX_FRAME_SAMPLES_48KHZ,
    OPUS_RTP_CLOCK_RATE, OPUS_RTP_SAMPLES_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS,
    PCM_FRAME_SAMPLES_8KHZ_20MS,
};
pub use plugin::{
    AudioCodecDescriptor, AudioCodecFactory, AudioCodecPlugin, CodecRegistry, FnCodecFactory,
    G711CodecPlugin, OpusPluginAdapter,
};
pub use rtcp::{
    ReceptionReportBlock, RtcpPacket, RtcpSenderInfo, RtpStreamStats, SdesChunk, SdesItem,
    SeqStatus, SDES_CNAME,
};
pub use rtp::{RtpExtensionHeader, RtpHeader, RtpPacket, RtpPacketRef, RtpPacketizer};
pub use session::{MediaSession, SessionCodec};
pub use srtp::{
    aes128_encrypt_block, derive_srtp_session_keys, hmac_sha1, sha1, DerivedSrtpKeys, SrtpContext,
    SrtpKeyMaterial,
};
pub use wav::WavPcm16;
