#![forbid(unsafe_code)]

//! MODULE_CONTRACT: Hardware-agnostic RTP/RTCP, G.711 codecs, RFC 4733 DTMF, adaptive jitter buffer, and in-memory WAV pipeline (`bmsip-media`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero OS audio device APIs (ALSA, PipeWire, CoreAudio, Oboe); zero `std::net`, `std::thread`, `std::fs`, `Instant::now()`, or `SystemTime::now()`; no `.unwrap()`/`.expect()` outside tests.
//! RFC_REFS: RFC 3550 (RTP/RTCP), RFC 3551 (G.711), RFC 4733 (DTMF), RFC 6716 / RFC 7587 (Opus).

pub mod codec;
pub mod dtmf;
pub mod error;
pub mod jitter;
pub mod opus;
pub mod rtcp;
pub mod rtp;
pub mod session;
pub mod wav;

pub use bmsip_core::core_version;
pub use codec::{
    alaw_decode_sample, alaw_encode_sample, decode_pcma, decode_pcmu, encode_pcma, encode_pcmu,
    ulaw_decode_sample, ulaw_encode_sample, G711Kind,
};
pub use dtmf::{DtmfDetector, DtmfDigit, DtmfEventPayload, DtmfSender};
pub use error::MediaError;
pub use jitter::{AdaptiveJitterBuffer, JitterBufferConfig, PlayoutFrame};
pub use opus::{
    downsample_48k_to_8k, upsample_8k_to_48k, BuiltInOpusCodec, OpusBandwidth, OpusCodecBackend,
    OpusFmtp, OpusMode, OpusToc, OPUS_RTP_CLOCK_RATE, OPUS_RTP_SAMPLES_20MS,
};
pub use rtcp::{ReceptionReportBlock, RtcpPacket, RtcpSenderInfo, RtpStreamStats};
pub use rtp::{RtpExtensionHeader, RtpHeader, RtpPacket, RtpPacketizer};
pub use session::{MediaSession, SessionCodec};
pub use wav::WavPcm16;
