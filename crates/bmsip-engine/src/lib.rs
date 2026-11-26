#![deny(unsafe_code)]

//! MODULE_CONTRACT: Deadlock-free multi-instance SIP runtime engine (`SipEngine`) wiring `bmsip-core` and `bmsip-media` to OS UDP/TCP/TLS (`rustls`) sockets, RFC 4568 SDES-SRTP, monotonic timers, `AudioPort`, `LibOpusCodec`, and `FlightRecorder`.
//! INVARIANTS: `unsafe` code restricted strictly to `opus_native`; zero global singletons or `static mut`; zero synchronous user callbacks invoked while holding mutexes; all host interaction goes through non-blocking `EngineCommand`/`EngineEvent` queues.
//! RFC_REFS: RFC 3261, RFC 3550, RFC 3711, RFC 4568, RFC 4733, RFC 5626, RFC 5922, RFC 6716.

pub mod audio;
pub mod command;
#[cfg(feature = "experimental-dtls")]
pub mod dtls;
pub mod engine;
pub mod error;
pub mod opus_native;
pub mod telemetry;
pub mod tls;
mod transport;

pub use audio::{
    AudioPort, NullAudioPort, PcmAudioHandle, PcmQueueAudioPort, WavAudioHandle, WavAudioPort,
    PCM_FRAME_SAMPLES_16KHZ_20MS, PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS,
};
pub use bmsip_core;
pub use bmsip_media;
pub use command::{EngineCommand, EngineConfig, EngineEvent, DEFAULT_UDP_KEEPALIVE_SECS};
pub use engine::{EngineEventReceiver, SipEngine};
pub use error::EngineError;
pub use opus_native::{libopus_version, LibOpusCodec};
pub use telemetry::{CallBlackBoxSnapshot, FlightRecorder, TelemetryCategory, TelemetryEntry};
pub use tls::TlsConfig;
