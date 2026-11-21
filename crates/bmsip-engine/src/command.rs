//! MODULE_CONTRACT: Non-blocking `EngineConfig`, `EngineCommand`, and `EngineEvent` contracts for [`crate::SipEngine`].
//! INVARIANTS: All variants are `Send`; host communication uses asynchronous message passing without callbacks under mutexes.
//! RFC_REFS: RFC 3261, RFC 4733.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bmsip_core::dialog::{RegistrationState, UaConfig};
use bmsip_core::sip::SipUri;
use bmsip_media::{AudioCodecFactory, CodecRegistry, DtmfDigit};

/// Startup configuration for [`crate::SipEngine`].
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub ua_config: UaConfig,
    pub registrar_addr: SocketAddr,
    pub bind_ip: IpAddr,
    pub sip_port: u16,
    pub telemetry_capacity: usize,
    pub codec_registry: CodecRegistry,
}

impl EngineConfig {
    /// Creates an [`EngineConfig`] with built-in codecs and a default telemetry ring capacity of 256 events.
    pub fn new(
        ua_config: UaConfig,
        registrar_addr: SocketAddr,
        bind_ip: IpAddr,
        sip_port: u16,
    ) -> Self {
        Self {
            ua_config,
            registrar_addr,
            bind_ip,
            sip_port,
            telemetry_capacity: 256,
            codec_registry: CodecRegistry::with_builtin_codecs(),
        }
    }

    /// Registers an [`AudioCodecFactory`] in `codec_registry` without changing the advertised SDP order.
    pub fn register_codec(&mut self, factory: Arc<dyn AudioCodecFactory>) {
        self.codec_registry.register(factory);
    }

    /// Registers a custom [`AudioCodecFactory`] and promotes its SDP entry to preferred position.
    pub fn register_custom_codec(&mut self, factory: Arc<dyn AudioCodecFactory>) {
        let rtp_codec = factory.descriptor().to_rtp_codec();
        self.codec_registry.register(factory);
        self.ua_config.supported_codecs.retain(|c| {
            !(c.encoding_name
                .eq_ignore_ascii_case(&rtp_codec.encoding_name)
                && c.clock_rate == rtp_codec.clock_rate
                && c.channels.unwrap_or(1) == rtp_codec.channels.unwrap_or(1))
        });
        self.ua_config.supported_codecs.insert(0, rtp_codec);
    }
}

/// Commands pushed from the application into [`crate::SipEngine`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineCommand {
    Register,
    Unregister,
    Dial {
        target_uri: SipUri,
    },
    Ring {
        call_id: String,
    },
    Answer {
        call_id: String,
    },
    Hangup {
        call_id: String,
    },
    Hold {
        call_id: String,
    },
    ResumeCall {
        call_id: String,
    },
    Transfer {
        call_id: String,
        target_uri: SipUri,
    },
    AttendedTransfer {
        call_id: String,
        target_call_id: String,
    },
    SendDtmf {
        call_id: String,
        digit: DtmfDigit,
    },
    NetworkChanged {
        new_bind_ip: IpAddr,
        new_sip_port: u16,
    },
    Suspend,
    Resume,
    ExportTelemetry {
        call_id: Option<String>,
    },
    Shutdown,
}

/// Events emitted from [`crate::SipEngine`] to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    RegistrationChanged(RegistrationState),
    OutboundCallStarted {
        call_id: String,
    },
    IncomingCall {
        call_id: String,
        from: String,
        to: String,
    },
    CallRinging {
        call_id: String,
        status_code: u16,
    },
    CallEstablished {
        call_id: String,
        codec: String,
        remote_rtp: SocketAddr,
    },
    CallMediaUpdated {
        call_id: String,
        remote_rtp: SocketAddr,
    },
    CallHoldChanged {
        call_id: String,
        local_hold: bool,
        remote_hold: bool,
    },
    CallTransferRequested {
        call_id: String,
        refer_to: String,
    },
    TransferStatus {
        call_id: String,
        status_code: u16,
        reason: String,
        terminated: bool,
    },
    DtmfReceived {
        call_id: String,
        digit: DtmfDigit,
    },
    CallTerminated {
        call_id: String,
        status_code: Option<u16>,
        reason: String,
        black_box_json: String,
    },
    Suspended,
    Resumed {
        local_sip_addr: SocketAddr,
    },
    NetworkUpdated {
        local_sip_addr: SocketAddr,
    },
    TelemetryExported {
        call_id: Option<String>,
        json: String,
    },
    Warning(String),
    Stopped,
}
