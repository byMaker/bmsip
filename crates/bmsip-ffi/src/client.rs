//! MODULE_CONTRACT: Safe Rust / UniFFI SDK object (`BmsipClient`) wrapping `SipEngine` and `PcmQueueAudioPort`.
//! INVARIANTS: `#![forbid(unsafe_code)]`; `Send + Sync` safe for Swift/Kotlin bindings; zero `.unwrap()`/`.expect()`; non-blocking PCM and event queues.
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733, RFC 7587.

#![forbid(unsafe_code)]

use std::fmt::{self, Write as _};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::time::Duration;

use bmsip_engine::bmsip_core::dialog::{RegistrationState, UaConfig};
use bmsip_engine::bmsip_core::sdp::{RtpCodec, SrtpMode};
use bmsip_engine::bmsip_core::sip::{SipTransport, SipUri};
use bmsip_engine::bmsip_media::DtmfDigit;
use bmsip_engine::{
    EngineCommand, EngineConfig, EngineEvent, PcmAudioHandle, PcmQueueAudioPort, SipEngine,
    TlsConfig,
};

/// Cross-platform FFI error surfaced to Swift, Kotlin, and C callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FfiError {
    InvalidArgument(String),
    RuntimeError(String),
    Closed,
}

impl fmt::Display for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::RuntimeError(msg) => write!(f, "runtime error: {msg}"),
            Self::Closed => write!(f, "client is closed"),
        }
    }
}

impl std::error::Error for FfiError {}

/// Signaling transport selection matching `FfiTransport` in `bmsip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiTransport {
    Udp,
    Tcp,
    Tls,
}

impl FfiTransport {
    /// Parses a case-insensitive transport string (`"udp"`, `"tcp"`, `"tls"`).
    pub fn parse_str(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "udp" => Some(Self::Udp),
            "tcp" => Some(Self::Tcp),
            "tls" => Some(Self::Tls),
            _ => None,
        }
    }

    fn to_sip_transport(self) -> SipTransport {
        match self {
            Self::Udp => SipTransport::Udp,
            Self::Tcp => SipTransport::Tcp,
            Self::Tls => SipTransport::Tls,
        }
    }
}

/// SRTP media encryption mode matching `FfiSrtpMode` in `bmsip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiSrtpMode {
    Disabled,
    SdesOptional,
    SdesRequired,
    DtlsSrtp,
}

impl FfiSrtpMode {
    /// Parses a case-insensitive SRTP mode string (`"off"`, `"optional"`, `"sdes"`, `"dtls"`).
    pub fn parse_str(raw: &str) -> Option<Self> {
        match SrtpMode::parse(raw).ok()? {
            SrtpMode::Disabled => Some(Self::Disabled),
            SrtpMode::SdesOptional => Some(Self::SdesOptional),
            SrtpMode::SdesRequired => Some(Self::SdesRequired),
            SrtpMode::DtlsSrtp => Some(Self::DtlsSrtp),
        }
    }

    fn to_srtp_mode(self) -> SrtpMode {
        match self {
            Self::Disabled => SrtpMode::Disabled,
            Self::SdesOptional => SrtpMode::SdesOptional,
            Self::SdesRequired => SrtpMode::SdesRequired,
            Self::DtlsSrtp => SrtpMode::DtlsSrtp,
        }
    }
}

/// Startup configuration matching `FfiConfig` in `bmsip.udl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiConfig {
    pub username: String,
    pub password: String,
    pub domain: String,
    pub registrar_addr: String,
    pub bind_ip: String,
    pub sip_port: u16,
    pub enable_opus: bool,
}

/// Discriminant matching `FfiEventKind` in `bmsip.udl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FfiEventKind {
    RegistrationChanged,
    OutboundCallStarted,
    IncomingCall,
    CallRinging,
    EarlyMediaStarted,
    CallEstablished,
    CallMediaUpdated,
    CallHoldChanged,
    CallTransferRequested,
    TransferStatus,
    DtmfReceived,
    CallTerminated,
    Suspended,
    Resumed,
    NetworkUpdated,
    TelemetryExported,
    Warning,
    Stopped,
}

impl FfiEventKind {
    /// Returns the canonical string label for JSON serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistrationChanged => "RegistrationChanged",
            Self::OutboundCallStarted => "OutboundCallStarted",
            Self::IncomingCall => "IncomingCall",
            Self::CallRinging => "CallRinging",
            Self::EarlyMediaStarted => "EarlyMediaStarted",
            Self::CallEstablished => "CallEstablished",
            Self::CallMediaUpdated => "CallMediaUpdated",
            Self::CallHoldChanged => "CallHoldChanged",
            Self::CallTransferRequested => "CallTransferRequested",
            Self::TransferStatus => "TransferStatus",
            Self::DtmfReceived => "DtmfReceived",
            Self::CallTerminated => "CallTerminated",
            Self::Suspended => "Suspended",
            Self::Resumed => "Resumed",
            Self::NetworkUpdated => "NetworkUpdated",
            Self::TelemetryExported => "TelemetryExported",
            Self::Warning => "Warning",
            Self::Stopped => "Stopped",
        }
    }
}

/// Typed event matching `FfiEvent` in `bmsip.udl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfiEvent {
    pub kind: FfiEventKind,
    pub call_id: Option<String>,
    pub detail: Option<String>,
    pub status_code: Option<u16>,
    pub black_box_json: Option<String>,
}

impl FfiEvent {
    /// Serializes this event to JSON for the C-API (`bmsip_client_poll_event_json`).
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(256);
        let _ = write!(out, "{{\"kind\":{}", json_quote(self.kind.as_str()));
        write_opt_str(&mut out, "call_id", self.call_id.as_deref());
        write_opt_str(&mut out, "detail", self.detail.as_deref());
        match self.status_code {
            Some(code) => {
                let _ = write!(out, ",\"status_code\":{code}");
            }
            None => out.push_str(",\"status_code\":null"),
        }
        write_opt_str(&mut out, "black_box_json", self.black_box_json.as_deref());
        out.push('}');
        out
    }
}

/// High-level cross-platform SIP client matching `interface BmsipClient` in `bmsip.udl`.
pub struct BmsipClient {
    engine: Mutex<Option<SipEngine>>,
    audio: PcmAudioHandle,
}

impl BmsipClient {
    /// Creates and starts a new [`BmsipClient`] instance with an 8 kHz (160-sample/20 ms) PCM bridge.
    pub fn new(config: FfiConfig) -> Result<Self, FfiError> {
        Self::new_with_sample_rate(config, 8_000)
    }

    /// Creates and starts a new [`BmsipClient`] with an explicit PCM bridge rate (`8000`, `16000`, or `48000` Hz).
    pub fn new_with_sample_rate(config: FfiConfig, sample_rate_hz: u32) -> Result<Self, FfiError> {
        Self::new_with_transport(config, sample_rate_hz, FfiTransport::Udp, None, false)
    }

    /// Creates and starts a new [`BmsipClient`] with explicit PCM bridge rate, SIP transport (`Udp`/`Tcp`/`Tls`),
    /// optional PEM CA trust bundle, and optional insecure TLS bypass flag (for lab/self-signed servers only).
    pub fn new_with_transport(
        config: FfiConfig,
        sample_rate_hz: u32,
        transport: FfiTransport,
        tls_ca_pem: Option<String>,
        tls_insecure: bool,
    ) -> Result<Self, FfiError> {
        Self::new_with_security(
            config,
            sample_rate_hz,
            transport,
            FfiSrtpMode::Disabled,
            tls_ca_pem,
            tls_insecure,
        )
    }

    /// Creates and starts a new [`BmsipClient`] with explicit PCM bridge rate, SIP transport (`Udp`/`Tcp`/`Tls`),
    /// SRTP media encryption mode (`Disabled`/`SdesOptional`/`SdesRequired`/`DtlsSrtp`), optional PEM CA trust bundle,
    /// and optional insecure TLS bypass flag.
    pub fn new_with_security(
        config: FfiConfig,
        sample_rate_hz: u32,
        transport: FfiTransport,
        srtp_mode: FfiSrtpMode,
        tls_ca_pem: Option<String>,
        tls_insecure: bool,
    ) -> Result<Self, FfiError> {
        if !matches!(sample_rate_hz, 8_000 | 16_000 | 48_000) {
            return Err(FfiError::InvalidArgument(format!(
                "unsupported audio sample_rate_hz {sample_rate_hz} (expected 8000, 16000, or 48000)"
            )));
        }
        let registrar_addr = resolve_socket_addr(&config.registrar_addr)?;
        let bind_ip: IpAddr = config.bind_ip.parse().map_err(|_| {
            FfiError::InvalidArgument(format!("invalid bind_ip '{}'", config.bind_ip))
        })?;

        let registrar_uri = SipUri::parse(&format!("sip:{}", config.registrar_addr))
            .map_err(|e| FfiError::InvalidArgument(e.to_string()))?;

        let mut ua_cfg = UaConfig::new(
            config.username,
            config.password,
            config.domain,
            registrar_uri,
            config.bind_ip,
            config.sip_port,
        )
        .with_transport(transport.to_sip_transport())
        .with_srtp_mode(srtp_mode.to_srtp_mode());
        if config.enable_opus {
            ua_cfg.supported_codecs = vec![
                RtpCodec::opus(),
                RtpCodec::g722(),
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::cn(),
                RtpCodec::telephone_event_48k(102),
                RtpCodec::telephone_event(101),
            ];
        } else {
            ua_cfg.supported_codecs = vec![
                RtpCodec::g722(),
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::cn(),
                RtpCodec::telephone_event(101),
            ];
        }

        let tls_cfg = TlsConfig {
            ca_cert_pem: tls_ca_pem,
            accept_invalid_certs: tls_insecure,
            ..TlsConfig::default()
        };
        let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, bind_ip, config.sip_port)
            .with_tls_config(tls_cfg);
        let (audio_port, audio_handle) =
            PcmQueueAudioPort::new_with_sample_rate(sample_rate_hz, 64);
        let engine = SipEngine::spawn(eng_cfg, Box::new(audio_port))
            .map_err(|e| FfiError::RuntimeError(e.to_string()))?;

        Ok(Self {
            engine: Mutex::new(Some(engine)),
            audio: audio_handle,
        })
    }

    /// Returns the configured mono PCM sample rate (`8000`, `16000`, or `48000` Hz) of the audio bridge.
    pub fn audio_sample_rate_hz(&self) -> u32 {
        self.audio.sample_rate_hz()
    }

    pub fn register_account(&self) -> Result<(), FfiError> {
        self.send(EngineCommand::Register)
    }

    pub fn unregister_account(&self) -> Result<(), FfiError> {
        self.send(EngineCommand::Unregister)
    }

    pub fn dial(&self, target_uri: String) -> Result<(), FfiError> {
        let uri =
            SipUri::parse(&target_uri).map_err(|e| FfiError::InvalidArgument(e.to_string()))?;
        self.send(EngineCommand::Dial { target_uri: uri })
    }

    pub fn ring(&self, call_id: String) -> Result<(), FfiError> {
        self.send(EngineCommand::Ring { call_id })
    }

    pub fn ring_early_media(&self, call_id: String) -> Result<(), FfiError> {
        self.send(EngineCommand::RingEarlyMedia { call_id })
    }

    pub fn answer(&self, call_id: String) -> Result<(), FfiError> {
        self.send(EngineCommand::Answer { call_id })
    }

    pub fn hangup(&self, call_id: String) -> Result<(), FfiError> {
        self.send(EngineCommand::Hangup { call_id })
    }

    pub fn hold(&self, call_id: String) -> Result<(), FfiError> {
        self.send(EngineCommand::Hold { call_id })
    }

    pub fn resume_call(&self, call_id: String) -> Result<(), FfiError> {
        self.send(EngineCommand::ResumeCall { call_id })
    }

    pub fn transfer(&self, call_id: String, target_uri: String) -> Result<(), FfiError> {
        let uri =
            SipUri::parse(&target_uri).map_err(|e| FfiError::InvalidArgument(e.to_string()))?;
        self.send(EngineCommand::Transfer {
            call_id,
            target_uri: uri,
        })
    }

    pub fn attended_transfer(
        &self,
        call_id: String,
        target_call_id: String,
    ) -> Result<(), FfiError> {
        self.send(EngineCommand::AttendedTransfer {
            call_id,
            target_call_id,
        })
    }

    pub fn send_dtmf(&self, call_id: String, digit: String) -> Result<(), FfiError> {
        let ch = digit
            .chars()
            .next()
            .ok_or_else(|| FfiError::InvalidArgument("empty DTMF digit".to_string()))?;
        let d = DtmfDigit::from_char(ch).map_err(|e| FfiError::InvalidArgument(e.to_string()))?;
        self.send(EngineCommand::SendDtmf { call_id, digit: d })
    }

    pub fn send_info_dtmf(
        &self,
        call_id: String,
        digit: String,
        duration_ms: u32,
    ) -> Result<(), FfiError> {
        let ch = digit
            .chars()
            .next()
            .ok_or_else(|| FfiError::InvalidArgument("empty DTMF digit".to_string()))?;
        let d = DtmfDigit::from_char(ch).map_err(|e| FfiError::InvalidArgument(e.to_string()))?;
        self.send(EngineCommand::SendInfoDtmf {
            call_id,
            digit: d,
            duration_ms,
        })
    }

    pub fn notify_network_changed(&self, bind_ip: String, sip_port: u16) -> Result<(), FfiError> {
        let ip: IpAddr = bind_ip
            .parse()
            .map_err(|_| FfiError::InvalidArgument(format!("invalid bind_ip '{bind_ip}'")))?;
        self.send(EngineCommand::NetworkChanged {
            new_bind_ip: ip,
            new_sip_port: sip_port,
        })
    }

    pub fn suspend(&self) -> Result<(), FfiError> {
        self.send(EngineCommand::Suspend)
    }

    pub fn resume(&self) -> Result<(), FfiError> {
        self.send(EngineCommand::Resume)
    }

    pub fn request_telemetry(&self, call_id: Option<String>) -> Result<(), FfiError> {
        self.send(EngineCommand::ExportTelemetry { call_id })
    }

    pub fn push_captured_pcm(&self, samples: Vec<i16>) -> Result<(), FfiError> {
        let got = samples.len();
        self.audio
            .push_captured_samples(samples)
            .map_err(|expected| {
                FfiError::InvalidArgument(format!("expected {expected} PCM samples, got {got}"))
            })
    }

    pub fn pop_playout_pcm(&self) -> Option<Vec<i16>> {
        self.audio.pop_playout_frame()
    }

    pub fn poll_event(&self, timeout_ms: u32) -> Option<FfiEvent> {
        let ev = {
            let guard = self.engine.lock().ok()?;
            let eng = guard.as_ref()?;
            if timeout_ms == 0 {
                eng.try_recv_event()
            } else {
                eng.recv_event_timeout(Duration::from_millis(u64::from(timeout_ms)))
            }
        };
        ev.map(map_engine_event)
    }

    pub fn local_sip_address(&self) -> String {
        self.engine
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|e| e.local_sip_addr().to_string()))
            .unwrap_or_default()
    }

    pub fn shutdown(&self) {
        if let Ok(mut guard) = self.engine.lock() {
            if let Some(eng) = guard.take() {
                let _ = eng.shutdown();
            }
        }
    }

    fn send(&self, cmd: EngineCommand) -> Result<(), FfiError> {
        let guard = self.engine.lock().map_err(|_| FfiError::Closed)?;
        let eng = guard.as_ref().ok_or(FfiError::Closed)?;
        eng.send_command(cmd)
            .map_err(|e| FfiError::RuntimeError(e.to_string()))
    }
}

fn resolve_socket_addr(addr: &str) -> Result<SocketAddr, FfiError> {
    let target = if addr.contains(':') {
        addr.to_string()
    } else {
        format!("{addr}:5060")
    };
    target
        .to_socket_addrs()
        .map_err(|e| FfiError::InvalidArgument(format!("failed to resolve '{target}': {e}")))?
        .next()
        .ok_or_else(|| FfiError::InvalidArgument(format!("no addresses resolved for '{target}'")))
}

fn map_engine_event(ev: EngineEvent) -> FfiEvent {
    match ev {
        EngineEvent::RegistrationChanged(state) => {
            let label = match state {
                RegistrationState::Unregistered => "Unregistered".to_string(),
                RegistrationState::Registering => "Registering".to_string(),
                RegistrationState::Registered { expires_secs, .. } => {
                    format!("Registered(expires={expires_secs})")
                }
                RegistrationState::Unregistering => "Unregistering".to_string(),
                RegistrationState::Failed {
                    status_code,
                    reason,
                } => format!("Failed(code={status_code:?}, reason={reason})"),
            };
            FfiEvent {
                kind: FfiEventKind::RegistrationChanged,
                call_id: None,
                detail: Some(label),
                status_code: None,
                black_box_json: None,
            }
        }
        EngineEvent::OutboundCallStarted { call_id } => FfiEvent {
            kind: FfiEventKind::OutboundCallStarted,
            call_id: Some(call_id),
            detail: None,
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::IncomingCall { call_id, from, to } => FfiEvent {
            kind: FfiEventKind::IncomingCall,
            call_id: Some(call_id),
            detail: Some(format!("{from} -> {to}")),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::CallRinging {
            call_id,
            status_code,
        } => FfiEvent {
            kind: FfiEventKind::CallRinging,
            call_id: Some(call_id),
            detail: None,
            status_code: Some(status_code),
            black_box_json: None,
        },
        EngineEvent::EarlyMediaStarted {
            call_id,
            codec,
            remote_rtp,
        } => FfiEvent {
            kind: FfiEventKind::EarlyMediaStarted,
            call_id: Some(call_id),
            detail: Some(format!("codec={codec}, remote_rtp={remote_rtp}")),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::CallEstablished {
            call_id,
            codec,
            remote_rtp,
        } => FfiEvent {
            kind: FfiEventKind::CallEstablished,
            call_id: Some(call_id),
            detail: Some(format!("codec={codec}, remote_rtp={remote_rtp}")),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::CallMediaUpdated {
            call_id,
            remote_rtp,
        } => FfiEvent {
            kind: FfiEventKind::CallMediaUpdated,
            call_id: Some(call_id),
            detail: Some(format!("remote_rtp={remote_rtp}")),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::CallHoldChanged {
            call_id,
            local_hold,
            remote_hold,
        } => FfiEvent {
            kind: FfiEventKind::CallHoldChanged,
            call_id: Some(call_id),
            detail: Some(format!(
                "local_hold={local_hold}, remote_hold={remote_hold}"
            )),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::CallTransferRequested { call_id, refer_to } => FfiEvent {
            kind: FfiEventKind::CallTransferRequested,
            call_id: Some(call_id),
            detail: Some(refer_to),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::TransferStatus {
            call_id,
            status_code,
            reason,
            terminated,
        } => FfiEvent {
            kind: FfiEventKind::TransferStatus,
            call_id: Some(call_id),
            detail: Some(format!("{reason} (terminated={terminated})")),
            status_code: Some(status_code),
            black_box_json: None,
        },
        EngineEvent::DtmfReceived { call_id, digit } => FfiEvent {
            kind: FfiEventKind::DtmfReceived,
            call_id: Some(call_id),
            detail: Some(digit.to_char().to_string()),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::CallTerminated {
            call_id,
            status_code,
            reason,
            black_box_json,
        } => FfiEvent {
            kind: FfiEventKind::CallTerminated,
            call_id: Some(call_id),
            detail: Some(reason),
            status_code,
            black_box_json: Some(black_box_json),
        },
        EngineEvent::Suspended => FfiEvent {
            kind: FfiEventKind::Suspended,
            call_id: None,
            detail: None,
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::Resumed { local_sip_addr } => FfiEvent {
            kind: FfiEventKind::Resumed,
            call_id: None,
            detail: Some(local_sip_addr.to_string()),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::NetworkUpdated { local_sip_addr } => FfiEvent {
            kind: FfiEventKind::NetworkUpdated,
            call_id: None,
            detail: Some(local_sip_addr.to_string()),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::TelemetryExported { call_id, json } => FfiEvent {
            kind: FfiEventKind::TelemetryExported,
            call_id,
            detail: None,
            status_code: None,
            black_box_json: Some(json),
        },
        EngineEvent::Warning(msg) => FfiEvent {
            kind: FfiEventKind::Warning,
            call_id: None,
            detail: Some(msg),
            status_code: None,
            black_box_json: None,
        },
        EngineEvent::Stopped => FfiEvent {
            kind: FfiEventKind::Stopped,
            call_id: None,
            detail: None,
            status_code: None,
            black_box_json: None,
        },
    }
}

fn write_opt_str(out: &mut String, key: &str, val: Option<&str>) {
    match val {
        Some(s) => {
            let _ = write!(out, ",{}:{}", json_quote(key), json_quote(s));
        }
        None => {
            let _ = write!(out, ",{}:null", json_quote(key));
        }
    }
}

fn json_quote(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
