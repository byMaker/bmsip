//! MODULE_CONTRACT: Sans-I/O SIP User Agent (`UserAgent`), Account Registration FSM (RFC 3261 §10), and Invite Dialog FSM (RFC 3261 §9, §12–15).
//! INVARIANTS: Zero I/O or system clock access; handles 401/407 Digest challenges on REGISTER/INVITE/BYE/UPDATE/REFER/INFO; enforces RFC 3261 §9.1 CANCEL ordering (defer CANCEL until 1xx arrives); supports Early Media (`183`/`180` SDP), Hold/Resume, UPDATE (RFC 3311), PRACK/100rel (RFC 3262), Session-Timers (RFC 4028), REFER/Replaces transfer (RFC 3515/3891), INFO DTMF (RFC 2976), Reason (RFC 3326), and P-Asserted-Identity/Privacy (RFC 3323/3325).
//! RFC_REFS: RFC 2976; RFC 3261 Sections 9, 10, 12, 13, 14, 15; RFC 3262; RFC 3264; RFC 3311; RFC 3323; RFC 3325; RFC 3326; RFC 3389; RFC 3515; RFC 3891; RFC 4028; RFC 6337.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::auth::hash::zeroize_bytes;
use crate::auth::{DigestAlgorithm, DigestChallenge, DigestCredentials};
use crate::error::SipError;
use crate::sdp::{
    negotiate_offer_answer_with_srtp, resolve_outbound_answer_srtp, Direction, NegotiatedSrtp,
    RtpCodec, SdesCryptoAttr, SdpMediaProfile, SdpSession, SrtpMode, SrtpSuite,
};
use crate::sip::{
    CSeq, CallerIdentity, Method, NameAddr, RAck, ReasonHeader, ReplacesHeader, SessionExpires,
    SessionRefresher, SipMessage, SipRequest, SipResponse, SipTransport, SipUri, Via,
};
use crate::transaction::{RfcTimers, TransactionEvent, TransactionId, TransactionManager};

const DEFAULT_USER_AGENT: &str = concat!("bmsip/", env!("CARGO_PKG_VERSION"));
const ALLOW_METHODS: &str = "INVITE, ACK, CANCEL, BYE, OPTIONS, UPDATE, PRACK, INFO, REFER, NOTIFY";
const SUPPORTED_EXTENSIONS: &str = "timer, 100rel, replaces";
const MAX_STALE_AUTH_RETRIES: u8 = 3;
const MAX_SESSION_TIMER_RETRIES: u8 = 3;
const MAX_GLARE_RETRIES: u8 = 3;

/// SIP account registration lifecycle state (RFC 3261 Section 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationState {
    Unregistered,
    Registering,
    Registered {
        expires_secs: u32,
        refresh_at: Instant,
        expires_at: Instant,
    },
    Unregistering,
    Failed {
        status_code: Option<u16>,
        reason: String,
    },
}

/// RFC 3261 Section 12 dialog identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

/// Direction of a SIP INVITE call session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallDirection {
    Outbound,
    Inbound,
}

/// Call dialog FSM states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Calling,
    Incoming,
    Ringing,
    Cancelling,
    Established,
    ReInviting,
    Terminating,
    Terminated,
}

/// User Agent configuration parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UaConfig {
    pub username: String,
    pub password: String,
    pub display_name: Option<String>,
    pub domain: String,
    pub registrar_uri: SipUri,
    pub local_host: String,
    pub local_sip_port: u16,
    /// Signaling transport protocol (`UDP`, `TCP`, or `TLS`; default `SipTransport::Udp`).
    pub transport: SipTransport,
    pub expires_secs: u32,
    pub supported_codecs: Vec<RtpCodec>,
    pub timers: RfcTimers,
    /// Optional per-instance entropy seed mixed into Call-IDs, tags, branches, and cnonces
    /// to prevent collisions across process restarts on fixed ports while keeping Sans-I/O determinism (`0` = deterministic default).
    pub instance_seed: u64,
    /// Dedicated 256-bit CSPRNG secret used exclusively for HMAC-SHA256 SDES master key derivation
    /// (never exposed in SIP `Call-ID`, `From` tags, or `Via` branches; populated by `SipEngine` from OS CSPRNG).
    pub crypto_seed: [u8; 32],
    /// Optional RFC 4028 Session-Timers interval in seconds (default `Some(1800)`, `None` disables Session-Timers).
    pub session_expires_secs: Option<u32>,
    /// Minimum acceptable RFC 4028 session interval (`Min-SE`, default `90` seconds).
    pub min_se_secs: u32,
    /// Optional asserted caller identity attached via `P-Asserted-Identity` (RFC 3325).
    pub asserted_identity: Option<NameAddr>,
    /// Optional privacy directive attached via `Privacy` (RFC 3323, e.g., `"id"`).
    pub privacy: Option<String>,
    /// SRTP media encryption policy (`Disabled`, `SdesOptional`, or `SdesRequired`).
    pub srtp_mode: SrtpMode,
    /// Explicit opt-in allowing RFC 4568 SDES `a=crypto:` keys over unencrypted UDP/TCP signaling (default `false`;
    /// strictly for isolated lab/test environments — RFC 4568 §8 requires TLS in production).
    pub allow_insecure_cleartext_sdes: bool,
}

impl UaConfig {
    /// Creates a `UaConfig` with standard defaults (300 s expiry, PCMU/PCMA/DTMF, RFC 3261 timers, 1800 s Session-Timers).
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        domain: impl Into<String>,
        registrar_uri: SipUri,
        local_host: impl Into<String>,
        local_sip_port: u16,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            display_name: None,
            domain: domain.into(),
            registrar_uri,
            local_host: local_host.into(),
            local_sip_port,
            transport: SipTransport::Udp,
            expires_secs: 300,
            supported_codecs: vec![
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::cn(),
                RtpCodec::telephone_event(101),
            ],
            timers: RfcTimers::default(),
            instance_seed: 0,
            crypto_seed: [0u8; 32],
            session_expires_secs: Some(1800),
            min_se_secs: 90,
            asserted_identity: None,
            privacy: None,
            srtp_mode: SrtpMode::Disabled,
            allow_insecure_cleartext_sdes: false,
        }
    }

    /// Sets the SIP signaling transport protocol (`Udp`, `Tcp`, or `Tls`).
    pub fn with_transport(mut self, transport: SipTransport) -> Self {
        self.transport = transport;
        self
    }

    /// Sets an explicit instance seed for unique Call-ID, tag, branch, and Digest `cnonce` generation across restarts.
    pub fn with_instance_seed(mut self, seed: u64) -> Self {
        self.instance_seed = seed;
        self
    }

    /// Injects a 256-bit OS CSPRNG secret exclusively for HMAC-SHA256 SDES master key derivation.
    pub fn with_crypto_seed(mut self, seed: [u8; 32]) -> Self {
        self.crypto_seed = seed;
        self
    }

    /// Configures RFC 4028 Session-Timers (`Session-Expires` and `Min-SE`).
    pub fn with_session_timers(
        mut self,
        session_expires_secs: Option<u32>,
        min_se_secs: u32,
    ) -> Self {
        self.session_expires_secs = session_expires_secs;
        self.min_se_secs = min_se_secs.max(1);
        self
    }

    /// Configures optional `P-Asserted-Identity` and `Privacy` headers on outbound calls.
    pub fn with_caller_identity(
        mut self,
        asserted_identity: Option<NameAddr>,
        privacy: Option<String>,
    ) -> Self {
        self.asserted_identity = asserted_identity;
        self.privacy = privacy;
        self
    }

    /// Configures the SRTP media encryption mode (`Disabled`, `SdesOptional`, or `SdesRequired`).
    pub fn with_srtp_mode(mut self, srtp_mode: SrtpMode) -> Self {
        self.srtp_mode = srtp_mode;
        self
    }

    /// Allows SDES `a=crypto:` key exchange over unencrypted UDP/TCP signaling (default `false`; lab/test use only).
    pub fn with_allow_insecure_cleartext_sdes(mut self, allow: bool) -> Self {
        self.allow_insecure_cleartext_sdes = allow;
        self
    }

    /// Evaluates the effective SRTP mode enforcing RFC 4568 §8 (SDES requires TLS unless explicitly overridden).
    pub fn effective_srtp_mode(&self) -> Result<SrtpMode, SipError> {
        let sdes_transport_allowed =
            self.transport == SipTransport::Tls || self.allow_insecure_cleartext_sdes;
        match self.srtp_mode {
            SrtpMode::Disabled => Ok(SrtpMode::Disabled),
            SrtpMode::SdesOptional => {
                if sdes_transport_allowed {
                    Ok(SrtpMode::SdesOptional)
                } else {
                    Ok(SrtpMode::Disabled)
                }
            }
            SrtpMode::SdesRequired => {
                if sdes_transport_allowed {
                    Ok(SrtpMode::SdesRequired)
                } else {
                    Err(SipError::TransactionError(
                        "SrtpMode::SdesRequired requires SipTransport::Tls unless allow_insecure_cleartext_sdes is explicitly enabled".to_string(),
                    ))
                }
            }
        }
    }

    fn aor_uri(&self) -> SipUri {
        SipUri::new(self.domain.clone()).with_user(self.username.clone())
    }

    fn contact_uri(&self) -> SipUri {
        SipUri::new(self.local_host.clone())
            .with_user(self.username.clone())
            .with_port(self.local_sip_port)
            .with_param("transport", Some(self.transport.uri_param().to_string()))
    }

    fn local_from_name_addr(&self) -> NameAddr {
        let mut addr = NameAddr::new(self.aor_uri());
        if let Some(dn) = &self.display_name {
            addr = addr.with_display_name(dn.clone());
        }
        addr
    }
}

/// High-level dialog and registration events emitted by [`UserAgent`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum UaEvent {
    RegistrationChanged(RegistrationState),
    IncomingCall {
        call_id: String,
        from: NameAddr,
        to: NameAddr,
        remote_sdp: Option<SdpSession>,
        caller_identity: Option<CallerIdentity>,
        replaces_call_id: Option<String>,
    },
    CallRinging {
        call_id: String,
        status_code: u16,
        early_sdp: Option<SdpSession>,
    },
    CallEstablished {
        call_id: String,
        local_sdp: SdpSession,
        remote_sdp: SdpSession,
        negotiated_codecs: Vec<RtpCodec>,
    },
    CallMediaUpdated {
        call_id: String,
        local_sdp: SdpSession,
        remote_sdp: SdpSession,
        negotiated_codecs: Vec<RtpCodec>,
    },
    CallHoldChanged {
        call_id: String,
        local_hold: bool,
        remote_hold: bool,
    },
    CallTransferRequested {
        call_id: String,
        refer_to: SipUri,
        referred_by: Option<NameAddr>,
        replaces: Option<ReplacesHeader>,
    },
    TransferNotify {
        call_id: String,
        status_code: u16,
        reason: String,
        terminated: bool,
    },
    DtmfReceived {
        call_id: String,
        digit: char,
        duration_ms: u32,
    },
    CallTerminated {
        call_id: String,
        status_code: Option<u16>,
        reason: String,
        reason_header: Option<ReasonHeader>,
    },
    ProtocolWarning(String),
}

#[derive(Debug, Clone, Default)]
struct AuthRetryState {
    www_attempts: u8,
    proxy_attempts: u8,
    www_header: Option<String>,
    proxy_header: Option<String>,
}

impl AuthRetryState {
    fn reset(&mut self) {
        self.www_attempts = 0;
        self.proxy_attempts = 0;
        self.www_header = None;
        self.proxy_header = None;
    }

    fn reset_attempts(&mut self) {
        self.www_attempts = 0;
        self.proxy_attempts = 0;
    }

    fn attempts_for(&self, status_code: u16) -> u8 {
        if status_code == 407 {
            self.proxy_attempts
        } else {
            self.www_attempts
        }
    }

    fn record_retry(&mut self, status_code: u16, header_value: String) {
        if status_code == 407 {
            self.proxy_attempts = self.proxy_attempts.saturating_add(1);
            self.proxy_header = Some(header_value);
        } else {
            self.www_attempts = self.www_attempts.saturating_add(1);
            self.www_header = Some(header_value);
        }
    }

    fn apply(&self, headers: &mut crate::sip::Headers) {
        if let Some(val) = &self.www_header {
            headers.set("Authorization", val.clone());
        }
        if let Some(val) = &self.proxy_header {
            headers.set("Proxy-Authorization", val.clone());
        }
    }
}

#[derive(Debug, Clone)]
enum AuthAction {
    Reset,
    Keep,
    Retry(u16, String),
}

#[derive(Debug, Clone)]
struct PendingReInviteRollback {
    prev_local_sdp: Option<SdpSession>,
    prev_sdp_version: u64,
    prev_local_hold: bool,
    prev_local_rtp_port: u16,
}

#[derive(Debug, Clone)]
struct RegisterSession {
    call_id: String,
    local_tag: String,
    cseq: u32,
    active_tx: Option<TransactionId>,
    auth: AuthRetryState,
    interval_too_brief_retried: bool,
    pending_expires: u32,
}

#[derive(Debug, Clone)]
struct Pending2xxAck {
    response: SipResponse,
    next_send_at: Instant,
    interval: Duration,
    deadline: Instant,
}

#[derive(Debug, Clone)]
struct PendingReliable1xx {
    response: SipResponse,
    rseq: u32,
    invite_cseq: u32,
    next_send_at: Instant,
    interval: Duration,
    deadline: Instant,
}

#[derive(Debug, Clone)]
struct PendingGlareRetry {
    due_at: Instant,
    ip: String,
    rtp_port: u16,
    desired_local_hold: bool,
    attempts: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAckSdpKind {
    InitialInvite,
    ReInvite,
}

#[derive(Debug, Clone)]
enum CallTxKind {
    Invite,
    ReInvite,
    Cancel,
    Bye,
    Update,
    Prack,
    Refer,
    Notify,
    Info,
}

#[derive(Debug, Clone)]
struct CallSession {
    call_id: String,
    direction: CallDirection,
    state: CallState,
    local_tag: String,
    remote_tag: Option<String>,
    local_uri: SipUri,
    remote_uri: SipUri,
    remote_target: SipUri,
    route_set: Vec<SipUri>,
    local_cseq: u32,
    remote_cseq: Option<u32>,
    local_rtp_port: u16,
    sdp_session_id: String,
    sdp_version: u64,
    local_sdp: Option<SdpSession>,
    remote_sdp: Option<SdpSession>,
    negotiated_codecs: Vec<RtpCodec>,
    local_crypto: Vec<SdesCryptoAttr>,
    negotiated_srtp: Option<NegotiatedSrtp>,
    local_hold: bool,
    remote_hold: bool,
    local_rseq: u32,
    pending_reliable_1xx: Option<PendingReliable1xx>,
    last_remote_rseq: Option<u32>,
    session_expires_secs: Option<u32>,
    min_se_secs: u32,
    session_refresher_is_local: bool,
    session_refresh_at: Option<Instant>,
    session_expire_at: Option<Instant>,
    session_timer_retries: u8,
    cancel_deadline: Option<Instant>,
    pending_reinvite_rollback: Option<PendingReInviteRollback>,
    pending_glare_retry: Option<PendingGlareRetry>,
    glare_attempts: u8,
    replaces_header: Option<ReplacesHeader>,
    active_invite_tx: Option<TransactionId>,
    active_invite_req: Option<SipRequest>,
    active_update_tx: Option<TransactionId>,
    active_update_req: Option<SipRequest>,
    active_refer_uri: Option<SipUri>,
    active_info_payload: Option<(char, u32)>,
    active_bye_tx: Option<TransactionId>,
    inbound_invite_tx: Option<TransactionId>,
    inbound_invite_req: Option<SipRequest>,
    inbound_invite_branch: Option<String>,
    pending_cancel: bool,
    pending_cancel_reason: Option<ReasonHeader>,
    received_provisional: bool,
    invite_auth: AuthRetryState,
    bye_auth: AuthRetryState,
    update_auth: AuthRetryState,
    refer_auth: AuthRetryState,
    info_auth: AuthRetryState,
    last_ack_for_2xx: Option<SipRequest>,
    awaiting_ack: Option<Pending2xxAck>,
    awaiting_ack_sdp: Option<PendingAckSdpKind>,
}

impl CallSession {
    fn dialog_id(&self) -> Option<DialogId> {
        self.remote_tag.as_ref().map(|rt| DialogId {
            call_id: self.call_id.clone(),
            local_tag: self.local_tag.clone(),
            remote_tag: rt.clone(),
        })
    }

    fn remote_name_addr(&self) -> NameAddr {
        let mut addr = NameAddr::new(self.remote_uri.clone());
        if let Some(tag) = &self.remote_tag {
            addr = addr.with_tag(tag.clone());
        }
        addr
    }

    fn local_name_addr(&self, display_name: Option<&str>) -> NameAddr {
        let mut addr = NameAddr::new(self.local_uri.clone()).with_tag(self.local_tag.clone());
        if let Some(dn) = display_name {
            addr = addr.with_display_name(dn);
        }
        addr
    }
}

/// Sans-I/O SIP User Agent combining RFC 3261 transactions, account registration, and call dialogs.
#[derive(Debug)]
pub struct UserAgent {
    config: UaConfig,
    transactions: TransactionManager,
    reg_state: RegistrationState,
    reg_session: RegisterSession,
    calls: HashMap<String, CallSession>,
    tx_to_call: HashMap<TransactionId, (String, CallTxKind)>,
    pending_events: VecDeque<UaEvent>,
    id_counter: u64,
}

impl Drop for UserAgent {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.config.crypto_seed);
    }
}

impl UserAgent {
    /// Creates a new [`UserAgent`] initialized in [`RegistrationState::Unregistered`].
    pub fn new(config: UaConfig) -> Self {
        let eff = effective_instance_seed(&config);
        let seed_part = format!("-{:08x}", (eff & 0xffff_ffff) as u32);
        let reg_call_id = format!(
            "bm-reg-{}{seed_part}@{}",
            config.local_sip_port, config.local_host
        );
        let reg_tag = format!("bm-rtag-{}{seed_part}", config.local_sip_port);
        let timers = config.timers;
        Self {
            config,
            transactions: TransactionManager::new(timers),
            reg_state: RegistrationState::Unregistered,
            reg_session: RegisterSession {
                call_id: reg_call_id,
                local_tag: reg_tag,
                cseq: 0,
                active_tx: None,
                auth: AuthRetryState::default(),
                interval_too_brief_retried: false,
                pending_expires: 0,
            },
            calls: HashMap::new(),
            tx_to_call: HashMap::new(),
            pending_events: VecDeque::new(),
            id_counter: 1,
        }
    }

    /// Returns the current User Agent configuration.
    pub fn config(&self) -> &UaConfig {
        &self.config
    }

    /// Returns the configured SIP signaling transport (`Udp`, `Tcp`, or `Tls`).
    pub fn transport(&self) -> SipTransport {
        self.config.transport
    }

    /// Returns the current SIP registration state.
    pub fn registration_state(&self) -> &RegistrationState {
        &self.reg_state
    }

    /// Returns the currently non-terminated call IDs tracked by this User Agent.
    pub fn active_call_ids(&self) -> Vec<String> {
        self.calls
            .iter()
            .filter(|(_, call)| {
                !matches!(call.state, CallState::Terminating | CallState::Terminated)
            })
            .map(|(cid, _)| cid.clone())
            .collect()
    }

    /// Returns the FSM state of a tracked call, if present.
    pub fn call_state(&self, call_id: &str) -> Option<CallState> {
        self.calls.get(call_id).map(|c| c.state)
    }

    /// Returns the established RFC 3261 dialog identifier for `call_id`, if a remote tag is known.
    pub fn dialog_id(&self, call_id: &str) -> Option<DialogId> {
        self.calls.get(call_id).and_then(CallSession::dialog_id)
    }

    /// Returns `(local_hold, remote_hold)` for an active call, if present.
    pub fn hold_state(&self, call_id: &str) -> Option<(bool, bool)> {
        self.calls
            .get(call_id)
            .map(|c| (c.local_hold, c.remote_hold))
    }

    /// Returns the negotiated SDP audio codecs for `call_id`, if any have been intersected.
    pub fn negotiated_codecs(&self, call_id: &str) -> Option<&[RtpCodec]> {
        self.calls
            .get(call_id)
            .map(|c| c.negotiated_codecs.as_slice())
    }

    /// Returns the bound local RTP port associated with `call_id`, if assigned.
    pub fn local_rtp_port(&self, call_id: &str) -> Option<u16> {
        self.calls.get(call_id).map(|c| c.local_rtp_port)
    }

    /// Returns the most recently received remote SDP offer/answer for `call_id`, if present.
    pub fn remote_sdp(&self, call_id: &str) -> Option<&SdpSession> {
        self.calls.get(call_id).and_then(|c| c.remote_sdp.as_ref())
    }

    /// Returns the negotiated SRTP security parameters (RFC 4568 SDES keys) for `call_id`, if active.
    pub fn negotiated_srtp(&self, call_id: &str) -> Option<&NegotiatedSrtp> {
        self.calls
            .get(call_id)
            .and_then(|c| c.negotiated_srtp.as_ref())
    }

    fn generate_sdes_candidates(&mut self, call_id: &str) -> Vec<SdesCryptoAttr> {
        let ctx1 = format!(
            "bmsip-sdes-v2|AES_CM_128_HMAC_SHA1_80|{call_id}|{}|{}:{}",
            self.id_counter, self.config.local_host, self.config.local_sip_port
        );
        self.id_counter = self.id_counter.wrapping_add(1);
        let ctx2 = format!(
            "bmsip-sdes-v2|AES_CM_128_HMAC_SHA1_32|{call_id}|{}|{}:{}",
            self.id_counter, self.config.local_host, self.config.local_sip_port
        );
        self.id_counter = self.id_counter.wrapping_add(1);
        vec![
            SdesCryptoAttr::derive_from_secret(
                1,
                SrtpSuite::AesCm128HmacSha1_80,
                &self.config.crypto_seed,
                ctx1.as_bytes(),
            ),
            SdesCryptoAttr::derive_from_secret(
                2,
                SrtpSuite::AesCm128HmacSha1_32,
                &self.config.crypto_seed,
                ctx2.as_bytes(),
            ),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    fn build_local_offer_sdp(
        &self,
        srtp_mode: SrtpMode,
        sdp_sid: &str,
        sdp_version: u64,
        ip: &str,
        rtp_port: u16,
        direction: Direction,
        codecs: Vec<RtpCodec>,
        local_crypto: &[SdesCryptoAttr],
    ) -> SdpSession {
        let (profile, crypto) = match srtp_mode {
            SrtpMode::Disabled => (SdpMediaProfile::RtpAvp, Vec::new()),
            SrtpMode::SdesOptional => (SdpMediaProfile::RtpAvp, local_crypto.to_vec()),
            SrtpMode::SdesRequired => (SdpMediaProfile::RtpSavp, local_crypto.to_vec()),
        };
        SdpSession {
            origin_username: self.config.username.clone(),
            session_id: sdp_sid.to_string(),
            session_version: sdp_version.to_string(),
            connection_ip: ip.to_string(),
            audio_port: rtp_port,
            profile,
            direction,
            codecs,
            ptime: Some(20),
            crypto,
            rtcp_port: None,
            rtcp_ip: None,
            rtcp_mux: false,
        }
    }

    /// Drains queued [`UaEvent`]s emitted by synchronous command methods (`answer`, `hangup`, etc.).
    pub fn drain_events(&mut self) -> Vec<UaEvent> {
        self.pending_events.drain(..).collect()
    }

    /// Initiates or refreshes SIP account `REGISTER` with `config.expires_secs`.
    pub fn register(&mut self, now: Instant) -> Result<(), SipError> {
        self.reg_session.interval_too_brief_retried = false;
        self.start_register_with_expires(self.config.expires_secs, AuthAction::Reset, now)?;
        self.set_registration_state(RegistrationState::Registering);
        Ok(())
    }

    /// Initiates SIP de-registration (`REGISTER` with `Expires: 0`).
    pub fn unregister(&mut self, now: Instant) -> Result<(), SipError> {
        self.reg_session.interval_too_brief_retried = false;
        self.start_register_with_expires(0, AuthAction::Reset, now)?;
        self.set_registration_state(RegistrationState::Unregistering);
        Ok(())
    }

    /// Starts an outbound `INVITE` call with an SDP audio offer and returns its `Call-ID`.
    pub fn dial(
        &mut self,
        mut target_uri: SipUri,
        local_rtp_port: u16,
        now: Instant,
    ) -> Result<String, SipError> {
        // RFC 3515 / RFC 3891: promote any `?Replaces=` URI header parameter on Refer-To into a SIP Replaces header.
        let mut extracted_replaces = None;
        if let Some(pos) = target_uri
            .headers
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case("replaces"))
        {
            let (_, val) = target_uri.headers.remove(pos);
            if !val.is_empty() {
                extracted_replaces = Some(ReplacesHeader::parse(&val)?);
            }
        }
        self.dial_internal(target_uri, extracted_replaces, local_rtp_port, now)
    }

    /// Starts an outbound `INVITE` carrying an explicit RFC 3891 `Replaces` header (attended transfer).
    pub fn dial_with_replaces(
        &mut self,
        target_uri: SipUri,
        replaces: ReplacesHeader,
        local_rtp_port: u16,
        now: Instant,
    ) -> Result<String, SipError> {
        self.dial_internal(target_uri, Some(replaces), local_rtp_port, now)
    }

    fn dial_internal(
        &mut self,
        target_uri: SipUri,
        replaces: Option<ReplacesHeader>,
        local_rtp_port: u16,
        now: Instant,
    ) -> Result<String, SipError> {
        let srtp_mode = self.config.effective_srtp_mode()?;
        let call_id = self.next_call_id();
        let local_tag = self.next_tag();
        let sdp_sid = self.next_numeric_id();
        let sdp_version = 1;
        let local_crypto = if matches!(srtp_mode, SrtpMode::SdesOptional | SrtpMode::SdesRequired) {
            self.generate_sdes_candidates(&call_id)
        } else {
            Vec::new()
        };

        let local_sdp = self.build_local_offer_sdp(
            srtp_mode,
            &sdp_sid,
            sdp_version,
            &self.config.local_host,
            local_rtp_port,
            Direction::SendRecv,
            self.config.supported_codecs.clone(),
            &local_crypto,
        );

        let init_se = self
            .config
            .session_expires_secs
            .map(|se| se.max(self.config.min_se_secs));

        let mut call = CallSession {
            call_id: call_id.clone(),
            direction: CallDirection::Outbound,
            state: CallState::Calling,
            local_tag,
            remote_tag: None,
            local_uri: self.config.aor_uri(),
            remote_uri: target_uri.clone(),
            remote_target: target_uri,
            route_set: Vec::new(),
            local_cseq: 1,
            remote_cseq: None,
            local_rtp_port,
            sdp_session_id: sdp_sid,
            sdp_version,
            local_sdp: Some(local_sdp.clone()),
            remote_sdp: None,
            negotiated_codecs: Vec::new(),
            local_crypto,
            negotiated_srtp: None,
            local_hold: false,
            remote_hold: false,
            local_rseq: 0,
            pending_reliable_1xx: None,
            last_remote_rseq: None,
            session_expires_secs: init_se,
            min_se_secs: self.config.min_se_secs.max(1),
            session_refresher_is_local: false,
            session_refresh_at: None,
            session_expire_at: None,
            session_timer_retries: 0,
            cancel_deadline: None,
            pending_reinvite_rollback: None,
            pending_glare_retry: None,
            glare_attempts: 0,
            replaces_header: replaces,
            active_invite_tx: None,
            active_invite_req: None,
            active_update_tx: None,
            active_update_req: None,
            active_refer_uri: None,
            active_info_payload: None,
            active_bye_tx: None,
            inbound_invite_tx: None,
            inbound_invite_req: None,
            inbound_invite_branch: None,
            pending_cancel: false,
            pending_cancel_reason: None,
            received_provisional: false,
            invite_auth: AuthRetryState::default(),
            bye_auth: AuthRetryState::default(),
            update_auth: AuthRetryState::default(),
            refer_auth: AuthRetryState::default(),
            info_auth: AuthRetryState::default(),
            last_ack_for_2xx: None,
            awaiting_ack: None,
            awaiting_ack_sdp: None,
        };

        let branch = self.next_branch();
        let req = Self::build_invite_request(&self.config, &call, &branch, &local_sdp);
        let tx_id = self
            .transactions
            .start_client_transaction(req.clone(), now)?;
        call.active_invite_tx = Some(tx_id.clone());
        call.active_invite_req = Some(req);

        self.calls.insert(call_id.clone(), call);
        self.tx_to_call
            .insert(tx_id, (call_id.clone(), CallTxKind::Invite));

        Ok(call_id)
    }

    /// Sends `180 Ringing` on an inbound call currently in [`CallState::Incoming`].
    pub fn ring(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
        let (tx_id, mut resp) = {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.direction != CallDirection::Inbound || call.state != CallState::Incoming {
                return Err(SipError::TransactionError(format!(
                    "cannot ring call {call_id} in state {:?}",
                    call.state
                )));
            }
            let tx_id = call.inbound_invite_tx.clone().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE tx".to_string())
            })?;
            let req = call.inbound_invite_req.as_ref().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE req".to_string())
            })?;
            let resp = req.create_response(180, "Ringing")?;
            (tx_id, resp)
        };

        let contact = NameAddr::new(self.config.contact_uri()).to_string();
        let to_hdr = {
            let mut to = resp.to()?;
            if let Some(call) = self.calls.get(call_id) {
                to.tag = Some(call.local_tag.clone());
            }
            to.to_string()
        };
        resp.headers.set("To", to_hdr);
        resp.headers.set("Contact", contact);
        resp.headers.set("Allow", ALLOW_METHODS);

        let tx_events = self.transactions.send_server_response(&tx_id, resp, now)?;
        self.process_transaction_events(tx_events, now);

        if let Some(call) = self.calls.get_mut(call_id) {
            call.state = CallState::Ringing;
        }
        Ok(())
    }

    /// Sends a reliable provisional response (`180`/`183` with `Require: 100rel` and `RSeq`) per RFC 3262.
    pub fn ring_reliable(
        &mut self,
        call_id: &str,
        status_code: u16,
        reason: &str,
        early_sdp: Option<SdpSession>,
        now: Instant,
    ) -> Result<u32, SipError> {
        if !(101..200).contains(&status_code) {
            return Err(SipError::TransactionError(format!(
                "reliable provisional status must be 101..=199, got {status_code}"
            )));
        }

        let (tx_id, mut resp, rseq, invite_cseq) = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.direction != CallDirection::Inbound
                || !matches!(call.state, CallState::Incoming | CallState::Ringing)
            {
                return Err(SipError::TransactionError(format!(
                    "cannot send reliable {status_code} on call {call_id} in state {:?}",
                    call.state
                )));
            }
            if call.pending_reliable_1xx.is_some() {
                return Err(SipError::TransactionError(format!(
                    "previous reliable 1xx response on call {call_id} is still awaiting PRACK"
                )));
            }
            let tx_id = call.inbound_invite_tx.clone().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE tx".to_string())
            })?;
            let req = call.inbound_invite_req.as_ref().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE req".to_string())
            })?;
            let invite_cseq = req.cseq()?.seq;
            call.local_rseq = call.local_rseq.saturating_add(1).max(1);
            let rseq = call.local_rseq;
            let mut resp = req.create_response(status_code, reason)?;
            if let Some(sdp) = early_sdp {
                call.local_sdp = Some(sdp.clone());
                resp = resp.with_body("application/sdp", sdp.to_string().into_bytes());
            }
            (tx_id, resp, rseq, invite_cseq)
        };

        let contact = NameAddr::new(self.config.contact_uri()).to_string();
        let to_hdr = {
            let mut to = resp.to()?;
            if let Some(call) = self.calls.get(call_id) {
                to.tag = Some(call.local_tag.clone());
            }
            to.to_string()
        };
        resp.headers.set("To", to_hdr);
        resp.headers.set("Contact", contact);
        resp.headers.set("Require", "100rel");
        resp.headers.set("RSeq", rseq.to_string());
        resp.headers.set("Allow", ALLOW_METHODS);
        resp.headers.set("Supported", SUPPORTED_EXTENSIONS);

        let tx_events = self
            .transactions
            .send_server_response(&tx_id, resp.clone(), now)?;
        self.process_transaction_events(tx_events, now);

        let t1 = self
            .config
            .timers
            .t1
            .clamp(Duration::from_millis(1), Duration::from_secs(60));
        if let Some(call) = self.calls.get_mut(call_id) {
            call.pending_reliable_1xx = Some(PendingReliable1xx {
                response: resp,
                rseq,
                invite_cseq,
                next_send_at: now + t1,
                interval: t1,
                deadline: now + t1.saturating_mul(64),
            });
            if call.state == CallState::Incoming {
                call.state = CallState::Ringing;
            }
        }
        Ok(rseq)
    }

    /// Sends an early-media `183 Session Progress` (or `180 Ringing`) carrying a negotiated SDP answer per RFC 3264 / RFC 3960.
    pub fn ring_early_media(
        &mut self,
        call_id: &str,
        status_code: u16,
        local_rtp_port: u16,
        reliable: bool,
        now: Instant,
    ) -> Result<SdpSession, SipError> {
        if !(180..200).contains(&status_code) {
            return Err(SipError::TransactionError(format!(
                "early-media provisional status must be 180..=199, got {status_code}"
            )));
        }
        if local_rtp_port == 0 {
            return Err(SipError::TransactionError(
                "early-media local RTP port must be non-zero".to_string(),
            ));
        }

        let (tx_id, req, remote_sdp_opt, local_tag, sdp_sid, local_hold, peer_requires_100rel) = {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.direction != CallDirection::Inbound
                || !matches!(call.state, CallState::Incoming | CallState::Ringing)
            {
                return Err(SipError::TransactionError(format!(
                    "cannot send early media on call {call_id} in state {:?}",
                    call.state
                )));
            }
            let tx_id = call.inbound_invite_tx.clone().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE tx".to_string())
            })?;
            let req = call.inbound_invite_req.clone().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE req".to_string())
            })?;
            let req_100rel = req
                .headers
                .get("Require")
                .is_some_and(|v| v.to_ascii_lowercase().contains("100rel"));
            (
                tx_id,
                req,
                call.remote_sdp.clone(),
                call.local_tag.clone(),
                call.sdp_session_id.clone(),
                call.local_hold,
                req_100rel,
            )
        };

        let srtp_mode = self.config.effective_srtp_mode()?;
        let remote_sdp = remote_sdp_opt.ok_or_else(|| {
            SipError::InvalidSdp("inbound INVITE lacked SDP offer for early media".to_string())
        })?;
        let local_candidates = match self.calls.get(call_id) {
            Some(c) if !c.local_crypto.is_empty() => c.local_crypto.clone(),
            _ => self.generate_sdes_candidates(call_id),
        };
        let (mut answer_sdp, negotiated, negotiated_srtp) = negotiate_offer_answer_with_srtp(
            &remote_sdp,
            &self.config.supported_codecs,
            &self.config.local_host,
            local_rtp_port,
            srtp_mode,
            &local_candidates,
        )?;
        answer_sdp.origin_username = self.config.username.clone();
        answer_sdp.session_id = sdp_sid;
        answer_sdp.session_version = "1".to_string();
        answer_sdp.direction = constrain_answer_direction(remote_sdp.direction, local_hold);
        let remote_hold = is_remote_hold(remote_sdp.direction);

        if let Some(call) = self.calls.get_mut(call_id) {
            call.local_rtp_port = local_rtp_port;
            call.local_sdp = Some(answer_sdp.clone());
            if !answer_sdp.crypto.is_empty() {
                call.local_crypto = answer_sdp.crypto.clone();
            }
            call.negotiated_srtp = negotiated_srtp;
            call.remote_hold = remote_hold;
            call.negotiated_codecs = negotiated;
            call.state = CallState::Ringing;
        }

        let reason = match status_code {
            180 => "Ringing",
            183 => "Session Progress",
            _ => "Provisional",
        };
        if reliable || peer_requires_100rel {
            let _ =
                self.ring_reliable(call_id, status_code, reason, Some(answer_sdp.clone()), now)?;
            return Ok(answer_sdp);
        }

        let mut resp = req
            .create_response(status_code, reason)?
            .with_body("application/sdp", answer_sdp.to_string().into_bytes());
        let mut to = resp.to()?;
        to.tag = Some(local_tag);
        resp.headers.set("To", to.to_string());
        resp.headers.set(
            "Contact",
            NameAddr::new(self.config.contact_uri()).to_string(),
        );
        resp.headers.set("Allow", ALLOW_METHODS);
        resp.headers.set("Supported", SUPPORTED_EXTENSIONS);

        let tx_events = self.transactions.send_server_response(&tx_id, resp, now)?;
        self.process_transaction_events(tx_events, now);
        Ok(answer_sdp)
    }

    /// Answers an inbound call (`200 OK` with negotiated SDP) and starts 2xx ACK retransmission timer.
    pub fn answer(
        &mut self,
        call_id: &str,
        local_rtp_port: u16,
        now: Instant,
    ) -> Result<(), SipError> {
        let (tx_id, req, remote_sdp_opt, local_tag, sdp_sid, local_hold, existing_port) = {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.direction != CallDirection::Inbound
                || !matches!(call.state, CallState::Incoming | CallState::Ringing)
            {
                return Err(SipError::TransactionError(format!(
                    "cannot answer call {call_id} in state {:?}",
                    call.state
                )));
            }
            let tx_id = call.inbound_invite_tx.clone().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE tx".to_string())
            })?;
            let req = call.inbound_invite_req.clone().ok_or_else(|| {
                SipError::TransactionError("missing inbound INVITE req".to_string())
            })?;
            (
                tx_id,
                req,
                call.remote_sdp.clone(),
                call.local_tag.clone(),
                call.sdp_session_id.clone(),
                call.local_hold,
                call.local_rtp_port,
            )
        };
        let effective_rtp_port = if local_rtp_port == 0 && existing_port != 0 {
            existing_port
        } else {
            local_rtp_port
        };

        let Some(remote_sdp) = remote_sdp_opt else {
            if !req.body.is_empty() || effective_rtp_port == 0 {
                self.reject_inbound_invite_488(call_id, &tx_id, &req, &local_tag, now);
                return Err(SipError::InvalidSdp(
                    "inbound INVITE lacked usable SDP offer".to_string(),
                ));
            }
            // RFC 3261 §13.2.1: delayed SDP offer — return local offer in 200 OK and await answer in ACK.
            let srtp_mode = match self.config.effective_srtp_mode() {
                Ok(mode) => mode,
                Err(err) => {
                    self.reject_inbound_invite_488(call_id, &tx_id, &req, &local_tag, now);
                    return Err(err);
                }
            };
            let local_candidates = match self.calls.get(call_id) {
                Some(c) if !c.local_crypto.is_empty() => c.local_crypto.clone(),
                _ if matches!(srtp_mode, SrtpMode::SdesOptional | SrtpMode::SdesRequired) => {
                    self.generate_sdes_candidates(call_id)
                }
                _ => Vec::new(),
            };
            let dir = if local_hold {
                Direction::SendOnly
            } else {
                Direction::SendRecv
            };
            let offer_sdp = self.build_local_offer_sdp(
                srtp_mode,
                &sdp_sid,
                1,
                &self.config.local_host,
                effective_rtp_port,
                dir,
                self.config.supported_codecs.clone(),
                &local_candidates,
            );

            let mut resp = req
                .create_response(200, "OK")?
                .with_body("application/sdp", offer_sdp.to_string().into_bytes());
            let mut to = resp.to()?;
            to.tag = Some(local_tag);
            resp.headers.set("To", to.to_string());
            resp.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            resp.headers.set("Allow", ALLOW_METHODS);
            resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
            self.apply_uas_session_timer_to_response(call_id, &req, &mut resp, now);

            let tx_events = self
                .transactions
                .send_server_response(&tx_id, resp.clone(), now)?;
            self.process_transaction_events(tx_events, now);

            let t1 = self
                .config
                .timers
                .t1
                .clamp(Duration::from_millis(1), Duration::from_secs(60));
            if let Some(call) = self.calls.get_mut(call_id) {
                call.state = CallState::Established;
                call.local_rtp_port = effective_rtp_port;
                call.local_sdp = Some(offer_sdp.clone());
                if !offer_sdp.crypto.is_empty() {
                    call.local_crypto = offer_sdp.crypto;
                }
                call.inbound_invite_tx = None;
                call.inbound_invite_req = None;
                call.pending_reliable_1xx = None;
                call.awaiting_ack_sdp = Some(PendingAckSdpKind::InitialInvite);
                call.awaiting_ack = Some(Pending2xxAck {
                    response: resp,
                    next_send_at: now + t1,
                    interval: t1,
                    deadline: now + t1.saturating_mul(64),
                });
            }
            return Ok(());
        };

        let srtp_mode = match self.config.effective_srtp_mode() {
            Ok(mode) => mode,
            Err(err) => {
                self.reject_inbound_invite_488(call_id, &tx_id, &req, &local_tag, now);
                return Err(err);
            }
        };
        let local_candidates = match self.calls.get(call_id) {
            Some(c) if !c.local_crypto.is_empty() => c.local_crypto.clone(),
            _ => self.generate_sdes_candidates(call_id),
        };
        let (mut answer_sdp, negotiated, negotiated_srtp) = match negotiate_offer_answer_with_srtp(
            &remote_sdp,
            &self.config.supported_codecs,
            &self.config.local_host,
            effective_rtp_port,
            srtp_mode,
            &local_candidates,
        ) {
            Ok(triple) => triple,
            Err(err) => {
                self.reject_inbound_invite_488(call_id, &tx_id, &req, &local_tag, now);
                return Err(err);
            }
        };
        answer_sdp.origin_username = self.config.username.clone();
        answer_sdp.session_id = sdp_sid;
        answer_sdp.session_version = "1".to_string();
        answer_sdp.direction = constrain_answer_direction(remote_sdp.direction, local_hold);
        let remote_hold = is_remote_hold(remote_sdp.direction);

        // Note: `SipRequest::create_response` already copies all `Record-Route` headers per RFC 3261 §12.1.1.
        let mut resp = req
            .create_response(200, "OK")?
            .with_body("application/sdp", answer_sdp.to_string().into_bytes());

        let mut to = resp.to()?;
        to.tag = Some(local_tag);
        resp.headers.set("To", to.to_string());
        resp.headers.set(
            "Contact",
            NameAddr::new(self.config.contact_uri()).to_string(),
        );
        resp.headers.set("Allow", ALLOW_METHODS);
        resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
        self.apply_uas_session_timer_to_response(call_id, &req, &mut resp, now);

        let tx_events = self
            .transactions
            .send_server_response(&tx_id, resp.clone(), now)?;
        self.process_transaction_events(tx_events, now);

        let t1 = self.config.timers.t1.max(Duration::from_millis(1));
        if let Some(call) = self.calls.get_mut(call_id) {
            call.state = CallState::Established;
            call.local_rtp_port = effective_rtp_port;
            call.local_sdp = Some(answer_sdp.clone());
            call.remote_sdp = Some(remote_sdp.clone());
            if !answer_sdp.crypto.is_empty() {
                call.local_crypto = answer_sdp.crypto.clone();
            }
            call.negotiated_srtp = negotiated_srtp;
            call.remote_hold = remote_hold;
            call.negotiated_codecs = negotiated.clone();
            call.inbound_invite_tx = None;
            call.inbound_invite_req = None;
            call.pending_reliable_1xx = None;
            call.awaiting_ack_sdp = None;
            call.awaiting_ack = Some(Pending2xxAck {
                response: resp,
                next_send_at: now + t1,
                interval: t1,
                deadline: now + t1.min(Duration::from_secs(60)).saturating_mul(64),
            });
        }

        self.pending_events.push_back(UaEvent::CallEstablished {
            call_id: call_id.to_string(),
            local_sdp: answer_sdp,
            remote_sdp,
            negotiated_codecs: negotiated,
        });
        if remote_hold {
            self.pending_events.push_back(UaEvent::CallHoldChanged {
                call_id: call_id.to_string(),
                local_hold,
                remote_hold,
            });
        }
        Ok(())
    }

    /// Rejects, cancels, or terminates an active call (`486`, `CANCEL`, or `BYE`).
    pub fn hangup(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
        self.hangup_with_reason(call_id, None, now)
    }

    /// Rejects, cancels, or terminates an active call while attaching an optional RFC 3326 `Reason` header.
    pub fn hangup_with_reason(
        &mut self,
        call_id: &str,
        reason: Option<ReasonHeader>,
        now: Instant,
    ) -> Result<(), SipError> {
        let (direction, state, inbound_tx, inbound_req, local_tag) = {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            (
                call.direction,
                call.state,
                call.inbound_invite_tx.clone(),
                call.inbound_invite_req.clone(),
                call.local_tag.clone(),
            )
        };

        match (direction, state) {
            (CallDirection::Outbound, CallState::Calling) => {
                // RFC 3261 §9.1: CANCEL MUST NOT be sent until ANY 1xx provisional arrives
                // (including `100 Trying`, which keeps CallState in `Calling`).
                let already_got_1xx = self
                    .calls
                    .get(call_id)
                    .is_some_and(|c| c.received_provisional);
                if already_got_1xx {
                    self.send_cancel_for_call_with_reason(call_id, reason, now)?;
                } else if let Some(call) = self.calls.get_mut(call_id) {
                    call.pending_cancel = true;
                    call.pending_cancel_reason = reason;
                    call.state = CallState::Cancelling;
                }
                Ok(())
            }
            (CallDirection::Outbound, CallState::Ringing) => {
                self.send_cancel_for_call_with_reason(call_id, reason, now)?;
                Ok(())
            }
            (CallDirection::Inbound, CallState::Incoming | CallState::Ringing) => {
                if let Some(call) = self.calls.get_mut(call_id) {
                    call.pending_reliable_1xx = None;
                }
                if let (Some(tx_id), Some(req)) = (inbound_tx, inbound_req) {
                    let mut resp = req.create_response(486, "Busy Here")?;
                    let mut to = resp.to()?;
                    to.tag = Some(local_tag);
                    resp.headers.set("To", to.to_string());
                    if let Some(r) = &reason {
                        resp.headers.set("Reason", r.to_string());
                    }
                    let tx_events = self.transactions.send_server_response(&tx_id, resp, now)?;
                    self.process_transaction_events(tx_events, now);
                }
                self.terminate_call_with_reason(
                    call_id,
                    Some(486),
                    "Rejected locally".to_string(),
                    reason,
                );
                Ok(())
            }
            (_, CallState::Established | CallState::ReInviting) => {
                self.send_bye_for_call_with_reason(call_id, None, reason, now)?;
                Ok(())
            }
            (_, CallState::Cancelling | CallState::Terminating | CallState::Terminated) => Ok(()),
            (CallDirection::Outbound, CallState::Incoming)
            | (CallDirection::Inbound, CallState::Calling) => {
                Err(SipError::TransactionError(format!(
                    "invalid call state {:?} for direction {:?}",
                    state, direction
                )))
            }
        }
    }

    /// Places an established call on local hold via an in-dialog `re-INVITE` (`a=sendonly` or `a=inactive`).
    pub fn hold(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
        let (local_ip, local_rtp_port, prev_local_hold, remote_hold, target_dir) = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.state != CallState::Established {
                return Err(SipError::TransactionError(format!(
                    "cannot hold call {call_id} in state {:?}",
                    call.state
                )));
            }
            call.pending_glare_retry = None;
            call.glare_attempts = 0;
            let dir = if call.remote_hold {
                Direction::Inactive
            } else {
                Direction::SendOnly
            };
            (
                self.config.local_host.clone(),
                call.local_rtp_port,
                call.local_hold,
                call.remote_hold,
                dir,
            )
        };

        self.send_reinvite_with_direction(
            call_id,
            &local_ip,
            local_rtp_port,
            target_dir,
            Some(true),
            now,
        )?;
        if !prev_local_hold {
            self.pending_events.push_back(UaEvent::CallHoldChanged {
                call_id: call_id.to_string(),
                local_hold: true,
                remote_hold,
            });
        }
        Ok(())
    }

    /// Resumes an established call from local hold via an in-dialog `re-INVITE` (`a=sendrecv`).
    pub fn resume_call(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
        let (local_ip, local_rtp_port, prev_local_hold, remote_hold) = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.state != CallState::Established {
                return Err(SipError::TransactionError(format!(
                    "cannot resume call {call_id} in state {:?}",
                    call.state
                )));
            }
            call.pending_glare_retry = None;
            call.glare_attempts = 0;
            (
                self.config.local_host.clone(),
                call.local_rtp_port,
                call.local_hold,
                call.remote_hold,
            )
        };

        self.send_reinvite_with_direction(
            call_id,
            &local_ip,
            local_rtp_port,
            Direction::SendRecv,
            Some(false),
            now,
        )?;
        if prev_local_hold {
            self.pending_events.push_back(UaEvent::CallHoldChanged {
                call_id: call_id.to_string(),
                local_hold: false,
                remote_hold,
            });
        }
        Ok(())
    }

    /// Initiates an in-dialog `re-INVITE` updating local IP/port and incrementing SDP `o=` version.
    pub fn reinvite(
        &mut self,
        call_id: &str,
        new_local_ip: &str,
        new_local_rtp_port: u16,
        now: Instant,
    ) -> Result<(), SipError> {
        let dir = match self.calls.get_mut(call_id) {
            Some(c) => {
                c.pending_glare_retry = None;
                c.glare_attempts = 0;
                if c.local_hold && c.remote_hold {
                    Direction::Inactive
                } else if c.local_hold {
                    Direction::SendOnly
                } else {
                    Direction::SendRecv
                }
            }
            None => Direction::SendRecv,
        };
        self.send_reinvite_with_direction(call_id, new_local_ip, new_local_rtp_port, dir, None, now)
    }

    fn send_reinvite_with_direction(
        &mut self,
        call_id: &str,
        new_local_ip: &str,
        new_local_rtp_port: u16,
        direction: Direction,
        new_local_hold: Option<bool>,
        now: Instant,
    ) -> Result<(), SipError> {
        let srtp_mode = self.config.effective_srtp_mode()?;
        let branch = self.next_branch();
        if self
            .calls
            .get(call_id)
            .is_some_and(|c| c.local_crypto.is_empty())
            && matches!(srtp_mode, SrtpMode::SdesOptional | SrtpMode::SdesRequired)
        {
            let cands = self.generate_sdes_candidates(call_id);
            if let Some(c) = self.calls.get_mut(call_id) {
                c.local_crypto = cands;
            }
        }
        let (sdp_sid, sdp_version, codecs, local_crypto) = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.state != CallState::Established {
                return Err(SipError::TransactionError(format!(
                    "cannot send re-INVITE for call {call_id} in state {:?}",
                    call.state
                )));
            }
            call.pending_reinvite_rollback = Some(PendingReInviteRollback {
                prev_local_sdp: call.local_sdp.clone(),
                prev_sdp_version: call.sdp_version,
                prev_local_hold: call.local_hold,
                prev_local_rtp_port: call.local_rtp_port,
            });
            if let Some(lh) = new_local_hold {
                call.local_hold = lh;
            }
            call.local_cseq += 1;
            call.local_rtp_port = new_local_rtp_port;
            call.sdp_version += 1;
            call.state = CallState::ReInviting;
            call.invite_auth.reset();

            let codecs = if call.negotiated_codecs.is_empty() {
                self.config.supported_codecs.clone()
            } else {
                call.negotiated_codecs.clone()
            };
            (
                call.sdp_session_id.clone(),
                call.sdp_version,
                codecs,
                call.local_crypto.clone(),
            )
        };
        let new_sdp = self.build_local_offer_sdp(
            srtp_mode,
            &sdp_sid,
            sdp_version,
            new_local_ip,
            new_local_rtp_port,
            direction,
            codecs,
            &local_crypto,
        );
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.local_sdp = Some(new_sdp.clone());
            Self::build_in_dialog_invite(&self.config, call, &branch, &new_sdp)
        };

        let tx_id = match self.transactions.start_client_transaction(req.clone(), now) {
            Ok(id) => id,
            Err(err) => {
                if let Some(call) = self.calls.get_mut(call_id) {
                    call.state = CallState::Established;
                    if let Some(rb) = call.pending_reinvite_rollback.take() {
                        call.local_sdp = rb.prev_local_sdp;
                        call.sdp_version = rb.prev_sdp_version;
                        call.local_hold = rb.prev_local_hold;
                        call.local_rtp_port = rb.prev_local_rtp_port;
                    }
                }
                return Err(err);
            }
        };
        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_invite_tx = Some(tx_id.clone());
            call.active_invite_req = Some(req);
            call.local_sdp = Some(new_sdp);
        }
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::ReInvite));
        Ok(())
    }

    /// Sends an RFC 3311 `UPDATE` request with a fresh SDP offer on an early or established dialog.
    pub fn send_update(
        &mut self,
        call_id: &str,
        new_local_ip: Option<&str>,
        new_local_rtp_port: Option<u16>,
        now: Instant,
    ) -> Result<(), SipError> {
        let srtp_mode = self.config.effective_srtp_mode()?;
        let branch = self.next_branch();
        {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if !matches!(
                call.state,
                CallState::Incoming | CallState::Ringing | CallState::Established
            ) || call.remote_tag.is_none()
            {
                return Err(SipError::TransactionError(format!(
                    "cannot send UPDATE for call {call_id} in state {:?}",
                    call.state
                )));
            }
            let effective_port = new_local_rtp_port.unwrap_or(call.local_rtp_port);
            if effective_port == 0 {
                return Err(SipError::TransactionError(format!(
                    "cannot send SDP UPDATE for call {call_id} with local RTP port 0"
                )));
            }
        }
        if self
            .calls
            .get(call_id)
            .is_some_and(|c| c.local_crypto.is_empty())
            && matches!(srtp_mode, SrtpMode::SdesOptional | SrtpMode::SdesRequired)
        {
            let cands = self.generate_sdes_candidates(call_id);
            if let Some(c) = self.calls.get_mut(call_id) {
                c.local_crypto = cands;
            }
        }
        let (sdp_sid, sdp_version, ip, port, dir, codecs, local_crypto) = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.local_cseq += 1;
            call.update_auth.reset();
            if let Some(p) = new_local_rtp_port {
                call.local_rtp_port = p;
            }
            call.sdp_version += 1;

            let ip = new_local_ip.unwrap_or(&self.config.local_host).to_string();
            let port = call.local_rtp_port;
            let codecs = if call.negotiated_codecs.is_empty() {
                self.config.supported_codecs.clone()
            } else {
                call.negotiated_codecs.clone()
            };
            let dir = if call.local_hold && call.remote_hold {
                Direction::Inactive
            } else if call.local_hold {
                Direction::SendOnly
            } else {
                Direction::SendRecv
            };
            (
                call.sdp_session_id.clone(),
                call.sdp_version,
                ip,
                port,
                dir,
                codecs,
                call.local_crypto.clone(),
            )
        };
        let sdp = self.build_local_offer_sdp(
            srtp_mode,
            &sdp_sid,
            sdp_version,
            &ip,
            port,
            dir,
            codecs,
            &local_crypto,
        );
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.local_sdp = Some(sdp.clone());
            Self::build_in_dialog_update(&self.config, call, &branch, Some(&sdp))
        };

        let tx_id = self
            .transactions
            .start_client_transaction(req.clone(), now)?;
        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_update_tx = Some(tx_id.clone());
            call.active_update_req = Some(req);
        }
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Update));
        Ok(())
    }

    fn send_session_refresh_update(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
        let branch = self.next_branch();
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.state != CallState::Established || call.remote_tag.is_none() {
                return Err(SipError::TransactionError(format!(
                    "cannot send refresh UPDATE for call {call_id} in state {:?}",
                    call.state
                )));
            }
            call.local_cseq += 1;
            call.update_auth.reset();
            Self::build_in_dialog_update(&self.config, call, &branch, None)
        };

        let tx_id = self
            .transactions
            .start_client_transaction(req.clone(), now)?;
        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_update_tx = Some(tx_id.clone());
            call.active_update_req = Some(req);
        }
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Update));
        Ok(())
    }

    /// Initiates a blind call transfer (`REFER` per RFC 3515) on an active dialog.
    pub fn refer(
        &mut self,
        call_id: &str,
        target_uri: SipUri,
        now: Instant,
    ) -> Result<(), SipError> {
        self.send_refer_with_auth(call_id, target_uri, None, now)
    }

    fn send_refer_with_auth(
        &mut self,
        call_id: &str,
        target_uri: SipUri,
        auth_retry: Option<(u16, String)>,
        now: Instant,
    ) -> Result<(), SipError> {
        let branch = self.next_branch();
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if !matches!(call.state, CallState::Established | CallState::ReInviting)
                || call.remote_tag.is_none()
            {
                return Err(SipError::TransactionError(format!(
                    "cannot send REFER for call {call_id} in state {:?}",
                    call.state
                )));
            }
            call.local_cseq += 1;
            match auth_retry {
                Some((code, hdr_val)) => call.refer_auth.record_retry(code, hdr_val),
                None => call.refer_auth.reset(),
            }
            call.active_refer_uri = Some(target_uri.clone());

            let mut req = SipRequest::new(Method::Refer, call.remote_target.clone());
            req.headers.add(
                "Via",
                Via::new(
                    self.config.transport.via_proto(),
                    format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                    branch,
                )
                .to_string(),
            );
            for route in &call.route_set {
                req.headers
                    .add("Route", NameAddr::new(route.clone()).to_string());
            }
            req.headers.set(
                "From",
                call.local_name_addr(self.config.display_name.as_deref())
                    .to_string(),
            );
            req.headers.set("To", call.remote_name_addr().to_string());
            req.headers.set("Call-ID", call.call_id.clone());
            req.headers.set(
                "CSeq",
                CSeq::new(call.local_cseq, Method::Refer).to_string(),
            );
            req.headers.set("Max-Forwards", "70");
            req.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            req.headers
                .set("Refer-To", NameAddr::new(target_uri).to_string());
            req.headers.set(
                "Referred-By",
                NameAddr::new(self.config.aor_uri()).to_string(),
            );
            call.refer_auth.apply(&mut req.headers);
            req
        };

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Refer));
        Ok(())
    }

    /// Initiates an attended call transfer (`REFER` with `?Replaces=...` per RFC 3515 & RFC 3891) bridging `call_id` to `target_call_id`.
    pub fn attended_transfer(
        &mut self,
        call_id: &str,
        target_call_id: &str,
        now: Instant,
    ) -> Result<(), SipError> {
        if call_id == target_call_id {
            return Err(SipError::TransactionError(
                "cannot attended-transfer a call onto itself".to_string(),
            ));
        }
        let target_uri = {
            let target_call = self.calls.get(target_call_id).ok_or_else(|| {
                SipError::TransactionError(format!("unknown target call {target_call_id}"))
            })?;
            let remote_tag = target_call.remote_tag.clone().ok_or_else(|| {
                SipError::TransactionError(format!(
                    "target call {target_call_id} lacks remote dialog tag"
                ))
            })?;
            let replaces = ReplacesHeader::new(
                target_call.call_id.clone(),
                remote_tag,
                target_call.local_tag.clone(),
            );
            let mut uri = target_call.remote_uri.clone();
            uri.headers
                .retain(|(k, _)| !k.eq_ignore_ascii_case("replaces"));
            uri.headers
                .push(("Replaces".to_string(), replaces.to_uri_escaped()));
            uri
        };
        self.refer(call_id, target_uri, now)
    }

    /// Sends an in-dialog RFC 3515 `NOTIFY` (`Event: refer`, `message/sipfrag`) reporting transfer progress to the transferor.
    pub fn notify_refer_status(
        &mut self,
        call_id: &str,
        status_code: u16,
        reason: &str,
        terminated: bool,
        now: Instant,
    ) -> Result<(), SipError> {
        let branch = self.next_branch();
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if call.remote_tag.is_none() {
                return Err(SipError::TransactionError(format!(
                    "cannot send NOTIFY for call {call_id} without remote tag"
                )));
            }
            call.local_cseq += 1;

            let sipfrag = format!("SIP/2.0 {status_code} {reason}\r\n");
            let mut req = SipRequest::new(Method::Notify, call.remote_target.clone())
                .with_body("message/sipfrag;version=2.0", sipfrag.into_bytes());
            req.headers.add(
                "Via",
                Via::new(
                    self.config.transport.via_proto(),
                    format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                    branch,
                )
                .to_string(),
            );
            for route in &call.route_set {
                req.headers
                    .add("Route", NameAddr::new(route.clone()).to_string());
            }
            req.headers.set(
                "From",
                call.local_name_addr(self.config.display_name.as_deref())
                    .to_string(),
            );
            req.headers.set("To", call.remote_name_addr().to_string());
            req.headers.set("Call-ID", call.call_id.clone());
            req.headers.set(
                "CSeq",
                CSeq::new(call.local_cseq, Method::Notify).to_string(),
            );
            req.headers.set("Max-Forwards", "70");
            req.headers.set("Event", "refer");
            let sub_state = if terminated {
                "terminated;reason=noresource"
            } else {
                "active;expires=60"
            };
            req.headers.set("Subscription-State", sub_state);
            req.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            req
        };

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Notify));
        Ok(())
    }

    /// Sends a legacy RFC 2976 SIP `INFO` DTMF (`application/dtmf-relay`) digit on an early or established dialog.
    pub fn send_info_dtmf(
        &mut self,
        call_id: &str,
        digit: char,
        duration_ms: u32,
        now: Instant,
    ) -> Result<(), SipError> {
        let normalized = normalize_dtmf_char(digit).ok_or_else(|| {
            SipError::TransactionError(format!("unsupported SIP INFO DTMF digit '{digit}'"))
        })?;
        let clamped_dur = duration_ms.clamp(40, 5_000);
        if let Some(call) = self.calls.get_mut(call_id) {
            call.info_auth.reset();
            call.active_info_payload = Some((normalized, clamped_dur));
        }
        self.send_info_dtmf_with_auth(call_id, normalized, clamped_dur, None, now)
    }

    fn send_info_dtmf_with_auth(
        &mut self,
        call_id: &str,
        digit: char,
        duration_ms: u32,
        auth_retry: Option<(u16, String)>,
        now: Instant,
    ) -> Result<(), SipError> {
        let branch = self.next_branch();
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            if !matches!(
                call.state,
                CallState::Ringing | CallState::Established | CallState::ReInviting
            ) || call.remote_tag.is_none()
            {
                return Err(SipError::TransactionError(format!(
                    "cannot send SIP INFO DTMF for call {call_id} in state {:?}",
                    call.state
                )));
            }
            call.local_cseq += 1;
            match auth_retry {
                Some((code, hdr_val)) => call.info_auth.record_retry(code, hdr_val),
                None => call.info_auth.reset(),
            }
            call.active_info_payload = Some((digit, duration_ms));

            let body = format!("Signal={digit}\r\nDuration={duration_ms}\r\n");
            let mut req = SipRequest::new(Method::Info, call.remote_target.clone())
                .with_body("application/dtmf-relay", body.into_bytes());
            req.headers.add(
                "Via",
                Via::new(
                    self.config.transport.via_proto(),
                    format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                    branch,
                )
                .to_string(),
            );
            for route in &call.route_set {
                req.headers
                    .add("Route", NameAddr::new(route.clone()).to_string());
            }
            req.headers.set(
                "From",
                call.local_name_addr(self.config.display_name.as_deref())
                    .to_string(),
            );
            req.headers.set("To", call.remote_name_addr().to_string());
            req.headers.set("Call-ID", call.call_id.clone());
            req.headers
                .set("CSeq", CSeq::new(call.local_cseq, Method::Info).to_string());
            req.headers.set("Max-Forwards", "70");
            req.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            req.headers.set("User-Agent", DEFAULT_USER_AGENT);
            call.info_auth.apply(&mut req.headers);
            req
        };

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Info));
        Ok(())
    }

    /// Handles a mobile/desktop network handover (`Wi-Fi <-> LTE`) across registration and active calls.
    pub fn notify_network_changed(
        &mut self,
        new_local_ip: impl Into<String>,
        new_local_sip_port: u16,
        now: Instant,
    ) -> Result<(), SipError> {
        self.notify_network_changed_with_rtp_ports(
            new_local_ip,
            new_local_sip_port,
            &HashMap::new(),
            now,
        )
    }

    /// Handles a network handover while allowing callers to supply rebound per-call local RTP ports for `re-INVITE` SDP offers.
    pub fn notify_network_changed_with_rtp_ports(
        &mut self,
        new_local_ip: impl Into<String>,
        new_local_sip_port: u16,
        rebound_rtp_ports: &HashMap<String, u16>,
        now: Instant,
    ) -> Result<(), SipError> {
        let new_ip = new_local_ip.into();
        self.config.local_host = new_ip.clone();
        self.config.local_sip_port = new_local_sip_port;

        if matches!(
            self.reg_state,
            RegistrationState::Registered { .. } | RegistrationState::Registering
        ) {
            self.register(now)?;
        }

        let mut ringing_updates = Vec::new();
        for (call_id, &new_port) in rebound_rtp_ports {
            if let Some(call) = self.calls.get_mut(call_id) {
                if call.state != CallState::Established {
                    call.local_rtp_port = new_port;
                    if call.state == CallState::Ringing
                        && call.remote_tag.is_some()
                        && call.active_update_tx.is_none()
                    {
                        ringing_updates.push((call_id.clone(), new_port));
                    }
                }
            }
        }
        for (call_id, rtp_port) in ringing_updates {
            let _ = self.send_update(&call_id, Some(&new_ip), Some(rtp_port), now);
        }

        let established_calls: Vec<(String, u16)> = self
            .calls
            .iter_mut()
            .filter(|(_, call)| call.state == CallState::Established)
            .map(|(id, call)| {
                call.pending_glare_retry = None;
                call.glare_attempts = 0;
                let port = rebound_rtp_ports
                    .get(id)
                    .copied()
                    .unwrap_or(call.local_rtp_port);
                (id.clone(), port)
            })
            .collect();

        for (call_id, rtp_port) in established_calls {
            self.reinvite(&call_id, &new_ip, rtp_port, now)?;
        }

        Ok(())
    }

    /// Parses and feeds a raw inbound SIP datagram into the User Agent.
    pub fn receive_datagram(&mut self, bytes: &[u8], now: Instant) -> Vec<UaEvent> {
        match SipMessage::parse(bytes) {
            Ok(msg) => self.receive_message(msg, now),
            Err(err) => {
                let mut events = self.drain_events();
                events.push(UaEvent::ProtocolWarning(err.to_string()));
                events
            }
        }
    }

    /// Feeds a parsed inbound [`SipMessage`] into the User Agent.
    pub fn receive_message(&mut self, msg: SipMessage, now: Instant) -> Vec<UaEvent> {
        let tx_events = self.transactions.receive_message(msg, now);
        self.process_transaction_events(tx_events, now);
        self.drain_events()
    }

    /// Returns the earliest deadline across transactions, registration refresh, UAS 2xx retransmits, and RFC 4028 Session Timers.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let tx_dl = self.transactions.poll_timeout();
        let reg_dl = match &self.reg_state {
            RegistrationState::Registered { refresh_at, .. } => Some(*refresh_at),
            _ => None,
        };
        let ack_dl = self
            .calls
            .values()
            .filter_map(|c| c.awaiting_ack.as_ref().map(|a| a.next_send_at))
            .min();
        let se_refresh_dl = self
            .calls
            .values()
            .filter_map(|c| c.session_refresh_at)
            .min();
        let se_expire_dl = self
            .calls
            .values()
            .filter_map(|c| c.session_expire_at)
            .min();
        let cancel_dl = self.calls.values().filter_map(|c| c.cancel_deadline).min();

        let rel1xx_dl = self
            .calls
            .values()
            .filter_map(|c| {
                c.pending_reliable_1xx
                    .as_ref()
                    .map(|p| p.next_send_at.min(p.deadline))
            })
            .min();
        let glare_dl = self
            .calls
            .values()
            .filter_map(|c| c.pending_glare_retry.as_ref().map(|g| g.due_at))
            .min();

        [
            tx_dl,
            reg_dl,
            ack_dl,
            rel1xx_dl,
            glare_dl,
            se_refresh_dl,
            se_expire_dl,
            cancel_dl,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Advances transaction, registration refresh, UAS 2xx retransmission, and Session-Timer deadlines up to `now`.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<UaEvent> {
        let tx_events = self.transactions.handle_timeout(now);
        self.process_transaction_events(tx_events, now);

        if let RegistrationState::Registered { refresh_at, .. } = self.reg_state {
            if now >= refresh_at {
                if let Err(err) = self.register(now) {
                    self.set_registration_state(RegistrationState::Failed {
                        status_code: None,
                        reason: err.to_string(),
                    });
                }
            }
        }

        let due_acks: Vec<String> = self
            .calls
            .iter()
            .filter_map(|(id, call)| {
                call.awaiting_ack
                    .as_ref()
                    .filter(|a| now >= a.next_send_at)
                    .map(|_| id.clone())
            })
            .collect();

        let t2 = self.config.timers.t2;
        for call_id in due_acks {
            let mut timed_out = false;
            let mut resend_resp = None;

            if let Some(call) = self.calls.get_mut(&call_id) {
                if let Some(pending) = call.awaiting_ack.as_mut() {
                    if now >= pending.deadline {
                        timed_out = true;
                    } else {
                        resend_resp = Some(pending.response.clone());
                        pending.interval = (pending.interval * 2).min(t2);
                        pending.next_send_at = now + pending.interval;
                    }
                }
            }

            if timed_out {
                if let Some(call) = self.calls.get_mut(&call_id) {
                    call.awaiting_ack = None;
                }
                let reason_hdr = ReasonHeader::sip(408, "ACK Timeout");
                let _ = self.send_bye_for_call_with_reason(
                    &call_id,
                    None,
                    Some(reason_hdr.clone()),
                    now,
                );
                self.terminate_call_with_reason(
                    &call_id,
                    None,
                    "ACK timeout for 200 OK (RFC 3261 §13.3.1.4)".to_string(),
                    Some(reason_hdr),
                );
            } else if let Some(resp) = resend_resp {
                self.transactions.send_stateless_response(resp);
            }
        }

        // RFC 3262 §3: retransmit unacknowledged reliable 1xx responses at T1 doubling up to 64*T1,
        // or reject the INVITE with 504 Server Time-out if PRACK never arrives.
        let due_reliable_1xx: Vec<String> = self
            .calls
            .iter()
            .filter_map(|(id, call)| {
                call.pending_reliable_1xx
                    .as_ref()
                    .filter(|p| now >= p.next_send_at || now >= p.deadline)
                    .map(|_| id.clone())
            })
            .collect();
        for call_id in due_reliable_1xx {
            let mut timed_out = false;
            let mut resend_resp: Option<SipResponse> = None;
            let mut inv_tx_opt: Option<TransactionId> = None;

            if let Some(call) = self.calls.get_mut(&call_id) {
                if let Some(pending) = call.pending_reliable_1xx.as_mut() {
                    if now >= pending.deadline {
                        timed_out = true;
                    } else {
                        resend_resp = Some(pending.response.clone());
                        inv_tx_opt = call.inbound_invite_tx.clone();
                        pending.interval = pending.interval.saturating_mul(2);
                        pending.next_send_at = now + pending.interval;
                    }
                }
            }

            if timed_out {
                let (inv_tx, inv_req, ltag) = match self.calls.get_mut(&call_id) {
                    Some(call) => {
                        call.pending_reliable_1xx = None;
                        (
                            call.inbound_invite_tx.take(),
                            call.inbound_invite_req.take(),
                            call.local_tag.clone(),
                        )
                    }
                    None => (None, None, String::new()),
                };
                if let (Some(tx_id), Some(req)) = (inv_tx, inv_req) {
                    if let Ok(resp) = req.create_response(504, "Server Time-out") {
                        self.send_uas_response(&tx_id, resp, Some(&ltag), now);
                    }
                }
                let reason_hdr = ReasonHeader::sip(504, "Server Time-out");
                self.terminate_call_with_reason(
                    &call_id,
                    Some(504),
                    "100rel PRACK timeout (RFC 3262 §3)".to_string(),
                    Some(reason_hdr),
                );
            } else if let Some(resp) = resend_resp {
                if let Some(inv_tx) = inv_tx_opt {
                    if self
                        .transactions
                        .send_server_response(&inv_tx, resp.clone(), now)
                        .is_err()
                    {
                        self.transactions.send_stateless_response(resp);
                    }
                } else {
                    self.transactions.send_stateless_response(resp);
                }
            }
        }

        // RFC 3261 §14.1: retry outbound re-INVITE after 491 Request Pending backoff.
        let due_glare_retries: Vec<String> = self
            .calls
            .iter()
            .filter_map(|(id, call)| {
                if call.state == CallState::Established
                    && call.active_invite_tx.is_none()
                    && call.active_update_tx.is_none()
                    && call
                        .pending_glare_retry
                        .as_ref()
                        .is_some_and(|g| now >= g.due_at)
                {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for call_id in due_glare_retries {
            let Some(retry) = self
                .calls
                .get_mut(&call_id)
                .and_then(|c| c.pending_glare_retry.take())
            else {
                continue;
            };
            let Some((dir, remote_hold)) = self.calls.get(&call_id).map(|c| {
                let d = if retry.desired_local_hold && c.remote_hold {
                    Direction::Inactive
                } else if retry.desired_local_hold {
                    Direction::SendOnly
                } else {
                    Direction::SendRecv
                };
                (d, c.remote_hold)
            }) else {
                continue;
            };
            if let Some(c) = self.calls.get_mut(&call_id) {
                c.glare_attempts = retry.attempts;
            }
            let prev_hold = self.calls.get(&call_id).is_some_and(|c| c.local_hold);
            if self
                .send_reinvite_with_direction(
                    &call_id,
                    &retry.ip,
                    retry.rtp_port,
                    dir,
                    Some(retry.desired_local_hold),
                    now,
                )
                .is_err()
                && prev_hold != retry.desired_local_hold
            {
                self.pending_events.push_back(UaEvent::CallHoldChanged {
                    call_id,
                    local_hold: prev_hold,
                    remote_hold,
                });
            }
        }

        // RFC 4028: check Session-Timer expiration and refresh deadlines.
        let expired_sessions: Vec<String> = self
            .calls
            .iter()
            .filter_map(|(id, call)| {
                call.session_expire_at
                    .filter(|exp| now >= *exp)
                    .map(|_| id.clone())
            })
            .collect();
        for call_id in expired_sessions {
            if let Some(call) = self.calls.get_mut(&call_id) {
                call.session_expire_at = None;
                call.session_refresh_at = None;
            }
            let reason_hdr = ReasonHeader::sip(408, "Session Timer Expired");
            let _ =
                self.send_bye_for_call_with_reason(&call_id, None, Some(reason_hdr.clone()), now);
            self.terminate_call_with_reason(
                &call_id,
                Some(408),
                "Session Timer Expired".to_string(),
                Some(reason_hdr),
            );
        }

        let due_refreshes: Vec<String> = self
            .calls
            .iter()
            .filter_map(|(id, call)| {
                if call.state == CallState::Established
                    && call.active_update_tx.is_none()
                    && call.session_refresh_at.is_some_and(|dl| now >= dl)
                {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for call_id in due_refreshes {
            if let Some(call) = self.calls.get_mut(&call_id) {
                call.session_refresh_at = None;
            }
            if let Err(err) = self.send_session_refresh_update(&call_id, now) {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
            }
        }

        let expired_cancels: Vec<String> = self
            .calls
            .iter()
            .filter_map(|(id, call)| {
                if call.state == CallState::Cancelling
                    && call.cancel_deadline.is_some_and(|dl| now >= dl)
                {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for call_id in expired_cancels {
            let reason_hdr = ReasonHeader::sip(408, "Request Timeout");
            self.terminate_call_with_reason(
                &call_id,
                Some(408),
                "CANCEL final response timeout".to_string(),
                Some(reason_hdr),
            );
        }

        self.drain_events()
    }

    /// Drains outbound SIP messages queued for UDP/TCP network transmission.
    pub fn poll_transmit(&mut self) -> Vec<Vec<u8>> {
        self.transactions.poll_transmit()
    }

    fn set_registration_state(&mut self, new_state: RegistrationState) {
        self.reg_state = new_state.clone();
        self.pending_events
            .push_back(UaEvent::RegistrationChanged(new_state));
    }

    fn next_seq(&mut self) -> u64 {
        let val = self.id_counter;
        self.id_counter = self.id_counter.saturating_add(1);
        val
    }

    fn seed_suffix(&self) -> String {
        let eff = effective_instance_seed(&self.config);
        format!("-{:08x}", (eff & 0xffff_ffff) as u32)
    }

    fn next_numeric_id(&mut self) -> String {
        let seq = self.next_seq();
        let eff = effective_instance_seed(&self.config);
        format!("{}{}{}", (eff % 1_000_000), self.config.local_sip_port, seq)
    }

    fn next_call_id(&mut self) -> String {
        let seq = self.next_seq();
        let suffix = self.seed_suffix();
        format!(
            "bm-{}{suffix}-{}@{}",
            self.config.local_sip_port, seq, self.config.local_host
        )
    }

    fn next_tag(&mut self) -> String {
        let seq = self.next_seq();
        let suffix = self.seed_suffix();
        format!("bm-tag-{}{suffix}-{}", self.config.local_sip_port, seq)
    }

    fn next_branch(&mut self) -> String {
        let seq = self.next_seq();
        let suffix = self.seed_suffix();
        format!("z9hG4bK-bm-{}{suffix}-{}", self.config.local_sip_port, seq)
    }

    fn next_cnonce(&mut self) -> String {
        let seq = self.next_seq();
        let eff = effective_instance_seed(&self.config);
        format!(
            "bmcnonce{:08x}{:04x}{:08x}",
            (eff & 0xffff_ffff) as u32,
            self.config.local_sip_port,
            seq
        )
    }

    fn reject_inbound_invite_488(
        &mut self,
        call_id: &str,
        tx_id: &TransactionId,
        req: &SipRequest,
        local_tag: &str,
        now: Instant,
    ) {
        if let Some(call) = self.calls.get_mut(call_id) {
            call.pending_reliable_1xx = None;
        }
        if let Ok(mut resp) = req.create_response(488, "Not Acceptable Here") {
            if let Ok(mut to) = resp.to() {
                to.tag = Some(local_tag.to_string());
                resp.headers.set("To", to.to_string());
            }
            if let Ok(events) = self.transactions.send_server_response(tx_id, resp, now) {
                self.process_transaction_events(events, now);
            }
        }
        self.terminate_call(call_id, Some(488), "Not Acceptable Here".to_string());
    }

    fn start_register_with_expires(
        &mut self,
        expires: u32,
        auth_action: AuthAction,
        now: Instant,
    ) -> Result<(), SipError> {
        self.reg_session.cseq += 1;
        match auth_action {
            AuthAction::Reset => self.reg_session.auth.reset(),
            AuthAction::Keep => {}
            AuthAction::Retry(status_code, hdr_val) => {
                self.reg_session.auth.record_retry(status_code, hdr_val);
            }
        }
        self.reg_session.pending_expires = expires;

        if let Some(old_tx) = self.reg_session.active_tx.take() {
            let _ = old_tx;
        }

        let branch = self.next_branch();
        let aor = self.config.aor_uri();
        let contact = NameAddr::new(self.config.contact_uri()).to_string();

        let mut req = SipRequest::new(Method::Register, self.config.registrar_uri.clone());
        req.headers.add(
            "Via",
            Via::new(
                self.config.transport.via_proto(),
                format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                branch,
            )
            .to_string(),
        );
        req.headers.set(
            "From",
            self.config
                .local_from_name_addr()
                .with_tag(self.reg_session.local_tag.clone())
                .to_string(),
        );
        req.headers.set("To", NameAddr::new(aor).to_string());
        req.headers.set("Call-ID", self.reg_session.call_id.clone());
        req.headers.set(
            "CSeq",
            CSeq::new(self.reg_session.cseq, Method::Register).to_string(),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers.set("Contact", contact);
        req.headers.set("Expires", expires.to_string());
        req.headers.set("Allow", ALLOW_METHODS);
        req.headers.set("Supported", SUPPORTED_EXTENSIONS);
        req.headers.set("User-Agent", DEFAULT_USER_AGENT);
        self.reg_session.auth.apply(&mut req.headers);

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        self.reg_session.active_tx = Some(tx_id);
        Ok(())
    }

    fn build_invite_request(
        config: &UaConfig,
        call: &CallSession,
        branch: &str,
        sdp: &SdpSession,
    ) -> SipRequest {
        let mut req = SipRequest::new(Method::Invite, call.remote_uri.clone())
            .with_body("application/sdp", sdp.to_string().into_bytes());
        req.headers.add(
            "Via",
            Via::new(
                config.transport.via_proto(),
                format!("{}:{}", config.local_host, config.local_sip_port),
                branch,
            )
            .to_string(),
        );
        req.headers.set(
            "From",
            call.local_name_addr(config.display_name.as_deref())
                .to_string(),
        );
        req.headers
            .set("To", NameAddr::new(call.remote_uri.clone()).to_string());
        req.headers.set("Call-ID", call.call_id.clone());
        req.headers.set(
            "CSeq",
            CSeq::new(call.local_cseq, Method::Invite).to_string(),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("Contact", NameAddr::new(config.contact_uri()).to_string());
        req.headers.set("Allow", ALLOW_METHODS);
        req.headers.set("Supported", SUPPORTED_EXTENSIONS);
        req.headers.set("User-Agent", DEFAULT_USER_AGENT);
        if let Some(se) = call.session_expires_secs {
            req.headers.set("Session-Expires", se.to_string());
            req.headers
                .set("Min-SE", call.min_se_secs.max(1).to_string());
        }
        if let Some(rep) = &call.replaces_header {
            req.headers.set("Replaces", rep.to_string());
        }
        if let Some(pai) = &config.asserted_identity {
            req.headers.set("P-Asserted-Identity", pai.to_string());
        }
        if let Some(priv_val) = &config.privacy {
            req.headers.set("Privacy", priv_val.clone());
        }
        call.invite_auth.apply(&mut req.headers);
        req
    }

    fn build_in_dialog_invite(
        config: &UaConfig,
        call: &CallSession,
        branch: &str,
        sdp: &SdpSession,
    ) -> SipRequest {
        let mut req = SipRequest::new(Method::Invite, call.remote_target.clone())
            .with_body("application/sdp", sdp.to_string().into_bytes());
        req.headers.add(
            "Via",
            Via::new(
                config.transport.via_proto(),
                format!("{}:{}", config.local_host, config.local_sip_port),
                branch,
            )
            .to_string(),
        );
        for route in &call.route_set {
            req.headers
                .add("Route", NameAddr::new(route.clone()).to_string());
        }
        req.headers.set(
            "From",
            call.local_name_addr(config.display_name.as_deref())
                .to_string(),
        );
        req.headers.set("To", call.remote_name_addr().to_string());
        req.headers.set("Call-ID", call.call_id.clone());
        req.headers.set(
            "CSeq",
            CSeq::new(call.local_cseq, Method::Invite).to_string(),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("Contact", NameAddr::new(config.contact_uri()).to_string());
        req.headers.set("Allow", ALLOW_METHODS);
        req.headers.set("Supported", SUPPORTED_EXTENSIONS);
        if let Some(se) = call.session_expires_secs {
            let refresher = if call.session_refresher_is_local {
                Some(SessionRefresher::Uac)
            } else {
                None
            };
            req.headers.set(
                "Session-Expires",
                SessionExpires::new(se, refresher).to_string(),
            );
            req.headers
                .set("Min-SE", call.min_se_secs.max(1).to_string());
        }
        call.invite_auth.apply(&mut req.headers);
        req
    }

    fn build_in_dialog_update(
        config: &UaConfig,
        call: &CallSession,
        branch: &str,
        sdp: Option<&SdpSession>,
    ) -> SipRequest {
        let mut req = SipRequest::new(Method::Update, call.remote_target.clone());
        if let Some(s) = sdp {
            req = req.with_body("application/sdp", s.to_string().into_bytes());
        }
        req.headers.add(
            "Via",
            Via::new(
                config.transport.via_proto(),
                format!("{}:{}", config.local_host, config.local_sip_port),
                branch,
            )
            .to_string(),
        );
        for route in &call.route_set {
            req.headers
                .add("Route", NameAddr::new(route.clone()).to_string());
        }
        req.headers.set(
            "From",
            call.local_name_addr(config.display_name.as_deref())
                .to_string(),
        );
        req.headers.set("To", call.remote_name_addr().to_string());
        req.headers.set("Call-ID", call.call_id.clone());
        req.headers.set(
            "CSeq",
            CSeq::new(call.local_cseq, Method::Update).to_string(),
        );
        req.headers.set("Max-Forwards", "70");
        req.headers
            .set("Contact", NameAddr::new(config.contact_uri()).to_string());
        req.headers.set("Supported", SUPPORTED_EXTENSIONS);
        if let Some(se) = call.session_expires_secs {
            let refresher = if call.session_refresher_is_local {
                Some(SessionRefresher::Uac)
            } else {
                None
            };
            req.headers.set(
                "Session-Expires",
                SessionExpires::new(se, refresher).to_string(),
            );
            req.headers
                .set("Min-SE", call.min_se_secs.max(1).to_string());
        }
        call.update_auth.apply(&mut req.headers);
        req
    }

    fn build_ack_for_2xx(&mut self, call: &CallSession, invite_cseq: u32) -> SipRequest {
        let branch = self.next_branch();
        let mut ack = SipRequest::new(Method::Ack, call.remote_target.clone());
        ack.headers.add(
            "Via",
            Via::new(
                self.config.transport.via_proto(),
                format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                branch,
            )
            .to_string(),
        );
        for route in &call.route_set {
            ack.headers
                .add("Route", NameAddr::new(route.clone()).to_string());
        }
        ack.headers.set(
            "From",
            call.local_name_addr(self.config.display_name.as_deref())
                .to_string(),
        );
        ack.headers.set("To", call.remote_name_addr().to_string());
        ack.headers.set("Call-ID", call.call_id.clone());
        ack.headers
            .set("CSeq", CSeq::new(invite_cseq, Method::Ack).to_string());
        ack.headers.set("Max-Forwards", "70");
        call.invite_auth.apply(&mut ack.headers);
        ack
    }

    fn send_cancel_for_call_with_reason(
        &mut self,
        call_id: &str,
        reason: Option<ReasonHeader>,
        now: Instant,
    ) -> Result<(), SipError> {
        let cancel_t1 = self
            .config
            .timers
            .t1
            .clamp(Duration::from_millis(1), Duration::from_secs(60));
        let cancel_dl = now + cancel_t1.saturating_mul(64);
        let orig_req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.state = CallState::Cancelling;
            call.cancel_deadline = Some(cancel_dl);
            call.pending_cancel = false;
            call.pending_cancel_reason = None;
            call.active_invite_req.clone().ok_or_else(|| {
                SipError::TransactionError("missing original INVITE request for CANCEL".to_string())
            })?
        };

        // RFC 3261 §9.1: CANCEL reuses the INVITE's Request-URI, top Via branch, From, To, Call-ID, and CSeq number.
        let mut cancel = SipRequest::new(Method::Cancel, orig_req.uri.clone());
        if let Some(via) = orig_req.headers.get("Via") {
            cancel.headers.add("Via", via);
        }
        for route in orig_req.headers.get_all("Route") {
            cancel.headers.add("Route", route);
        }
        if let Some(from) = orig_req.headers.get("From") {
            cancel.headers.set("From", from);
        }
        if let Some(to) = orig_req.headers.get("To") {
            cancel.headers.set("To", to);
        }
        if let Some(cid) = orig_req.headers.get("Call-ID") {
            cancel.headers.set("Call-ID", cid);
        }
        let inv_seq = orig_req.cseq()?.seq;
        cancel
            .headers
            .set("CSeq", CSeq::new(inv_seq, Method::Cancel).to_string());
        cancel.headers.set("Max-Forwards", "70");
        if let Some(r) = reason {
            cancel.headers.set("Reason", r.to_string());
        }

        let tx_id = self.transactions.start_client_transaction(cancel, now)?;
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Cancel));
        Ok(())
    }

    fn send_bye_for_call(
        &mut self,
        call_id: &str,
        auth_retry: Option<(u16, String)>,
        now: Instant,
    ) -> Result<(), SipError> {
        self.send_bye_for_call_with_reason(call_id, auth_retry, None, now)
    }

    fn send_bye_for_call_with_reason(
        &mut self,
        call_id: &str,
        auth_retry: Option<(u16, String)>,
        reason: Option<ReasonHeader>,
        now: Instant,
    ) -> Result<(), SipError> {
        let branch = self.next_branch();
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.local_cseq += 1;
            call.state = CallState::Terminating;
            call.session_refresh_at = None;
            call.session_expire_at = None;
            call.cancel_deadline = None;
            call.pending_reliable_1xx = None;
            call.pending_glare_retry = None;
            call.awaiting_ack = None;
            call.awaiting_ack_sdp = None;
            match auth_retry {
                Some((code, hdr_val)) => call.bye_auth.record_retry(code, hdr_val),
                None => call.bye_auth.reset(),
            }

            let mut bye = SipRequest::new(Method::Bye, call.remote_target.clone());
            bye.headers.add(
                "Via",
                Via::new(
                    self.config.transport.via_proto(),
                    format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                    branch,
                )
                .to_string(),
            );
            for route in &call.route_set {
                bye.headers
                    .add("Route", NameAddr::new(route.clone()).to_string());
            }
            bye.headers.set(
                "From",
                call.local_name_addr(self.config.display_name.as_deref())
                    .to_string(),
            );
            bye.headers.set("To", call.remote_name_addr().to_string());
            bye.headers.set("Call-ID", call.call_id.clone());
            bye.headers
                .set("CSeq", CSeq::new(call.local_cseq, Method::Bye).to_string());
            bye.headers.set("Max-Forwards", "70");
            if let Some(r) = reason {
                bye.headers.set("Reason", r.to_string());
            }
            call.bye_auth.apply(&mut bye.headers);
            bye
        };

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_bye_tx = Some(tx_id.clone());
        }
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Bye));
        Ok(())
    }

    fn process_transaction_events(&mut self, events: Vec<TransactionEvent>, now: Instant) {
        for ev in events {
            match ev {
                TransactionEvent::ServerRequest { tx_id, request } => {
                    self.on_server_request(tx_id, request, now);
                }
                TransactionEvent::AckFor2xx(ack) => {
                    self.on_ack_for_2xx(ack, now);
                }
                TransactionEvent::ServerAckReceived(_) => {}
                TransactionEvent::ClientProvisional { tx_id, response } => {
                    self.on_client_provisional(tx_id, response, now);
                }
                TransactionEvent::ClientFinal { tx_id, response } => {
                    self.on_client_final(tx_id, response, now);
                }
                TransactionEvent::Unmatched2xx(response) => {
                    self.on_unmatched_2xx(response, now);
                }
                TransactionEvent::TransactionTimeout(tx_id) => {
                    self.on_transaction_timeout(tx_id);
                }
                TransactionEvent::TransactionTerminated(tx_id) => {
                    self.tx_to_call.remove(&tx_id);
                }
                TransactionEvent::ProtocolWarning(msg) => {
                    self.pending_events.push_back(UaEvent::ProtocolWarning(msg));
                }
            }
        }
    }

    fn ensure_response_to_tag(&mut self, resp: &mut SipResponse, dialog_tag: Option<&str>) {
        if resp.status_code == 100 {
            return;
        }
        if let Ok(mut to) = resp.to() {
            if to.tag.is_none() {
                let tag = match dialog_tag {
                    Some(t) => t.to_string(),
                    None => self.next_tag(),
                };
                to.tag = Some(tag);
                resp.headers.set("To", to.to_string());
            }
        }
    }

    fn send_uas_response(
        &mut self,
        tx_id: &TransactionId,
        mut resp: SipResponse,
        dialog_tag: Option<&str>,
        now: Instant,
    ) {
        self.ensure_response_to_tag(&mut resp, dialog_tag);
        if let Ok(events) = self.transactions.send_server_response(tx_id, resp, now) {
            self.process_transaction_events(events, now);
        }
    }

    fn on_server_request(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        match request.method {
            Method::Options => {
                if let Ok(mut resp) = request.create_response(200, "OK") {
                    resp.headers.set("Allow", ALLOW_METHODS);
                    resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
                    self.send_uas_response(&tx_id, resp, None, now);
                }
            }
            Method::Invite => {
                self.on_inbound_invite(tx_id, request, now);
            }
            Method::Cancel => {
                self.on_inbound_cancel(tx_id, request, now);
            }
            Method::Bye => {
                self.on_inbound_bye(tx_id, request, now);
            }
            Method::Update => {
                self.on_inbound_update(tx_id, request, now);
            }
            Method::Prack => {
                self.on_inbound_prack(tx_id, request, now);
            }
            Method::Refer => {
                self.on_inbound_refer(tx_id, request, now);
            }
            Method::Notify => {
                self.on_inbound_notify(tx_id, request, now);
            }
            Method::Info => {
                self.on_inbound_info(tx_id, request, now);
            }
            _ => {
                if let Ok(resp) = request.create_response(405, "Method Not Allowed") {
                    self.send_uas_response(&tx_id, resp, None, now);
                }
            }
        }
    }

    fn on_inbound_invite(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = match request.call_id() {
            Ok(id) => id.to_string(),
            Err(err) => {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
                return;
            }
        };

        let to = match request.to() {
            Ok(t) => t,
            Err(err) => {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
                return;
            }
        };

        // Check for in-dialog re-INVITE matching an active call (RFC 3261 §12.2.2 & §14.2).
        if let Some(to_tag) = to.tag.as_deref() {
            let from_tag = request.from().ok().and_then(|f| f.tag);
            let req_cseq = request.cseq().ok().map(|c| c.seq);

            enum ReInviteAction {
                Process,
                Glare491(String),
                OutOfOrder500(String),
                NotFound481,
            }

            let action = if let Some(existing) = self.calls.get_mut(&call_id) {
                let remote_tag_matches = match (&existing.remote_tag, &from_tag) {
                    (Some(expected), Some(actual)) => expected == actual,
                    (None, _) => true,
                    (Some(_), None) => false,
                };
                if existing.local_tag == to_tag && remote_tag_matches {
                    let ltag = existing.local_tag.clone();
                    if let (Some(rc), Some(prev)) = (req_cseq, existing.remote_cseq) {
                        if rc <= prev {
                            ReInviteAction::OutOfOrder500(ltag)
                        } else {
                            existing.remote_cseq = Some(rc);
                            match existing.state {
                                CallState::Established => ReInviteAction::Process,
                                CallState::ReInviting => ReInviteAction::Glare491(ltag),
                                _ => ReInviteAction::NotFound481,
                            }
                        }
                    } else {
                        if let Some(rc) = req_cseq {
                            existing.remote_cseq = Some(rc);
                        }
                        match existing.state {
                            CallState::Established => ReInviteAction::Process,
                            CallState::ReInviting => ReInviteAction::Glare491(ltag),
                            _ => ReInviteAction::NotFound481,
                        }
                    }
                } else {
                    ReInviteAction::NotFound481
                }
            } else {
                ReInviteAction::NotFound481
            };

            match action {
                ReInviteAction::Process => {
                    self.handle_inbound_reinvite(&call_id, tx_id, request, now);
                }
                ReInviteAction::Glare491(ltag) => {
                    if let Ok(resp) = request.create_response(491, "Request Pending") {
                        self.send_uas_response(&tx_id, resp, Some(&ltag), now);
                    }
                }
                ReInviteAction::OutOfOrder500(ltag) => {
                    if let Ok(resp) = request.create_response(500, "Server Internal Error") {
                        self.send_uas_response(&tx_id, resp, Some(&ltag), now);
                    }
                }
                ReInviteAction::NotFound481 => {
                    if let Ok(resp) =
                        request.create_response(481, "Call/Transaction Does Not Exist")
                    {
                        self.send_uas_response(&tx_id, resp, None, now);
                    }
                }
            }
            return;
        }

        if self.calls.contains_key(&call_id) {
            if let Ok(resp) = request.create_response(482, "Loop Detected") {
                self.send_uas_response(&tx_id, resp, None, now);
            }
            return;
        }

        // RFC 4028 §6: reject Session-Expires below local Min-SE with 422 Session Interval Too Small.
        if let Some(se_raw) = request.headers.get("Session-Expires") {
            if let Ok(se) = SessionExpires::parse(se_raw) {
                if se.delta_seconds < self.config.min_se_secs {
                    if let Ok(mut resp) = request.create_response(422, "Session Interval Too Small")
                    {
                        resp.headers
                            .set("Min-SE", self.config.min_se_secs.max(1).to_string());
                        self.send_uas_response(&tx_id, resp, None, now);
                    }
                    return;
                }
            }
        }

        // RFC 3891: validate optional Replaces header and match target dialog prior to accepting.
        let mut replaces_call_id = None;
        if let Some(rep_raw) = request.headers.get("Replaces") {
            let Ok(rep) = ReplacesHeader::parse_header_value(rep_raw) else {
                if let Ok(resp) = request.create_response(400, "Bad Replaces Header") {
                    self.send_uas_response(&tx_id, resp, None, now);
                }
                return;
            };
            let matches: Vec<(String, CallDirection, CallState)> = self
                .calls
                .iter()
                .filter(|(_, existing)| {
                    existing.call_id == rep.call_id
                        && existing.local_tag == rep.to_tag
                        && existing.remote_tag.as_deref() == Some(rep.from_tag.as_str())
                })
                .map(|(cid, existing)| (cid.clone(), existing.direction, existing.state))
                .collect();

            if matches.len() != 1 {
                if let Ok(resp) = request.create_response(481, "Call/Transaction Does Not Exist") {
                    self.send_uas_response(&tx_id, resp, None, now);
                }
                return;
            }
            let (old_cid, existing_dir, existing_state) = &matches[0];
            match existing_state {
                CallState::Terminating | CallState::Cancelling | CallState::Terminated => {
                    if let Ok(resp) = request.create_response(603, "Decline") {
                        self.send_uas_response(&tx_id, resp, None, now);
                    }
                    return;
                }
                CallState::Calling | CallState::Incoming | CallState::Ringing => {
                    // RFC 3891 §3: an early dialog NOT initiated by this UA MUST be rejected with 481.
                    if *existing_dir != CallDirection::Outbound {
                        if let Ok(resp) =
                            request.create_response(481, "Call/Transaction Does Not Exist")
                        {
                            self.send_uas_response(&tx_id, resp, None, now);
                        }
                        return;
                    }
                }
                CallState::Established | CallState::ReInviting => {
                    // RFC 3891 §3: confirmed dialog with `early-only` MUST be rejected with 486 Busy Here.
                    if rep.early_only {
                        if let Ok(resp) = request.create_response(486, "Busy Here") {
                            self.send_uas_response(&tx_id, resp, None, now);
                        }
                        return;
                    }
                }
            }
            let old_cid = old_cid.clone();
            let _ = self.hangup_with_reason(
                &old_cid,
                Some(ReasonHeader::sip(200, "Call replaced")),
                now,
            );
            replaces_call_id = Some(old_cid);
        }

        // Send 100 Trying immediately on valid new INVITE.
        if let Ok(r100) = request.create_response(100, "Trying") {
            if let Ok(events) = self.transactions.send_server_response(&tx_id, r100, now) {
                self.process_transaction_events(events, now);
            }
        }

        let from = match request.from() {
            Ok(f) => f,
            Err(err) => {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
                return;
            }
        };
        let remote_sdp = parse_optional_sdp(&request.body);
        let caller_identity = CallerIdentity::from_headers(&request.headers);
        let remote_cseq = request.cseq().ok().map(|c| c.seq);
        let remote_target = match request.contact() {
            Ok(Some(c)) => c.uri,
            _ => from.uri.clone(),
        };
        let route_set = extract_record_routes(&request.headers, false);
        let branch = request
            .top_via()
            .ok()
            .and_then(|v| v.branch)
            .unwrap_or_default();

        let local_tag = self.next_tag();
        let sdp_sid = self.next_numeric_id();

        let call = CallSession {
            call_id: call_id.clone(),
            direction: CallDirection::Inbound,
            state: CallState::Incoming,
            local_tag,
            remote_tag: from.tag.clone(),
            local_uri: to.uri.clone(),
            remote_uri: from.uri.clone(),
            remote_target,
            route_set,
            local_cseq: 1,
            remote_cseq,
            local_rtp_port: 0,
            sdp_session_id: sdp_sid,
            sdp_version: 1,
            local_sdp: None,
            remote_sdp: remote_sdp.clone(),
            negotiated_codecs: Vec::new(),
            local_crypto: Vec::new(),
            negotiated_srtp: None,
            local_hold: false,
            remote_hold: remote_sdp
                .as_ref()
                .is_some_and(|s| is_remote_hold(s.direction)),
            local_rseq: 0,
            pending_reliable_1xx: None,
            last_remote_rseq: None,
            session_expires_secs: None,
            min_se_secs: self.config.min_se_secs.max(1),
            session_refresher_is_local: false,
            session_refresh_at: None,
            session_expire_at: None,
            session_timer_retries: 0,
            cancel_deadline: None,
            pending_reinvite_rollback: None,
            pending_glare_retry: None,
            glare_attempts: 0,
            replaces_header: None,
            active_invite_tx: None,
            active_invite_req: None,
            active_update_tx: None,
            active_update_req: None,
            active_refer_uri: None,
            active_info_payload: None,
            active_bye_tx: None,
            inbound_invite_tx: Some(tx_id),
            inbound_invite_req: Some(request),
            inbound_invite_branch: Some(branch),
            pending_cancel: false,
            pending_cancel_reason: None,
            received_provisional: false,
            invite_auth: AuthRetryState::default(),
            bye_auth: AuthRetryState::default(),
            update_auth: AuthRetryState::default(),
            refer_auth: AuthRetryState::default(),
            info_auth: AuthRetryState::default(),
            last_ack_for_2xx: None,
            awaiting_ack: None,
            awaiting_ack_sdp: None,
        };
        self.calls.insert(call_id.clone(), call);

        self.pending_events.push_back(UaEvent::IncomingCall {
            call_id,
            from,
            to,
            remote_sdp,
            caller_identity,
            replaces_call_id,
        });
    }

    fn handle_inbound_reinvite(
        &mut self,
        call_id: &str,
        tx_id: TransactionId,
        request: SipRequest,
        now: Instant,
    ) {
        let local_tag = self.calls.get(call_id).map(|c| c.local_tag.clone());
        if let Some(se_raw) = request.headers.get("Session-Expires") {
            if let Ok(se) = SessionExpires::parse(se_raw) {
                if se.delta_seconds < self.config.min_se_secs {
                    if let Ok(mut resp) = request.create_response(422, "Session Interval Too Small")
                    {
                        resp.headers
                            .set("Min-SE", self.config.min_se_secs.max(1).to_string());
                        self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                    }
                    return;
                }
            }
        }

        let Some(remote_sdp) = parse_optional_sdp(&request.body) else {
            if !request.body.is_empty() {
                if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                    self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                }
                return;
            }
            // RFC 3261 §14.1: delayed offer re-INVITE — send current local SDP offer in 200 OK,
            // then apply remote SDP answer upon ACK.
            let Ok(srtp_mode) = self.config.effective_srtp_mode() else {
                if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                    self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                }
                return;
            };
            if self
                .calls
                .get(call_id)
                .is_some_and(|c| c.local_crypto.is_empty())
                && matches!(srtp_mode, SrtpMode::SdesOptional | SrtpMode::SdesRequired)
            {
                let cands = self.generate_sdes_candidates(call_id);
                if let Some(c) = self.calls.get_mut(call_id) {
                    c.local_crypto = cands;
                }
            }
            let Some((local_rtp_port, sdp_sid, sdp_version, dir, codecs, local_crypto)) =
                self.calls.get_mut(call_id).map(|c| {
                    c.sdp_version += 1;
                    let dir = if c.local_hold && c.remote_hold {
                        Direction::Inactive
                    } else if c.local_hold {
                        Direction::SendOnly
                    } else {
                        Direction::SendRecv
                    };
                    // RFC 3261 §14.1 / RFC 3264 §8: advertise full local codec capabilities in a delayed re-INVITE offer.
                    let codecs = self.config.supported_codecs.clone();
                    (
                        c.local_rtp_port,
                        c.sdp_session_id.clone(),
                        c.sdp_version,
                        dir,
                        codecs,
                        c.local_crypto.clone(),
                    )
                })
            else {
                return;
            };
            if local_rtp_port == 0 {
                if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                    self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                }
                return;
            }
            let offer_sdp = self.build_local_offer_sdp(
                srtp_mode,
                &sdp_sid,
                sdp_version,
                &self.config.local_host,
                local_rtp_port,
                dir,
                codecs,
                &local_crypto,
            );
            let Ok(mut resp) = request.create_response(200, "OK") else {
                return;
            };
            resp = resp.with_body("application/sdp", offer_sdp.to_string().into_bytes());
            resp.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            resp.headers.set("Allow", ALLOW_METHODS);
            resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
            self.apply_uas_session_timer_to_response(call_id, &request, &mut resp, now);
            self.ensure_response_to_tag(&mut resp, local_tag.as_deref());

            if let Ok(events) = self
                .transactions
                .send_server_response(&tx_id, resp.clone(), now)
            {
                self.process_transaction_events(events, now);
            }

            let t1 = self
                .config
                .timers
                .t1
                .clamp(Duration::from_millis(1), Duration::from_secs(60));
            if let Some(call) = self.calls.get_mut(call_id) {
                call.local_sdp = Some(offer_sdp.clone());
                if !offer_sdp.crypto.is_empty() {
                    call.local_crypto = offer_sdp.crypto;
                }
                if let Ok(Some(c)) = request.contact() {
                    call.remote_target = c.uri;
                }
                call.awaiting_ack_sdp = Some(PendingAckSdpKind::ReInvite);
                call.awaiting_ack = Some(Pending2xxAck {
                    response: resp,
                    next_send_at: now + t1,
                    interval: t1,
                    deadline: now + t1.saturating_mul(64),
                });
            }
            return;
        };

        let (local_rtp_port, sdp_sid, sdp_version, local_hold, prev_remote_hold) =
            match self.calls.get_mut(call_id) {
                Some(c) => {
                    c.sdp_version += 1;
                    (
                        c.local_rtp_port,
                        c.sdp_session_id.clone(),
                        c.sdp_version,
                        c.local_hold,
                        c.remote_hold,
                    )
                }
                None => return,
            };

        let srtp_mode = match self.config.effective_srtp_mode() {
            Ok(m) => m,
            Err(_) => {
                if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                    self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                }
                return;
            }
        };
        let local_candidates = match self.calls.get(call_id) {
            Some(c) if !c.local_crypto.is_empty() => c.local_crypto.clone(),
            _ => self.generate_sdes_candidates(call_id),
        };
        let negotiated_res = negotiate_offer_answer_with_srtp(
            &remote_sdp,
            &self.config.supported_codecs,
            &self.config.local_host,
            local_rtp_port,
            srtp_mode,
            &local_candidates,
        );
        let (mut answer_sdp, negotiated, negotiated_srtp) = match negotiated_res {
            Ok(triple) => triple,
            Err(_) => {
                if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                    self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                }
                return;
            }
        };
        answer_sdp.origin_username = self.config.username.clone();
        answer_sdp.session_id = sdp_sid;
        answer_sdp.session_version = sdp_version.to_string();
        answer_sdp.direction = constrain_answer_direction(remote_sdp.direction, local_hold);
        let new_remote_hold = is_remote_hold(remote_sdp.direction);

        let Ok(mut resp) = request.create_response(200, "OK") else {
            return;
        };
        resp = resp.with_body("application/sdp", answer_sdp.to_string().into_bytes());
        resp.headers.set(
            "Contact",
            NameAddr::new(self.config.contact_uri()).to_string(),
        );
        resp.headers.set("Allow", ALLOW_METHODS);
        resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
        self.apply_uas_session_timer_to_response(call_id, &request, &mut resp, now);
        self.ensure_response_to_tag(&mut resp, local_tag.as_deref());

        if let Ok(events) = self
            .transactions
            .send_server_response(&tx_id, resp.clone(), now)
        {
            self.process_transaction_events(events, now);
        }

        let t1 = self.config.timers.t1.max(Duration::from_millis(1));
        if let Some(call) = self.calls.get_mut(call_id) {
            call.local_sdp = Some(answer_sdp.clone());
            call.remote_sdp = Some(remote_sdp.clone());
            if !answer_sdp.crypto.is_empty() {
                call.local_crypto = answer_sdp.crypto.clone();
            }
            call.negotiated_srtp = negotiated_srtp;
            call.remote_hold = new_remote_hold;
            call.negotiated_codecs = negotiated.clone();
            if let Ok(Some(c)) = request.contact() {
                call.remote_target = c.uri;
            }
            call.awaiting_ack_sdp = None;
            call.awaiting_ack = Some(Pending2xxAck {
                response: resp,
                next_send_at: now + t1,
                interval: t1,
                deadline: now + t1.min(Duration::from_secs(60)).saturating_mul(64),
            });
        }

        if new_remote_hold != prev_remote_hold {
            self.pending_events.push_back(UaEvent::CallHoldChanged {
                call_id: call_id.to_string(),
                local_hold,
                remote_hold: new_remote_hold,
            });
        }

        self.pending_events.push_back(UaEvent::CallMediaUpdated {
            call_id: call_id.to_string(),
            local_sdp: answer_sdp,
            remote_sdp,
            negotiated_codecs: negotiated,
        });
    }

    fn on_inbound_cancel(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let top_via = request.top_via().ok();
        let cancel_branch = top_via.as_ref().and_then(|v| v.branch.clone());
        let cancel_sent_by = top_via
            .as_ref()
            .map(|v| crate::transaction::normalize_sent_by(&v.sent_by));
        let call_id = request.call_id().ok().map(str::to_string);

        let matching_call = call_id.and_then(|cid| {
            let call = self.calls.get(&cid)?;
            let inv_sent_by = call
                .inbound_invite_tx
                .as_ref()
                .and_then(|t| t.sent_by.as_deref());
            if call.direction == CallDirection::Inbound
                && matches!(call.state, CallState::Incoming | CallState::Ringing)
                && call.inbound_invite_branch.as_deref() == cancel_branch.as_deref()
                && inv_sent_by == cancel_sent_by.as_deref()
            {
                Some((cid, call.local_tag.clone()))
            } else {
                None
            }
        });

        let (resp_code, dialog_tag) = if let Some((_, ref tag)) = matching_call {
            ((200, "OK"), Some(tag.clone()))
        } else {
            ((481, "Call/Transaction Does Not Exist"), None)
        };
        if let Ok(resp) = request.create_response(resp_code.0, resp_code.1) {
            self.send_uas_response(&tx_id, resp, dialog_tag.as_deref(), now);
        }

        if let Some((cid, local_tag)) = matching_call {
            if let Some(call) = self.calls.get_mut(&cid) {
                call.pending_reliable_1xx = None;
                if let (Some(inv_tx), Some(inv_req)) =
                    (&call.inbound_invite_tx, &call.inbound_invite_req)
                {
                    if let Ok(mut r487) = inv_req.create_response(487, "Request Terminated") {
                        if let Ok(mut to) = r487.to() {
                            to.tag = Some(local_tag);
                            r487.headers.set("To", to.to_string());
                        }
                        let _ = self.transactions.send_server_response(inv_tx, r487, now);
                    }
                }
            }
            self.terminate_call(&cid, Some(487), "Request Terminated".to_string());
        }
    }

    fn on_inbound_bye(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = request.call_id().ok().map(str::to_string);
        let to_tag = request.to().ok().and_then(|t| t.tag);
        let from_tag = request.from().ok().and_then(|f| f.tag);
        let req_cseq = request.cseq().ok().map(|c| c.seq);

        enum ByeAction {
            Accept { cid: String, local_tag: String },
            OutOfOrder500(String),
            NotFound481,
        }

        let action = if let Some(cid) = call_id {
            if let Some(call) = self.calls.get_mut(&cid) {
                let to_ok = to_tag.as_deref().is_none_or(|tt| tt == call.local_tag);
                let from_ok = match (&call.remote_tag, &from_tag) {
                    (Some(expected), Some(actual)) => expected == actual,
                    _ => true,
                };
                if to_ok && from_ok {
                    if let (Some(rc), Some(prev)) = (req_cseq, call.remote_cseq) {
                        if rc <= prev {
                            ByeAction::OutOfOrder500(call.local_tag.clone())
                        } else {
                            call.remote_cseq = Some(rc);
                            ByeAction::Accept {
                                cid,
                                local_tag: call.local_tag.clone(),
                            }
                        }
                    } else {
                        if let Some(rc) = req_cseq {
                            call.remote_cseq = Some(rc);
                        }
                        ByeAction::Accept {
                            cid,
                            local_tag: call.local_tag.clone(),
                        }
                    }
                } else {
                    ByeAction::NotFound481
                }
            } else {
                ByeAction::NotFound481
            }
        } else {
            ByeAction::NotFound481
        };

        match action {
            ByeAction::Accept { cid, local_tag } => {
                let reason_header = extract_reason_header(&request.headers);
                if let Ok(resp) = request.create_response(200, "OK") {
                    self.send_uas_response(&tx_id, resp, Some(&local_tag), now);
                }
                if let Some(call) = self.calls.get_mut(&cid) {
                    call.pending_reliable_1xx = None;
                    call.pending_glare_retry = None;
                    if call.direction == CallDirection::Inbound
                        && matches!(call.state, CallState::Incoming | CallState::Ringing)
                    {
                        if let (Some(inv_tx), Some(inv_req)) = (
                            call.inbound_invite_tx.take(),
                            call.inbound_invite_req.take(),
                        ) {
                            if let Ok(mut r487) = inv_req.create_response(487, "Request Terminated")
                            {
                                if let Ok(mut to) = r487.to() {
                                    to.tag = Some(local_tag.clone());
                                    r487.headers.set("To", to.to_string());
                                }
                                let _ = self.transactions.send_server_response(&inv_tx, r487, now);
                            }
                        }
                    }
                }
                self.terminate_call_with_reason(
                    &cid,
                    Some(200),
                    "Remote hangup".to_string(),
                    reason_header,
                );
            }
            ByeAction::OutOfOrder500(local_tag) => {
                if let Ok(resp) = request.create_response(500, "Server Internal Error") {
                    self.send_uas_response(&tx_id, resp, Some(&local_tag), now);
                }
            }
            ByeAction::NotFound481 => {
                if let Ok(resp) = request.create_response(481, "Call/Transaction Does Not Exist") {
                    self.send_uas_response(&tx_id, resp, None, now);
                }
            }
        }
    }

    fn check_in_dialog_request(&mut self, request: &SipRequest) -> InDialogCheck {
        let Ok(call_id) = request.call_id().map(str::to_string) else {
            return InDialogCheck::NotFound481;
        };
        let to_tag = request.to().ok().and_then(|t| t.tag);
        let from_tag = request.from().ok().and_then(|f| f.tag);
        let req_cseq = request.cseq().ok().map(|c| c.seq);

        let Some(call) = self.calls.get_mut(&call_id) else {
            return InDialogCheck::NotFound481;
        };
        let to_ok = to_tag.as_deref().is_some_and(|tt| tt == call.local_tag);
        let from_ok = match (&call.remote_tag, &from_tag) {
            (Some(expected), Some(actual)) => expected == actual,
            (None, _) => true,
            (Some(_), None) => false,
        };
        if !to_ok || !from_ok {
            return InDialogCheck::NotFound481;
        }
        if let (Some(rc), Some(prev)) = (req_cseq, call.remote_cseq) {
            if rc <= prev {
                return InDialogCheck::OutOfOrder500;
            }
            call.remote_cseq = Some(rc);
        } else if let Some(rc) = req_cseq {
            call.remote_cseq = Some(rc);
        }
        InDialogCheck::Valid(call_id)
    }

    fn send_simple_server_response(
        &mut self,
        tx_id: &TransactionId,
        request: &SipRequest,
        code: u16,
        reason: &str,
        now: Instant,
    ) {
        if let Ok(resp) = request.create_response(code, reason) {
            let dialog_tag = request
                .call_id()
                .ok()
                .and_then(|cid| self.calls.get(cid).map(|c| c.local_tag.clone()));
            self.send_uas_response(tx_id, resp, dialog_tag.as_deref(), now);
        }
    }

    fn on_inbound_update(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = match self.check_in_dialog_request(&request) {
            InDialogCheck::Valid(cid) => cid,
            InDialogCheck::OutOfOrder500 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    500,
                    "Server Internal Error",
                    now,
                );
                return;
            }
            InDialogCheck::NotFound481 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    481,
                    "Call/Transaction Does Not Exist",
                    now,
                );
                return;
            }
        };

        let local_tag = self.calls.get(&call_id).map(|c| c.local_tag.clone());
        if let Some(se_raw) = request.headers.get("Session-Expires") {
            if let Ok(se) = SessionExpires::parse(se_raw) {
                if se.delta_seconds < self.config.min_se_secs {
                    if let Ok(mut resp) = request.create_response(422, "Session Interval Too Small")
                    {
                        resp.headers
                            .set("Min-SE", self.config.min_se_secs.max(1).to_string());
                        self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
                    }
                    return;
                }
            }
        }

        if request.body.is_empty() {
            let Ok(mut resp) = request.create_response(200, "OK") else {
                return;
            };
            resp.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            resp.headers.set("Allow", ALLOW_METHODS);
            resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
            self.apply_uas_session_timer_to_response(&call_id, &request, &mut resp, now);
            self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);
            return;
        }

        // RFC 3311 §5.2 / RFC 6337: reject UPDATE carrying SDP with 491 if an offer/answer is already pending.
        let sdp_glare = self.calls.get(&call_id).is_some_and(|c| {
            c.state == CallState::ReInviting
                || c.active_update_req
                    .as_ref()
                    .is_some_and(|r| !r.body.is_empty())
                || c.pending_reliable_1xx
                    .as_ref()
                    .is_some_and(|p| !p.response.body.is_empty())
                || (c.direction == CallDirection::Outbound
                    && c.state == CallState::Calling
                    && c.remote_sdp.is_none())
        });
        if sdp_glare {
            self.send_simple_server_response(&tx_id, &request, 491, "Request Pending", now);
            return;
        }

        let Some(remote_sdp) = parse_optional_sdp(&request.body) else {
            self.send_simple_server_response(&tx_id, &request, 488, "Not Acceptable Here", now);
            return;
        };

        let (local_rtp_port, sdp_sid, sdp_version, local_hold, prev_remote_hold) =
            match self.calls.get_mut(&call_id) {
                Some(c) => {
                    c.sdp_version += 1;
                    (
                        c.local_rtp_port,
                        c.sdp_session_id.clone(),
                        c.sdp_version,
                        c.local_hold,
                        c.remote_hold,
                    )
                }
                None => return,
            };

        let Ok(srtp_mode) = self.config.effective_srtp_mode() else {
            self.send_simple_server_response(&tx_id, &request, 488, "Not Acceptable Here", now);
            return;
        };
        let local_candidates = match self.calls.get(&call_id) {
            Some(c) if !c.local_crypto.is_empty() => c.local_crypto.clone(),
            _ => self.generate_sdes_candidates(&call_id),
        };
        let Ok((mut answer_sdp, negotiated, negotiated_srtp)) = negotiate_offer_answer_with_srtp(
            &remote_sdp,
            &self.config.supported_codecs,
            &self.config.local_host,
            local_rtp_port,
            srtp_mode,
            &local_candidates,
        ) else {
            self.send_simple_server_response(&tx_id, &request, 488, "Not Acceptable Here", now);
            return;
        };
        answer_sdp.origin_username = self.config.username.clone();
        answer_sdp.session_id = sdp_sid;
        answer_sdp.session_version = sdp_version.to_string();
        answer_sdp.direction = constrain_answer_direction(remote_sdp.direction, local_hold);
        let new_remote_hold = is_remote_hold(remote_sdp.direction);

        let Ok(mut resp) = request.create_response(200, "OK") else {
            return;
        };
        resp = resp.with_body("application/sdp", answer_sdp.to_string().into_bytes());
        resp.headers.set(
            "Contact",
            NameAddr::new(self.config.contact_uri()).to_string(),
        );
        resp.headers.set("Allow", ALLOW_METHODS);
        resp.headers.set("Supported", SUPPORTED_EXTENSIONS);
        self.apply_uas_session_timer_to_response(&call_id, &request, &mut resp, now);
        self.send_uas_response(&tx_id, resp, local_tag.as_deref(), now);

        if let Some(call) = self.calls.get_mut(&call_id) {
            call.local_sdp = Some(answer_sdp.clone());
            call.remote_sdp = Some(remote_sdp.clone());
            if !answer_sdp.crypto.is_empty() {
                call.local_crypto = answer_sdp.crypto.clone();
            }
            call.negotiated_srtp = negotiated_srtp;
            call.remote_hold = new_remote_hold;
            call.negotiated_codecs = negotiated.clone();
            if let Ok(Some(c)) = request.contact() {
                call.remote_target = c.uri;
            }
        }

        if new_remote_hold != prev_remote_hold {
            self.pending_events.push_back(UaEvent::CallHoldChanged {
                call_id: call_id.clone(),
                local_hold,
                remote_hold: new_remote_hold,
            });
        }
        self.pending_events.push_back(UaEvent::CallMediaUpdated {
            call_id,
            local_sdp: answer_sdp,
            remote_sdp,
            negotiated_codecs: negotiated,
        });
    }

    fn on_inbound_prack(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = match self.check_in_dialog_request(&request) {
            InDialogCheck::Valid(cid) => cid,
            InDialogCheck::OutOfOrder500 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    500,
                    "Server Internal Error",
                    now,
                );
                return;
            }
            InDialogCheck::NotFound481 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    481,
                    "Call/Transaction Does Not Exist",
                    now,
                );
                return;
            }
        };

        let Some(rack) = request
            .headers
            .get("RAck")
            .and_then(|v| RAck::parse(v).ok())
        else {
            self.send_simple_server_response(&tx_id, &request, 400, "Missing or Invalid RAck", now);
            return;
        };

        let valid_rack = self.calls.get_mut(&call_id).is_some_and(|c| {
            let matches_rseq = c
                .pending_reliable_1xx
                .as_ref()
                .is_some_and(|p| p.rseq == rack.rseq)
                || (c.local_rseq > 0 && rack.rseq <= c.local_rseq);
            let expected_inv_cseq = c
                .pending_reliable_1xx
                .as_ref()
                .map(|p| p.invite_cseq)
                .or_else(|| {
                    c.inbound_invite_req
                        .as_ref()
                        .and_then(|r| r.cseq().ok())
                        .map(|cs| cs.seq)
                });
            if matches_rseq && rack.method == Method::Invite && expected_inv_cseq == Some(rack.cseq)
            {
                if c.pending_reliable_1xx
                    .as_ref()
                    .is_some_and(|p| p.rseq == rack.rseq)
                {
                    c.pending_reliable_1xx = None;
                }
                if let Ok(Some(contact)) = request.contact() {
                    c.remote_target = contact.uri;
                }
                true
            } else {
                false
            }
        });

        if !valid_rack {
            self.send_simple_server_response(
                &tx_id,
                &request,
                481,
                "Call/Transaction Does Not Exist",
                now,
            );
            return;
        }

        if let Ok(mut resp) = request.create_response(200, "OK") {
            resp.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            let dialog_tag = self.calls.get(&call_id).map(|c| c.local_tag.clone());
            self.send_uas_response(&tx_id, resp, dialog_tag.as_deref(), now);
        }
    }

    fn on_inbound_refer(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = match self.check_in_dialog_request(&request) {
            InDialogCheck::Valid(cid) => cid,
            InDialogCheck::OutOfOrder500 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    500,
                    "Server Internal Error",
                    now,
                );
                return;
            }
            InDialogCheck::NotFound481 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    481,
                    "Call/Transaction Does Not Exist",
                    now,
                );
                return;
            }
        };

        let Some(refer_to) = request.headers.get("Refer-To").and_then(|raw| {
            NameAddr::parse(raw)
                .map(|a| a.uri)
                .or_else(|_| SipUri::parse(raw))
                .ok()
        }) else {
            self.send_simple_server_response(&tx_id, &request, 400, "Invalid Refer-To", now);
            return;
        };

        let referred_by = request
            .headers
            .get("Referred-By")
            .and_then(|raw| NameAddr::parse(raw).ok());
        let replaces = refer_to
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("replaces"))
            .and_then(|(_, val)| ReplacesHeader::parse(val).ok());

        if let Ok(mut resp) = request.create_response(202, "Accepted") {
            resp.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            let dialog_tag = self.calls.get(&call_id).map(|c| c.local_tag.clone());
            self.send_uas_response(&tx_id, resp, dialog_tag.as_deref(), now);
        }

        // RFC 3515 §2.4.5: immediately send initial NOTIFY (100 Trying, active) for implicit REFER subscription.
        let _ = self.notify_refer_status(&call_id, 100, "Trying", false, now);

        self.pending_events
            .push_back(UaEvent::CallTransferRequested {
                call_id,
                refer_to,
                referred_by,
                replaces,
            });
    }

    fn on_inbound_notify(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = match self.check_in_dialog_request(&request) {
            InDialogCheck::Valid(cid) => cid,
            InDialogCheck::OutOfOrder500 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    500,
                    "Server Internal Error",
                    now,
                );
                return;
            }
            InDialogCheck::NotFound481 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    481,
                    "Call/Transaction Does Not Exist",
                    now,
                );
                return;
            }
        };

        self.send_simple_server_response(&tx_id, &request, 200, "OK", now);

        let is_refer = request
            .headers
            .get("Event")
            .is_some_and(|e| e.trim().to_ascii_lowercase().starts_with("refer"))
            || request
                .headers
                .get("Content-Type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("sipfrag"));

        if is_refer {
            let (status_code, reason) = parse_sipfrag_status(&request.body);
            let terminated = request
                .headers
                .get("Subscription-State")
                .is_some_and(|s| s.to_ascii_lowercase().contains("terminated"));
            self.pending_events.push_back(UaEvent::TransferNotify {
                call_id,
                status_code,
                reason,
                terminated,
            });
        }
    }

    fn on_inbound_info(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        let call_id = match self.check_in_dialog_request(&request) {
            InDialogCheck::Valid(cid) => cid,
            InDialogCheck::OutOfOrder500 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    500,
                    "Server Internal Error",
                    now,
                );
                return;
            }
            InDialogCheck::NotFound481 => {
                self.send_simple_server_response(
                    &tx_id,
                    &request,
                    481,
                    "Call/Transaction Does Not Exist",
                    now,
                );
                return;
            }
        };

        let media_type = request
            .headers
            .get("Content-Type")
            .and_then(|v| v.split(';').next())
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();

        if media_type != "application/dtmf-relay" && media_type != "application/dtmf" {
            self.send_simple_server_response(&tx_id, &request, 415, "Unsupported Media Type", now);
            return;
        }

        let Some((digit, duration_ms)) = parse_sip_info_dtmf(&request.body, &media_type) else {
            self.send_simple_server_response(&tx_id, &request, 400, "Bad DTMF Payload", now);
            return;
        };

        self.send_simple_server_response(&tx_id, &request, 200, "OK", now);
        self.pending_events.push_back(UaEvent::DtmfReceived {
            call_id,
            digit,
            duration_ms,
        });
    }

    fn on_ack_for_2xx(&mut self, ack: SipRequest, now: Instant) {
        let Ok(cid) = ack.call_id().map(str::to_string) else {
            return;
        };
        let ack_cseq = ack.cseq().ok().map(|c| c.seq);
        let ack_to_tag = ack.to().ok().and_then(|t| t.tag);
        let completed_kind = if let Some(call) = self.calls.get_mut(&cid) {
            let expected_cseq = call
                .awaiting_ack
                .as_ref()
                .and_then(|p| p.response.cseq().ok().map(|c| c.seq));
            let to_ok = ack_to_tag.as_deref() == Some(call.local_tag.as_str());
            if to_ok && expected_cseq.is_some() && ack_cseq == expected_cseq {
                call.awaiting_ack = None;
                call.awaiting_ack_sdp.take()
            } else {
                None
            }
        } else {
            None
        };

        let Some(ack_kind) = completed_kind else {
            return;
        };

        struct DelayedAckSdpOutcome {
            local_sdp: SdpSession,
            remote_sdp: SdpSession,
            negotiated_codecs: Vec<RtpCodec>,
            prev_remote_hold: bool,
            new_remote_hold: bool,
            local_hold: bool,
        }

        // Complete RFC 3261 §13.2.1 delayed offer negotiation using the SDP answer in ACK.
        let sdp_result: Result<DelayedAckSdpOutcome, ()> = (|| {
            let remote_sdp = parse_optional_sdp(&ack.body).ok_or(())?;
            if remote_sdp.audio_port == 0 {
                return Err(());
            }
            let local_sdp = self
                .calls
                .get(&cid)
                .and_then(|c| c.local_sdp.clone())
                .ok_or(())?;
            let effective_srtp = self
                .config
                .effective_srtp_mode()
                .unwrap_or(SrtpMode::Disabled);
            let srtp = resolve_outbound_answer_srtp(&local_sdp, &remote_sdp, effective_srtp)
                .map_err(|_| ())?;
            let has_common_audio = remote_sdp.codecs.iter().any(|ac| {
                !ac.is_comfort_noise()
                    && !ac.encoding_name.eq_ignore_ascii_case("telephone-event")
                    && local_sdp.codecs.iter().any(|lc| {
                        lc.encoding_name.eq_ignore_ascii_case(&ac.encoding_name)
                            && lc.clock_rate == ac.clock_rate
                    })
            });
            if !has_common_audio {
                return Err(());
            }
            let negotiated = intersect_answer_codecs(&local_sdp, &remote_sdp);
            let Some(call) = self.calls.get_mut(&cid) else {
                return Err(());
            };
            if let Some(NegotiatedSrtp::Sdes {
                suite,
                local_key_salt,
                ..
            }) = &srtp
            {
                if let Some(ans_c) = remote_sdp.crypto.first() {
                    call.local_crypto =
                        vec![SdesCryptoAttr::new(ans_c.tag, *suite, *local_key_salt)];
                }
            }
            let prev_remote_hold = call.remote_hold;
            let new_remote_hold = is_remote_hold(remote_sdp.direction);
            call.negotiated_srtp = srtp;
            call.remote_sdp = Some(remote_sdp.clone());
            call.remote_hold = new_remote_hold;
            call.negotiated_codecs = negotiated.clone();
            Ok(DelayedAckSdpOutcome {
                local_sdp,
                remote_sdp,
                negotiated_codecs: negotiated,
                prev_remote_hold,
                new_remote_hold,
                local_hold: call.local_hold,
            })
        })();

        match sdp_result {
            Ok(DelayedAckSdpOutcome {
                local_sdp,
                remote_sdp,
                negotiated_codecs,
                prev_remote_hold,
                new_remote_hold,
                local_hold,
            }) => match ack_kind {
                PendingAckSdpKind::InitialInvite => {
                    self.pending_events.push_back(UaEvent::CallEstablished {
                        call_id: cid.clone(),
                        local_sdp,
                        remote_sdp,
                        negotiated_codecs,
                    });
                    if new_remote_hold {
                        self.pending_events.push_back(UaEvent::CallHoldChanged {
                            call_id: cid,
                            local_hold,
                            remote_hold: new_remote_hold,
                        });
                    }
                }
                PendingAckSdpKind::ReInvite => {
                    self.pending_events.push_back(UaEvent::CallMediaUpdated {
                        call_id: cid.clone(),
                        local_sdp,
                        remote_sdp,
                        negotiated_codecs,
                    });
                    if new_remote_hold != prev_remote_hold {
                        self.pending_events.push_back(UaEvent::CallHoldChanged {
                            call_id: cid,
                            local_hold,
                            remote_hold: new_remote_hold,
                        });
                    }
                }
            },
            Err(()) => {
                let reason = ReasonHeader::sip(488, "Not Acceptable Here");
                let _ = self.send_bye_for_call_with_reason(&cid, None, Some(reason.clone()), now);
                self.terminate_call_with_reason(
                    &cid,
                    Some(488),
                    "Invalid or missing SDP answer in ACK".to_string(),
                    Some(reason),
                );
            }
        }
    }

    fn on_client_provisional(&mut self, tx_id: TransactionId, response: SipResponse, now: Instant) {
        let Some((call_id, kind)) = self.tx_to_call.get(&tx_id).cloned() else {
            return;
        };
        if !matches!(kind, CallTxKind::Invite) {
            return;
        }
        let mut prack_params: Option<(u32, u32)> = None;
        {
            let Some(call) = self.calls.get_mut(&call_id) else {
                return;
            };
            if call.active_invite_tx.as_ref() != Some(&tx_id) {
                return;
            }
            call.received_provisional = true;

            if let Ok(to) = response.to() {
                if let Some(tag) = to.tag {
                    call.remote_tag = Some(tag);
                }
            }
            if call.route_set.is_empty() {
                let routes = extract_record_routes(&response.headers, true);
                if !routes.is_empty() {
                    call.route_set = routes;
                }
            }
            if let Ok(Some(contact)) = response.contact() {
                call.remote_target = contact.uri;
            }

            if response.status_code > 100 {
                let early_sdp = parse_optional_sdp(&response.body);
                if call.state == CallState::Calling {
                    call.state = CallState::Ringing;
                }
                if let Some(ref sdp) = early_sdp {
                    call.remote_sdp = Some(sdp.clone());
                    call.remote_hold = is_remote_hold(sdp.direction);
                    let effective_srtp = self
                        .config
                        .effective_srtp_mode()
                        .unwrap_or(SrtpMode::Disabled);
                    if let Some(ref local_sdp) = call.local_sdp {
                        call.negotiated_codecs = intersect_answer_codecs(local_sdp, sdp);
                        if let Ok(srtp) =
                            resolve_outbound_answer_srtp(local_sdp, sdp, effective_srtp)
                        {
                            if let Some(NegotiatedSrtp::Sdes {
                                suite,
                                local_key_salt,
                                ..
                            }) = &srtp
                            {
                                if let Some(ans_c) = sdp.crypto.first() {
                                    call.local_crypto = vec![SdesCryptoAttr::new(
                                        ans_c.tag,
                                        *suite,
                                        *local_key_salt,
                                    )];
                                }
                            }
                            call.negotiated_srtp = srtp;
                        }
                    } else if let Ok((_, negotiated, srtp)) = negotiate_offer_answer_with_srtp(
                        sdp,
                        &self.config.supported_codecs,
                        &self.config.local_host,
                        call.local_rtp_port,
                        effective_srtp,
                        &call.local_crypto,
                    ) {
                        call.negotiated_codecs = negotiated;
                        call.negotiated_srtp = srtp;
                    }
                }

                // RFC 3262 §4: auto-acknowledge reliable 1xx responses carrying RSeq (with To-tag).
                if call.remote_tag.is_some() {
                    if let Some(rseq) = response
                        .headers
                        .get("RSeq")
                        .and_then(|v| v.trim().parse::<u32>().ok())
                    {
                        if rseq > call.last_remote_rseq.unwrap_or(0) {
                            call.last_remote_rseq = Some(rseq);
                            let inv_cseq = response.cseq().map(|c| c.seq).unwrap_or(1);
                            prack_params = Some((rseq, inv_cseq));
                        }
                    }
                }

                self.pending_events.push_back(UaEvent::CallRinging {
                    call_id: call_id.clone(),
                    status_code: response.status_code,
                    early_sdp,
                });
            }
        }

        if let Some((rseq, inv_cseq)) = prack_params {
            if let Err(err) = self.send_prack_for_call(&call_id, rseq, inv_cseq, now) {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
            }
        }

        // Send deferred CANCEL as soon as any 1xx provisional response arrives (RFC 3261 §9.1).
        if self.calls.get(&call_id).is_some_and(|c| c.pending_cancel) {
            let reason = self
                .calls
                .get_mut(&call_id)
                .and_then(|c| c.pending_cancel_reason.take());
            if let Err(err) = self.send_cancel_for_call_with_reason(&call_id, reason, now) {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
            }
        }
    }

    fn send_prack_for_call(
        &mut self,
        call_id: &str,
        rseq: u32,
        invite_cseq: u32,
        now: Instant,
    ) -> Result<(), SipError> {
        let branch = self.next_branch();
        let req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.local_cseq += 1;

            let mut req = SipRequest::new(Method::Prack, call.remote_target.clone());
            req.headers.add(
                "Via",
                Via::new(
                    self.config.transport.via_proto(),
                    format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                    branch,
                )
                .to_string(),
            );
            for route in &call.route_set {
                req.headers
                    .add("Route", NameAddr::new(route.clone()).to_string());
            }
            req.headers.set(
                "From",
                call.local_name_addr(self.config.display_name.as_deref())
                    .to_string(),
            );
            req.headers.set("To", call.remote_name_addr().to_string());
            req.headers.set("Call-ID", call.call_id.clone());
            req.headers.set(
                "CSeq",
                CSeq::new(call.local_cseq, Method::Prack).to_string(),
            );
            req.headers.set(
                "RAck",
                RAck::new(rseq, invite_cseq, Method::Invite).to_string(),
            );
            req.headers.set("Max-Forwards", "70");
            req.headers.set(
                "Contact",
                NameAddr::new(self.config.contact_uri()).to_string(),
            );
            req
        };

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Prack));
        Ok(())
    }

    fn on_client_final(&mut self, tx_id: TransactionId, response: SipResponse, now: Instant) {
        if self.reg_session.active_tx.as_ref() == Some(&tx_id) {
            self.handle_register_final(response, now);
            return;
        }

        let Some((call_id, kind)) = self.tx_to_call.remove(&tx_id) else {
            return;
        };

        match kind {
            CallTxKind::Invite | CallTxKind::ReInvite => {
                self.handle_invite_final(
                    &call_id,
                    &tx_id,
                    matches!(kind, CallTxKind::ReInvite),
                    response,
                    now,
                );
            }
            CallTxKind::Cancel | CallTxKind::Prack | CallTxKind::Notify => {}
            CallTxKind::Update => {
                self.handle_update_final(&call_id, &tx_id, response, now);
            }
            CallTxKind::Refer => {
                self.handle_refer_final(&call_id, response, now);
            }
            CallTxKind::Info => {
                self.handle_info_final(&call_id, response, now);
            }
            CallTxKind::Bye => {
                self.handle_bye_final(&call_id, &tx_id, response, now);
            }
        }
    }

    fn handle_register_final(&mut self, response: SipResponse, now: Instant) {
        self.reg_session.active_tx = None;
        let code = response.status_code;

        if (200..300).contains(&code) {
            if self.reg_session.pending_expires == 0 {
                self.reg_session.auth.reset();
                self.reg_session.interval_too_brief_retried = false;
                self.set_registration_state(RegistrationState::Unregistered);
                return;
            }
            let local_contact = self.config.contact_uri();
            let expires = extract_register_expires(&response, &local_contact)
                .unwrap_or(self.reg_session.pending_expires);
            if expires == 0 {
                self.reg_session.auth.reset();
                self.reg_session.interval_too_brief_retried = false;
                self.set_registration_state(RegistrationState::Unregistered);
                return;
            }
            let refresh_secs = ((expires as u64) * 4 / 5).max(1);
            let refresh_at = now + Duration::from_secs(refresh_secs);
            let expires_at = now + Duration::from_secs(expires as u64);
            self.reg_session.auth.reset();
            self.reg_session.interval_too_brief_retried = false;
            self.set_registration_state(RegistrationState::Registered {
                expires_secs: expires,
                refresh_at,
                expires_at,
            });
            return;
        }

        if code == 423
            && self.reg_session.pending_expires > 0
            && !self.reg_session.interval_too_brief_retried
        {
            if let Some(min_exp) = response
                .headers
                .get("Min-Expires")
                .and_then(|v| v.split(';').next()?.trim().parse::<u32>().ok())
                .filter(|v| *v > 0)
            {
                self.reg_session.interval_too_brief_retried = true;
                self.reg_session.auth.reset_attempts();
                let clamped_exp = min_exp.min(86_400);
                if let Err(err) =
                    self.start_register_with_expires(clamped_exp, AuthAction::Keep, now)
                {
                    self.set_registration_state(RegistrationState::Failed {
                        status_code: Some(code),
                        reason: err.to_string(),
                    });
                }
                return;
            }
        }

        if code == 401 || code == 407 {
            let attempts = self.reg_session.auth.attempts_for(code);
            if let Ok((_hdr_name, hdr_val, stale)) = self.compute_auth_header(
                &response,
                &Method::Register,
                &self.config.registrar_uri.to_string(),
            ) {
                let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                if can_retry {
                    let exp = self.reg_session.pending_expires;
                    if let Err(err) =
                        self.start_register_with_expires(exp, AuthAction::Retry(code, hdr_val), now)
                    {
                        self.set_registration_state(RegistrationState::Failed {
                            status_code: Some(code),
                            reason: err.to_string(),
                        });
                    }
                    return;
                }
            }
        }

        self.set_registration_state(RegistrationState::Failed {
            status_code: Some(code),
            reason: response.reason_phrase,
        });
    }

    fn handle_invite_final(
        &mut self,
        call_id: &str,
        tx_id: &TransactionId,
        is_reinvite: bool,
        response: SipResponse,
        now: Instant,
    ) {
        let Some(existing_active_tx) = self
            .calls
            .get(call_id)
            .and_then(|c| c.active_invite_tx.clone())
        else {
            return;
        };
        if &existing_active_tx != tx_id {
            return;
        }

        let code = response.status_code;
        if (200..300).contains(&code) {
            let mut cancelling_race = false;
            let mut established_payload = None;
            let mut hold_change_payload = None;

            if let Some(call) = self.calls.get_mut(call_id) {
                call.active_invite_tx = None;
                call.active_invite_req = None;
                call.pending_cancel = false;
                call.pending_cancel_reason = None;
                call.cancel_deadline = None;
                call.pending_reinvite_rollback = None;
                call.pending_glare_retry = None;
                call.glare_attempts = 0;
                call.session_timer_retries = 0;

                if let Ok(to) = response.to() {
                    if let Some(tag) = to.tag {
                        call.remote_tag = Some(tag);
                    }
                }
                if !is_reinvite {
                    call.route_set = extract_record_routes(&response.headers, true);
                }
                if let Ok(Some(contact)) = response.contact() {
                    call.remote_target = contact.uri;
                }

                let cseq_num = response.cseq().map(|c| c.seq).unwrap_or(call.local_cseq);

                if call.state == CallState::Cancelling {
                    cancelling_race = true;
                } else if let Some(remote_sdp) = parse_optional_sdp(&response.body) {
                    if let Some(local_sdp) = call.local_sdp.clone() {
                        let effective_srtp = self
                            .config
                            .effective_srtp_mode()
                            .unwrap_or(SrtpMode::Disabled);
                        match resolve_outbound_answer_srtp(&local_sdp, &remote_sdp, effective_srtp)
                        {
                            Ok(srtp) => {
                                if let Some(NegotiatedSrtp::Sdes {
                                    suite,
                                    local_key_salt,
                                    ..
                                }) = &srtp
                                {
                                    if let Some(ans_c) = remote_sdp.crypto.first() {
                                        call.local_crypto = vec![SdesCryptoAttr::new(
                                            ans_c.tag,
                                            *suite,
                                            *local_key_salt,
                                        )];
                                    }
                                }
                                call.negotiated_srtp = srtp;
                                let negotiated = intersect_answer_codecs(&local_sdp, &remote_sdp);
                                let prev_remote_hold = call.remote_hold;
                                let new_remote_hold = is_remote_hold(remote_sdp.direction);
                                call.remote_sdp = Some(remote_sdp.clone());
                                call.remote_hold = new_remote_hold;
                                call.negotiated_codecs = negotiated.clone();
                                call.state = CallState::Established;
                                established_payload = Some((local_sdp, remote_sdp, negotiated));
                                if (is_reinvite && new_remote_hold != prev_remote_hold)
                                    || (!is_reinvite && new_remote_hold)
                                {
                                    hold_change_payload = Some((call.local_hold, new_remote_hold));
                                }
                            }
                            Err(err) => {
                                self.pending_events
                                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
                                cancelling_race = true;
                            }
                        }
                    }
                } else if is_reinvite {
                    call.state = CallState::Established;
                    if let (Some(local_sdp), Some(remote_sdp)) =
                        (call.local_sdp.clone(), call.remote_sdp.clone())
                    {
                        established_payload =
                            Some((local_sdp, remote_sdp, call.negotiated_codecs.clone()));
                    }
                } else if let (Some(local_sdp), Some(remote_sdp)) =
                    (call.local_sdp.clone(), call.remote_sdp.clone())
                {
                    // Bodyless 200 OK after early media answer (e.g. reliable 183 + PRACK).
                    let effective_srtp = self
                        .config
                        .effective_srtp_mode()
                        .unwrap_or(SrtpMode::Disabled);
                    if effective_srtp == SrtpMode::SdesRequired && call.negotiated_srtp.is_none() {
                        self.pending_events.push_back(UaEvent::ProtocolWarning(
                            "bodyless 200 OK to INVITE lacked required SDES SRTP negotiation"
                                .to_string(),
                        ));
                        cancelling_race = true;
                    } else {
                        call.state = CallState::Established;
                        established_payload =
                            Some((local_sdp, remote_sdp, call.negotiated_codecs.clone()));
                    }
                } else {
                    // Initial INVITE received 200 OK without any SDP answer in dialog or 18x.
                    self.pending_events.push_back(UaEvent::ProtocolWarning(
                        "200 OK to INVITE missing SDP answer".to_string(),
                    ));
                    cancelling_race = true;
                }

                let ack_snapshot = call.clone();
                let ack = self.build_ack_for_2xx(&ack_snapshot, cseq_num);
                if let Some(call_mut) = self.calls.get_mut(call_id) {
                    call_mut.last_ack_for_2xx = Some(ack.clone());
                    call_mut.invite_auth.reset();
                }
                let _ = self.transactions.send_ack_for_2xx(ack);
            }

            if !cancelling_race {
                self.apply_uac_session_timer_from_response(call_id, &response, now);
            }

            if cancelling_race {
                // RFC 3261 §15: 200 OK arrived before CANCEL took effect -> ACK then immediately BYE.
                let _ = self.send_bye_for_call(call_id, None, now);
                return;
            }

            if let Some((local_sdp, remote_sdp, negotiated_codecs)) = established_payload {
                if is_reinvite {
                    self.pending_events.push_back(UaEvent::CallMediaUpdated {
                        call_id: call_id.to_string(),
                        local_sdp,
                        remote_sdp,
                        negotiated_codecs,
                    });
                } else {
                    self.pending_events.push_back(UaEvent::CallEstablished {
                        call_id: call_id.to_string(),
                        local_sdp,
                        remote_sdp,
                        negotiated_codecs,
                    });
                }
            }
            if let Some((local_hold, remote_hold)) = hold_change_payload {
                self.pending_events.push_back(UaEvent::CallHoldChanged {
                    call_id: call_id.to_string(),
                    local_hold,
                    remote_hold,
                });
            }
            return;
        }

        // RFC 4028 §6: handle 422 Session Interval Too Small by bumping Session-Expires >= Min-SE and retrying.
        if code == 422 {
            let can_retry = self.calls.get(call_id).is_some_and(|c| {
                c.session_timer_retries < MAX_SESSION_TIMER_RETRIES && !c.pending_cancel
            });
            if can_retry {
                let cur_min_se = self
                    .calls
                    .get(call_id)
                    .map_or(self.config.min_se_secs, |c| c.min_se_secs);
                let remote_min_se = response
                    .headers
                    .get("Min-SE")
                    .and_then(|v| v.split(';').next()?.trim().parse::<u32>().ok())
                    .unwrap_or_else(|| cur_min_se.max(1800));
                let new_se = remote_min_se.max(cur_min_se).max(90);
                let branch = self.next_branch();
                let config_ref = &self.config;
                let next_req = if let Some(call) = self.calls.get_mut(call_id) {
                    call.min_se_secs = call.min_se_secs.max(new_se);
                    call.session_expires_secs = Some(new_se);
                    call.session_timer_retries = call.session_timer_retries.saturating_add(1);
                    call.invite_auth.reset_attempts();
                    call.local_cseq += 1;
                    call.received_provisional = false;
                    call.local_sdp.clone().map(|sdp| {
                        if is_reinvite {
                            Self::build_in_dialog_invite(config_ref, call, &branch, &sdp)
                        } else {
                            Self::build_invite_request(config_ref, call, &branch, &sdp)
                        }
                    })
                } else {
                    None
                };
                if let Some(req) = next_req {
                    if let Ok(new_tx) = self.transactions.start_client_transaction(req.clone(), now)
                    {
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.active_invite_tx = Some(new_tx.clone());
                            call.active_invite_req = Some(req);
                        }
                        self.tx_to_call.insert(
                            new_tx,
                            (
                                call_id.to_string(),
                                if is_reinvite {
                                    CallTxKind::ReInvite
                                } else {
                                    CallTxKind::Invite
                                },
                            ),
                        );
                        return;
                    }
                }
            }
        }

        if code == 401 || code == 407 {
            let retry_state = self.calls.get(call_id).and_then(|c| {
                if !c.pending_cancel && c.state != CallState::Cancelling {
                    let target_uri = if is_reinvite {
                        c.remote_target.to_string()
                    } else {
                        c.remote_uri.to_string()
                    };
                    Some((c.invite_auth.attempts_for(code), target_uri))
                } else {
                    None
                }
            });
            if let Some((attempts, target_uri)) = retry_state {
                if let Ok((_hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Invite, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry {
                        let branch = self.next_branch();
                        let config_ref = &self.config;
                        let next_req = if let Some(call) = self.calls.get_mut(call_id) {
                            call.invite_auth.record_retry(code, hdr_val);
                            call.local_cseq += 1;
                            call.received_provisional = false;
                            call.local_sdp.clone().map(|sdp| {
                                if is_reinvite {
                                    Self::build_in_dialog_invite(config_ref, call, &branch, &sdp)
                                } else {
                                    Self::build_invite_request(config_ref, call, &branch, &sdp)
                                }
                            })
                        } else {
                            None
                        };
                        if let Some(req) = next_req {
                            if let Ok(new_tx) =
                                self.transactions.start_client_transaction(req.clone(), now)
                            {
                                if let Some(call) = self.calls.get_mut(call_id) {
                                    call.active_invite_tx = Some(new_tx.clone());
                                    call.active_invite_req = Some(req);
                                }
                                self.tx_to_call.insert(
                                    new_tx,
                                    (
                                        call_id.to_string(),
                                        if is_reinvite {
                                            CallTxKind::ReInvite
                                        } else {
                                            CallTxKind::Invite
                                        },
                                    ),
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }

        if is_reinvite && code == 491 {
            // RFC 3261 §14.1: retry re-INVITE after backoff (2.1-4.0s Call-ID owner, 0.1-2.0s non-owner).
            let seq_seed = self.id_counter;
            let eff_seed = effective_instance_seed(&self.config);
            let scheduled = if let Some(call) = self.calls.get_mut(call_id) {
                if call.glare_attempts < MAX_GLARE_RETRIES && !call.pending_cancel {
                    let desired_local_hold = call.local_hold;
                    let ip = call.local_sdp.as_ref().map_or_else(
                        || self.config.local_host.clone(),
                        |s| s.connection_ip.clone(),
                    );
                    let rtp_port = call.local_rtp_port;
                    let cseq_val = u64::from(call.local_cseq);
                    call.active_invite_tx = None;
                    call.active_invite_req = None;
                    call.state = CallState::Established;
                    if let Some(rb) = call.pending_reinvite_rollback.take() {
                        call.local_sdp = rb.prev_local_sdp;
                        call.sdp_version = rb.prev_sdp_version;
                        call.local_hold = rb.prev_local_hold;
                        call.local_rtp_port = rb.prev_local_rtp_port;
                    }
                    let h = splitmix64(
                        eff_seed
                            ^ seq_seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                            ^ cseq_val.wrapping_mul(0xbf58_476d_1ce4_e5b9),
                    );
                    let delay_ms = if call.direction == CallDirection::Outbound {
                        2100 + (h % 1901)
                    } else {
                        100 + (h % 1901)
                    };
                    call.glare_attempts = call.glare_attempts.saturating_add(1);
                    call.pending_glare_retry = Some(PendingGlareRetry {
                        due_at: now + Duration::from_millis(delay_ms),
                        ip,
                        rtp_port,
                        desired_local_hold,
                        attempts: call.glare_attempts,
                    });
                    true
                } else {
                    false
                }
            } else {
                false
            };
            if scheduled {
                return;
            }
        }

        if is_reinvite {
            // Re-INVITE rejection does not tear down an established dialog (RFC 3261 §14.1).
            if let Some(call) = self.calls.get_mut(call_id) {
                call.pending_glare_retry = None;
                call.glare_attempts = 0;
            }
            self.rollback_reinvite(call_id);
            self.pending_events
                .push_back(UaEvent::ProtocolWarning(format!(
                    "re-INVITE rejected with {code} {}",
                    response.reason_phrase
                )));
            return;
        }

        let reason_header = extract_reason_header(&response.headers);
        self.terminate_call_with_reason(call_id, Some(code), response.reason_phrase, reason_header);
    }

    fn handle_update_final(
        &mut self,
        call_id: &str,
        tx_id: &TransactionId,
        response: SipResponse,
        now: Instant,
    ) {
        let is_active = self
            .calls
            .get(call_id)
            .is_some_and(|c| c.active_update_tx.as_ref() == Some(tx_id));
        if !is_active {
            return;
        }

        let code = response.status_code;
        if (200..300).contains(&code) {
            let mut media_payload = None;
            let mut hold_payload = None;

            if let Some(call) = self.calls.get_mut(call_id) {
                let had_sdp = call
                    .active_update_req
                    .as_ref()
                    .is_some_and(|r| !r.body.is_empty());
                call.active_update_tx = None;
                call.active_update_req = None;
                call.update_auth.reset();
                call.session_timer_retries = 0;

                if let Ok(Some(contact)) = response.contact() {
                    call.remote_target = contact.uri;
                }
                if had_sdp {
                    if let (Some(local_sdp), Some(remote_sdp)) =
                        (call.local_sdp.clone(), parse_optional_sdp(&response.body))
                    {
                        let effective_srtp = self
                            .config
                            .effective_srtp_mode()
                            .unwrap_or(SrtpMode::Disabled);
                        if let Ok(srtp) =
                            resolve_outbound_answer_srtp(&local_sdp, &remote_sdp, effective_srtp)
                        {
                            call.negotiated_srtp = srtp;
                        }
                        let negotiated = intersect_answer_codecs(&local_sdp, &remote_sdp);
                        let prev_remote_hold = call.remote_hold;
                        let new_remote_hold = is_remote_hold(remote_sdp.direction);
                        call.remote_sdp = Some(remote_sdp.clone());
                        call.remote_hold = new_remote_hold;
                        call.negotiated_codecs = negotiated.clone();
                        if new_remote_hold != prev_remote_hold {
                            hold_payload = Some((call.local_hold, new_remote_hold));
                        }
                        media_payload = Some((local_sdp, remote_sdp, negotiated));
                    }
                }
            }

            self.apply_uac_session_timer_from_response(call_id, &response, now);
            if let Some((local_sdp, remote_sdp, negotiated_codecs)) = media_payload {
                self.pending_events.push_back(UaEvent::CallMediaUpdated {
                    call_id: call_id.to_string(),
                    local_sdp,
                    remote_sdp,
                    negotiated_codecs,
                });
            }
            if let Some((local_hold, remote_hold)) = hold_payload {
                self.pending_events.push_back(UaEvent::CallHoldChanged {
                    call_id: call_id.to_string(),
                    local_hold,
                    remote_hold,
                });
            }
            return;
        }

        if code == 422 {
            let can_retry = self
                .calls
                .get(call_id)
                .is_some_and(|c| c.session_timer_retries < MAX_SESSION_TIMER_RETRIES);
            if can_retry {
                let cur_min_se = self
                    .calls
                    .get(call_id)
                    .map_or(self.config.min_se_secs, |c| c.min_se_secs);
                let remote_min_se = response
                    .headers
                    .get("Min-SE")
                    .and_then(|v| v.split(';').next()?.trim().parse::<u32>().ok())
                    .unwrap_or_else(|| cur_min_se.max(1800));
                let new_se = remote_min_se.max(cur_min_se).max(90);
                let branch = self.next_branch();
                let config_ref = &self.config;
                let next_req = if let Some(call) = self.calls.get_mut(call_id) {
                    call.min_se_secs = call.min_se_secs.max(new_se);
                    call.session_expires_secs = Some(new_se);
                    call.session_timer_retries = call.session_timer_retries.saturating_add(1);
                    call.update_auth.reset_attempts();
                    call.local_cseq += 1;
                    let had_sdp = call
                        .active_update_req
                        .as_ref()
                        .is_some_and(|r| !r.body.is_empty());
                    let sdp_opt = if had_sdp {
                        call.local_sdp.clone()
                    } else {
                        None
                    };
                    Some(Self::build_in_dialog_update(
                        config_ref,
                        call,
                        &branch,
                        sdp_opt.as_ref(),
                    ))
                } else {
                    None
                };
                if let Some(req) = next_req {
                    if let Ok(new_tx) = self.transactions.start_client_transaction(req.clone(), now)
                    {
                        if let Some(call) = self.calls.get_mut(call_id) {
                            call.active_update_tx = Some(new_tx.clone());
                            call.active_update_req = Some(req);
                        }
                        self.tx_to_call
                            .insert(new_tx, (call_id.to_string(), CallTxKind::Update));
                        return;
                    }
                }
            }
        }

        if code == 401 || code == 407 {
            let retry_state = self.calls.get(call_id).map(|c| {
                (
                    c.update_auth.attempts_for(code),
                    c.remote_target.to_string(),
                )
            });
            if let Some((attempts, target_uri)) = retry_state {
                if let Ok((_hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Update, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry {
                        let branch = self.next_branch();
                        let config_ref = &self.config;
                        let next_req = if let Some(call) = self.calls.get_mut(call_id) {
                            call.update_auth.record_retry(code, hdr_val);
                            call.local_cseq += 1;
                            let had_sdp = call
                                .active_update_req
                                .as_ref()
                                .is_some_and(|r| !r.body.is_empty());
                            let sdp_opt = if had_sdp {
                                call.local_sdp.clone()
                            } else {
                                None
                            };
                            Some(Self::build_in_dialog_update(
                                config_ref,
                                call,
                                &branch,
                                sdp_opt.as_ref(),
                            ))
                        } else {
                            None
                        };
                        if let Some(req) = next_req {
                            if let Ok(new_tx) =
                                self.transactions.start_client_transaction(req.clone(), now)
                            {
                                if let Some(call) = self.calls.get_mut(call_id) {
                                    call.active_update_tx = Some(new_tx.clone());
                                    call.active_update_req = Some(req);
                                }
                                self.tx_to_call
                                    .insert(new_tx, (call_id.to_string(), CallTxKind::Update));
                                return;
                            }
                        }
                    }
                }
            }
        }

        let was_bodyless_refresh = self
            .calls
            .get(call_id)
            .and_then(|c| c.active_update_req.as_ref())
            .is_some_and(|r| r.body.is_empty());
        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_update_tx = None;
            call.active_update_req = None;
        }
        // RFC 4028 §7.4 / §10: fall back from unsupported UPDATE session refresh to re-INVITE.
        if matches!(code, 405 | 501) && was_bodyless_refresh {
            let reinvite_args = self.calls.get(call_id).and_then(|c| {
                if c.state == CallState::Established {
                    let dir = if c.local_hold && c.remote_hold {
                        Direction::Inactive
                    } else if c.local_hold {
                        Direction::SendOnly
                    } else {
                        Direction::SendRecv
                    };
                    Some((self.config.local_host.clone(), c.local_rtp_port, dir))
                } else {
                    None
                }
            });
            if let Some((ip, rtp_port, dir)) = reinvite_args {
                if self
                    .send_reinvite_with_direction(call_id, &ip, rtp_port, dir, None, now)
                    .is_ok()
                {
                    return;
                }
            }
        }
        self.pending_events
            .push_back(UaEvent::ProtocolWarning(format!(
                "UPDATE rejected with {code} {}",
                response.reason_phrase
            )));
    }

    fn handle_refer_final(&mut self, call_id: &str, response: SipResponse, now: Instant) {
        let code = response.status_code;
        if (200..300).contains(&code) {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.refer_auth.reset();
                call.active_refer_uri = None;
            }
            return;
        }

        if code == 401 || code == 407 {
            let retry_state = self.calls.get(call_id).and_then(|c| {
                c.active_refer_uri.clone().map(|ref_uri| {
                    (
                        c.refer_auth.attempts_for(code),
                        c.remote_target.to_string(),
                        ref_uri,
                    )
                })
            });
            if let Some((attempts, target_uri, ref_uri)) = retry_state {
                if let Ok((_hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Refer, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry
                        && self
                            .send_refer_with_auth(call_id, ref_uri, Some((code, hdr_val)), now)
                            .is_ok()
                    {
                        return;
                    }
                }
            }
        }

        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_refer_uri = None;
        }
        self.pending_events
            .push_back(UaEvent::ProtocolWarning(format!(
                "REFER rejected with {code} {}",
                response.reason_phrase
            )));
    }

    fn handle_info_final(&mut self, call_id: &str, response: SipResponse, now: Instant) {
        let code = response.status_code;
        if (200..300).contains(&code) {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.info_auth.reset();
                call.active_info_payload = None;
            }
            return;
        }

        if code == 401 || code == 407 {
            let retry_state = self.calls.get(call_id).and_then(|c| {
                c.active_info_payload.map(|(digit, dur)| {
                    (
                        c.info_auth.attempts_for(code),
                        c.remote_target.to_string(),
                        digit,
                        dur,
                    )
                })
            });
            if let Some((attempts, target_uri, digit, dur)) = retry_state {
                if let Ok((_hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Info, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry
                        && self
                            .send_info_dtmf_with_auth(
                                call_id,
                                digit,
                                dur,
                                Some((code, hdr_val)),
                                now,
                            )
                            .is_ok()
                    {
                        return;
                    }
                }
            }
        }

        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_info_payload = None;
        }
        self.pending_events
            .push_back(UaEvent::ProtocolWarning(format!(
                "INFO rejected with {code} {}",
                response.reason_phrase
            )));
    }

    fn handle_bye_final(
        &mut self,
        call_id: &str,
        tx_id: &TransactionId,
        response: SipResponse,
        now: Instant,
    ) {
        let is_active_bye = self
            .calls
            .get(call_id)
            .is_some_and(|c| c.active_bye_tx.as_ref() == Some(tx_id));
        if !is_active_bye {
            return;
        }

        let code = response.status_code;
        if code == 401 || code == 407 {
            let retry_state = self
                .calls
                .get(call_id)
                .map(|c| (c.bye_auth.attempts_for(code), c.remote_target.to_string()));
            if let Some((attempts, target_uri)) = retry_state {
                if let Ok((_hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Bye, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry
                        && self
                            .send_bye_for_call(call_id, Some((code, hdr_val)), now)
                            .is_ok()
                    {
                        return;
                    }
                }
            }
        }

        let reason_header = extract_reason_header(&response.headers);
        self.terminate_call_with_reason(call_id, Some(code), response.reason_phrase, reason_header);
    }

    fn on_unmatched_2xx(&mut self, response: SipResponse, now: Instant) {
        let Ok(call_id) = response.call_id().map(str::to_string) else {
            return;
        };
        let Ok(cseq) = response.cseq() else {
            return;
        };
        if cseq.method != Method::Invite {
            return;
        }
        let resp_to_tag = response.to().ok().and_then(|t| t.tag);

        if let Some(call) = self.calls.get(&call_id) {
            if resp_to_tag.is_some() && resp_to_tag == call.remote_tag {
                if let Some(ack) = &call.last_ack_for_2xx {
                    if ack.cseq().ok().map(|c| c.seq) == Some(cseq.seq) {
                        let _ = self.transactions.send_ack_for_2xx(ack.clone());
                    }
                }
                return;
            }
        }

        // RFC 3261 §13.2.2.4 / RFC 6026: Unmatched 2xx for a forked or late leg MUST be ACKed
        // with its own To-tag/Contact/Record-Route and immediately torn down with BYE.
        let (fallback_target, bye_cseq) = if let Some(call) = self.calls.get_mut(&call_id) {
            call.local_cseq += 1;
            (
                Some(call.remote_uri.clone()),
                call.local_cseq.max(cseq.seq.saturating_add(1)),
            )
        } else {
            (None, cseq.seq.saturating_add(1))
        };

        let target_uri = response
            .contact()
            .ok()
            .flatten()
            .map(|c| c.uri)
            .or(fallback_target)
            .or_else(|| response.to().ok().map(|t| t.uri));
        let Some(target_uri) = target_uri else {
            return;
        };

        let route_set = extract_record_routes(&response.headers, true);
        let ack_branch = self.next_branch();
        let mut ack = SipRequest::new(Method::Ack, target_uri.clone());
        ack.headers.add(
            "Via",
            Via::new(
                self.config.transport.via_proto(),
                format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                ack_branch,
            )
            .to_string(),
        );
        for route in &route_set {
            ack.headers
                .add("Route", NameAddr::new(route.clone()).to_string());
        }
        if let Some(from) = response.headers.get("From") {
            ack.headers.set("From", from);
        }
        if let Some(to) = response.headers.get("To") {
            ack.headers.set("To", to);
        }
        ack.headers.set("Call-ID", call_id.clone());
        ack.headers
            .set("CSeq", CSeq::new(cseq.seq, Method::Ack).to_string());
        ack.headers.set("Max-Forwards", "70");
        let _ = self.transactions.send_ack_for_2xx(ack);

        let bye_branch = self.next_branch();
        let mut bye = SipRequest::new(Method::Bye, target_uri);
        bye.headers.add(
            "Via",
            Via::new(
                self.config.transport.via_proto(),
                format!("{}:{}", self.config.local_host, self.config.local_sip_port),
                bye_branch,
            )
            .to_string(),
        );
        for route in &route_set {
            bye.headers
                .add("Route", NameAddr::new(route.clone()).to_string());
        }
        if let Some(from) = response.headers.get("From") {
            bye.headers.set("From", from);
        }
        if let Some(to) = response.headers.get("To") {
            bye.headers.set("To", to);
        }
        bye.headers.set("Call-ID", call_id);
        bye.headers
            .set("CSeq", CSeq::new(bye_cseq, Method::Bye).to_string());
        bye.headers.set("Max-Forwards", "70");
        let _ = self.transactions.start_client_transaction(bye, now);
    }

    fn rollback_reinvite(&mut self, call_id: &str) {
        let hold_revert = if let Some(call) = self.calls.get_mut(call_id) {
            call.active_invite_tx = None;
            call.active_invite_req = None;
            call.state = CallState::Established;
            if let Some(rb) = call.pending_reinvite_rollback.take() {
                let changed = call.local_hold != rb.prev_local_hold;
                call.local_sdp = rb.prev_local_sdp;
                call.sdp_version = rb.prev_sdp_version;
                call.local_hold = rb.prev_local_hold;
                call.local_rtp_port = rb.prev_local_rtp_port;
                changed.then_some((call.local_hold, call.remote_hold))
            } else {
                None
            }
        } else {
            None
        };
        if let Some((local_hold, remote_hold)) = hold_revert {
            self.pending_events.push_back(UaEvent::CallHoldChanged {
                call_id: call_id.to_string(),
                local_hold,
                remote_hold,
            });
        }
    }

    fn on_transaction_timeout(&mut self, tx_id: TransactionId) {
        if self.reg_session.active_tx.as_ref() == Some(&tx_id) {
            self.reg_session.active_tx = None;
            self.set_registration_state(RegistrationState::Failed {
                status_code: None,
                reason: "REGISTER transaction timed out".to_string(),
            });
            return;
        }

        if let Some((call_id, kind)) = self.tx_to_call.remove(&tx_id) {
            match kind {
                CallTxKind::Invite | CallTxKind::Bye => {
                    self.terminate_call(&call_id, None, "SIP transaction timed out".to_string());
                }
                CallTxKind::ReInvite => {
                    self.rollback_reinvite(&call_id);
                    self.pending_events.push_back(UaEvent::ProtocolWarning(
                        "re-INVITE transaction timed out".to_string(),
                    ));
                }
                CallTxKind::Update => {
                    if let Some(call) = self.calls.get_mut(&call_id) {
                        call.active_update_tx = None;
                        call.active_update_req = None;
                    }
                    self.pending_events.push_back(UaEvent::ProtocolWarning(
                        "UPDATE transaction timed out".to_string(),
                    ));
                }
                CallTxKind::Info => {
                    if let Some(call) = self.calls.get_mut(&call_id) {
                        call.active_info_payload = None;
                    }
                    self.pending_events.push_back(UaEvent::ProtocolWarning(
                        "INFO DTMF transaction timed out".to_string(),
                    ));
                }
                CallTxKind::Cancel | CallTxKind::Prack | CallTxKind::Refer | CallTxKind::Notify => {
                }
            }
        }
    }

    fn terminate_call(&mut self, call_id: &str, status_code: Option<u16>, reason: String) {
        self.terminate_call_with_reason(call_id, status_code, reason, None);
    }

    fn terminate_call_with_reason(
        &mut self,
        call_id: &str,
        status_code: Option<u16>,
        reason: String,
        reason_header: Option<ReasonHeader>,
    ) {
        if let Some(mut call) = self.calls.remove(call_id) {
            call.state = CallState::Terminated;
            self.tx_to_call.retain(|_, (cid, _)| cid != call_id);
            self.pending_events.push_back(UaEvent::CallTerminated {
                call_id: call_id.to_string(),
                status_code,
                reason,
                reason_header,
            });
        }
    }

    fn apply_uas_session_timer_to_response(
        &mut self,
        call_id: &str,
        request: &SipRequest,
        resp: &mut SipResponse,
        now: Instant,
    ) {
        let req_se = request
            .headers
            .get("Session-Expires")
            .and_then(|v| SessionExpires::parse(v).ok());
        let supports_timer = has_header_token(&request.headers, "Supported", "timer")
            || has_header_token(&request.headers, "Require", "timer");

        let chosen_se = if let Some(se) = req_se.as_ref() {
            Some(se.delta_seconds.max(self.config.min_se_secs).max(2))
        } else if supports_timer {
            self.config
                .session_expires_secs
                .map(|se| se.max(self.config.min_se_secs).max(2))
        } else {
            None
        };

        let Some(se_secs) = chosen_se else {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.session_expires_secs = None;
                call.session_refresh_at = None;
                call.session_expire_at = None;
            }
            return;
        };
        let requested_uas =
            req_se.as_ref().and_then(|s| s.refresher) == Some(SessionRefresher::Uas);
        // RFC 4028 §9 Table 2: UAS may select refresher=uac + Require: timer only when UAC supports timer.
        let role = if requested_uas || !supports_timer {
            SessionRefresher::Uas
        } else {
            SessionRefresher::Uac
        };
        resp.headers.set(
            "Session-Expires",
            SessionExpires::new(se_secs, Some(role)).to_string(),
        );
        if role == SessionRefresher::Uac {
            // RFC 4028 §9: when UAS assigns `refresher=uac`, response MUST include `Require: timer`.
            add_header_token(&mut resp.headers, "Require", "timer");
        }
        let is_local_refresher = role == SessionRefresher::Uas;
        if let Some(call) = self.calls.get_mut(call_id) {
            call.session_expires_secs = Some(se_secs);
            call.session_refresher_is_local = is_local_refresher;
            call.session_expire_at = Some(now + Duration::from_secs(u64::from(se_secs)));
            call.session_refresh_at = if is_local_refresher {
                Some(now + Duration::from_secs(u64::from(se_secs / 2).max(1)))
            } else {
                None
            };
        }
    }

    fn apply_uac_session_timer_from_response(
        &mut self,
        call_id: &str,
        response: &SipResponse,
        now: Instant,
    ) {
        let Some(raw) = response.headers.get("Session-Expires") else {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.session_expires_secs = None;
                call.session_refresh_at = None;
                call.session_expire_at = None;
            }
            return;
        };
        let Ok(parsed) = SessionExpires::parse(raw) else {
            return;
        };
        let se_secs = parsed.delta_seconds.max(2);
        let is_local_refresher = parsed.refresher != Some(SessionRefresher::Uas);
        if let Some(call) = self.calls.get_mut(call_id) {
            call.session_expires_secs = Some(se_secs);
            call.session_refresher_is_local = is_local_refresher;
            call.session_expire_at = Some(now + Duration::from_secs(u64::from(se_secs)));
            call.session_refresh_at = if is_local_refresher {
                Some(now + Duration::from_secs(u64::from(se_secs / 2).max(1)))
            } else {
                None
            };
        }
    }

    fn compute_auth_header(
        &mut self,
        response: &SipResponse,
        method: &Method,
        digest_uri: &str,
    ) -> Result<(&'static str, String, bool), SipError> {
        let (header_name_in, auth_header_name, missing_hdr) = if response.status_code == 407 {
            (
                "Proxy-Authenticate",
                "Proxy-Authorization",
                "Proxy-Authenticate",
            )
        } else {
            ("WWW-Authenticate", "Authorization", "WWW-Authenticate")
        };

        let raw_challenges = response.headers.get_all(header_name_in);
        if raw_challenges.is_empty() {
            return Err(SipError::MissingHeader(missing_hdr));
        }

        let mut challenges = Vec::new();
        let mut last_err: Option<SipError> = None;
        for raw in raw_challenges {
            match DigestChallenge::parse(raw) {
                Ok(ch) => challenges.push(ch),
                Err(err) => last_err = Some(err),
            }
        }
        if challenges.is_empty() {
            return Err(last_err.unwrap_or(SipError::MissingHeader(missing_hdr)));
        }

        // Prefer stronger SHA-256 / SHA-256-sess challenges over MD5 / MD5-sess when offered together.
        challenges.sort_by_key(|ch| match ch.algorithm {
            DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => 0u8,
            DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => 1u8,
        });

        let cnonce = self.next_cnonce();
        let creds = DigestCredentials::new(
            self.config.username.clone(),
            self.config.password.clone(),
            Some(cnonce),
        );
        for challenge in challenges {
            match creds.authorize(&challenge, method, digest_uri) {
                Ok(value) => return Ok((auth_header_name, value, challenge.stale)),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or(SipError::MissingHeader(missing_hdr)))
    }
}

fn fallback_instance_tag(config: &UaConfig) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in config
        .local_host
        .as_bytes()
        .iter()
        .chain(b"|")
        .chain(config.username.as_bytes())
        .chain(&config.local_sip_port.to_le_bytes())
    {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash.max(1)
}

fn effective_instance_seed(config: &UaConfig) -> u64 {
    if config.instance_seed == 0 {
        u64::from(fallback_instance_tag(config))
    } else {
        config.instance_seed
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn has_header_token(headers: &crate::sip::Headers, name: &str, token: &str) -> bool {
    headers.get_all(name).iter().any(|hdr| {
        hdr.split(',')
            .any(|part| part.trim().eq_ignore_ascii_case(token))
    })
}

fn add_header_token(headers: &mut crate::sip::Headers, name: &str, token: &str) {
    if has_header_token(headers, name, token) {
        return;
    }
    let existing = headers.get_all(name);
    if existing.is_empty() {
        headers.set(name, token);
    } else {
        let mut merged = existing.join(", ");
        merged.push_str(", ");
        merged.push_str(token);
        headers.set(name, merged);
    }
}

fn parse_optional_sdp(body: &[u8]) -> Option<SdpSession> {
    if body.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    SdpSession::parse(text).ok()
}

fn contact_matches_local(contact: &SipUri, local: &SipUri) -> bool {
    contact.user == local.user
        && contact.host.eq_ignore_ascii_case(&local.host)
        && contact.port.unwrap_or(5060) == local.port.unwrap_or(5060)
}

fn extract_register_expires(resp: &SipResponse, local_contact: &SipUri) -> Option<u32> {
    if let Ok(contacts) = resp.contacts() {
        if let Some(matched) = contacts
            .iter()
            .find(|c| contact_matches_local(&c.uri, local_contact))
        {
            if let Some(exp) = matched.expires {
                return Some(exp);
            }
        }
        // Fallback for NAT-rewritten single-binding responses where the registrar replaced host/port.
        if contacts.len() == 1 {
            if let Some(exp) = contacts[0].expires {
                return Some(exp);
            }
        }
    }
    resp.headers
        .get("Expires")
        .and_then(|v| v.trim().parse::<u32>().ok())
}

fn extract_record_routes(headers: &crate::sip::Headers, reverse_for_uac: bool) -> Vec<SipUri> {
    let mut routes = Vec::new();
    for raw in headers.get_all("Record-Route") {
        if let Ok(addrs) = NameAddr::parse_list(raw) {
            for addr in addrs {
                routes.push(addr.uri);
            }
        }
    }
    if reverse_for_uac {
        routes.reverse();
    }
    routes
}

fn intersect_answer_codecs(offer: &SdpSession, answer: &SdpSession) -> Vec<RtpCodec> {
    let mut matched = Vec::new();
    for ans_codec in &answer.codecs {
        if let Some(off_codec) = offer.codecs.iter().find(|c| {
            c.encoding_name
                .eq_ignore_ascii_case(&ans_codec.encoding_name)
                && c.clock_rate == ans_codec.clock_rate
        }) {
            matched.push(RtpCodec {
                payload_type: ans_codec.payload_type,
                encoding_name: ans_codec.encoding_name.clone(),
                clock_rate: ans_codec.clock_rate,
                channels: ans_codec.channels.or(off_codec.channels),
                fmtp: ans_codec.fmtp.clone().or_else(|| off_codec.fmtp.clone()),
            });
        }
    }
    if matched.is_empty() {
        answer.codecs.clone()
    } else {
        matched
    }
}

enum InDialogCheck {
    Valid(String),
    OutOfOrder500,
    NotFound481,
}

fn is_remote_hold(dir: Direction) -> bool {
    matches!(dir, Direction::SendOnly | Direction::Inactive)
}

fn constrain_answer_direction(offer_dir: Direction, local_hold: bool) -> Direction {
    let base = offer_dir.answer_direction();
    if !local_hold {
        base
    } else {
        match base {
            Direction::SendRecv => Direction::SendOnly,
            Direction::RecvOnly => Direction::Inactive,
            Direction::SendOnly | Direction::Inactive => base,
        }
    }
}

fn extract_reason_header(headers: &crate::sip::Headers) -> Option<ReasonHeader> {
    headers
        .get("Reason")
        .and_then(|v| ReasonHeader::parse(v).ok())
}

fn parse_sipfrag_status(body: &[u8]) -> (u16, String) {
    let Ok(text) = std::str::from_utf8(body) else {
        return (0, String::new());
    };
    let Some(first_line) = text.lines().next().map(str::trim) else {
        return (0, String::new());
    };
    let rest = first_line
        .strip_prefix("SIP/2.0 ")
        .unwrap_or(first_line)
        .trim();
    let mut parts = rest.splitn(2, char::is_whitespace);
    let code = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let reason = parts.next().map(str::trim).unwrap_or("").to_string();
    (code, reason)
}

fn normalize_dtmf_char(ch: char) -> Option<char> {
    let up = ch.to_ascii_uppercase();
    match up {
        '0'..='9' | '*' | '#' | 'A'..='D' => Some(up),
        _ => None,
    }
}

fn parse_dtmf_signal_token(raw: &str) -> Option<char> {
    let token = raw.trim().trim_matches('"');
    if token == "10" {
        return Some('*');
    }
    if token == "11" {
        return Some('#');
    }
    let mut chars = token.chars();
    let first = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    normalize_dtmf_char(first)
}

fn parse_sip_info_dtmf(body: &[u8], media_type: &str) -> Option<(char, u32)> {
    let text = std::str::from_utf8(body).ok()?.trim();
    if text.is_empty() {
        return None;
    }

    if media_type == "application/dtmf" {
        if let Some(digit) = parse_dtmf_signal_token(text) {
            return Some((digit, 160));
        }
    }

    let mut signal: Option<char> = None;
    let mut duration_ms: u32 = 160;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, val) = trimmed
            .split_once('=')
            .or_else(|| trimmed.split_once(':'))?;
        let key_lc = key.trim().to_ascii_lowercase();
        if key_lc == "signal" {
            signal = parse_dtmf_signal_token(val);
        } else if key_lc == "duration" {
            duration_ms = val.trim().parse::<u32>().ok()?.clamp(40, 5_000);
        }
    }
    signal.map(|d| (d, duration_ms))
}
