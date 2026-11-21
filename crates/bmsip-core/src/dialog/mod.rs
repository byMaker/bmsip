//! MODULE_CONTRACT: Sans-I/O SIP User Agent (`UserAgent`), Account Registration FSM (RFC 3261 §10), and Invite Dialog FSM (RFC 3261 §9, §12–15).
//! INVARIANTS: Zero I/O or system clock access; handles 401/407 Digest challenges on REGISTER/INVITE/BYE; enforces RFC 3261 §9.1 CANCEL ordering (defer CANCEL until 1xx arrives); auto-handles OPTIONS keepalives and 2xx ACK retransmissions.
//! RFC_REFS: RFC 3261 Sections 9, 10, 12, 13, 14, 15; RFC 3264.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::auth::{DigestChallenge, DigestCredentials};
use crate::error::SipError;
use crate::sdp::{negotiate_offer_answer, RtpCodec, SdpSession};
use crate::sip::{CSeq, Method, NameAddr, SipMessage, SipRequest, SipResponse, SipUri, Via};
use crate::transaction::{RfcTimers, TransactionEvent, TransactionId, TransactionManager};

const DEFAULT_USER_AGENT: &str = concat!("bmsip/", env!("CARGO_PKG_VERSION"));
const MAX_STALE_AUTH_RETRIES: u8 = 3;

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
    pub expires_secs: u32,
    pub supported_codecs: Vec<RtpCodec>,
    pub timers: RfcTimers,
    /// Optional per-instance entropy seed mixed into Call-IDs, tags, branches, and cnonces
    /// to prevent collisions across process restarts on fixed ports while keeping Sans-I/O determinism (`0` = deterministic default).
    pub instance_seed: u64,
}

impl UaConfig {
    /// Creates a `UaConfig` with standard defaults (300 s expiry, PCMU/PCMA/DTMF, RFC 3261 timers).
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
            expires_secs: 300,
            supported_codecs: vec![
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::telephone_event(101),
            ],
            timers: RfcTimers::default(),
            instance_seed: 0,
        }
    }

    /// Sets an explicit instance seed for unique Call-ID, tag, branch, and Digest `cnonce` generation across restarts.
    pub fn with_instance_seed(mut self, seed: u64) -> Self {
        self.instance_seed = seed;
        self
    }

    fn aor_uri(&self) -> SipUri {
        SipUri::new(self.domain.clone()).with_user(self.username.clone())
    }

    fn contact_uri(&self) -> SipUri {
        SipUri::new(self.local_host.clone())
            .with_user(self.username.clone())
            .with_port(self.local_sip_port)
            .with_param("transport", Some("udp".to_string()))
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
    CallTerminated {
        call_id: String,
        status_code: Option<u16>,
        reason: String,
    },
    ProtocolWarning(String),
}

#[derive(Debug, Clone)]
struct RegisterSession {
    call_id: String,
    local_tag: String,
    cseq: u32,
    active_tx: Option<TransactionId>,
    auth_attempts: u8,
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
enum CallTxKind {
    Invite,
    ReInvite,
    Cancel,
    Bye,
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
    active_invite_tx: Option<TransactionId>,
    active_invite_req: Option<SipRequest>,
    active_bye_tx: Option<TransactionId>,
    inbound_invite_tx: Option<TransactionId>,
    inbound_invite_req: Option<SipRequest>,
    inbound_invite_branch: Option<String>,
    pending_cancel: bool,
    invite_auth_attempts: u8,
    bye_auth_attempts: u8,
    last_ack_for_2xx: Option<SipRequest>,
    awaiting_ack: Option<Pending2xxAck>,
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

impl UserAgent {
    /// Creates a new [`UserAgent`] initialized in [`RegistrationState::Unregistered`].
    pub fn new(config: UaConfig) -> Self {
        let seed_part = if config.instance_seed == 0 {
            String::new()
        } else {
            format!("-{:08x}", (config.instance_seed & 0xffff_ffff) as u32)
        };
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
                auth_attempts: 0,
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

    /// Returns the current SIP registration state.
    pub fn registration_state(&self) -> &RegistrationState {
        &self.reg_state
    }

    /// Returns the FSM state of a tracked call, if present.
    pub fn call_state(&self, call_id: &str) -> Option<CallState> {
        self.calls.get(call_id).map(|c| c.state)
    }

    /// Returns the established RFC 3261 dialog identifier for `call_id`, if a remote tag is known.
    pub fn dialog_id(&self, call_id: &str) -> Option<DialogId> {
        self.calls.get(call_id).and_then(CallSession::dialog_id)
    }

    /// Drains queued [`UaEvent`]s emitted by synchronous command methods (`answer`, `hangup`, etc.).
    pub fn drain_events(&mut self) -> Vec<UaEvent> {
        self.pending_events.drain(..).collect()
    }

    /// Initiates or refreshes SIP account `REGISTER` with `config.expires_secs`.
    pub fn register(&mut self, now: Instant) -> Result<(), SipError> {
        self.start_register_with_expires(self.config.expires_secs, None, 0, now)?;
        self.set_registration_state(RegistrationState::Registering);
        Ok(())
    }

    /// Initiates SIP de-registration (`REGISTER` with `Expires: 0`).
    pub fn unregister(&mut self, now: Instant) -> Result<(), SipError> {
        self.start_register_with_expires(0, None, 0, now)?;
        self.set_registration_state(RegistrationState::Unregistering);
        Ok(())
    }

    /// Starts an outbound `INVITE` call with an SDP audio offer and returns its `Call-ID`.
    pub fn dial(
        &mut self,
        target_uri: SipUri,
        local_rtp_port: u16,
        now: Instant,
    ) -> Result<String, SipError> {
        let call_id = self.next_call_id();
        let local_tag = self.next_tag();
        let sdp_sid = self.next_numeric_id();
        let sdp_version = 1;

        let local_sdp = SdpSession {
            origin_username: self.config.username.clone(),
            session_id: sdp_sid.clone(),
            session_version: sdp_version.to_string(),
            connection_ip: self.config.local_host.clone(),
            audio_port: local_rtp_port,
            direction: crate::sdp::Direction::SendRecv,
            codecs: self.config.supported_codecs.clone(),
            ptime: Some(20),
        };

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
            active_invite_tx: None,
            active_invite_req: None,
            active_bye_tx: None,
            inbound_invite_tx: None,
            inbound_invite_req: None,
            inbound_invite_branch: None,
            pending_cancel: false,
            invite_auth_attempts: 0,
            bye_auth_attempts: 0,
            last_ack_for_2xx: None,
            awaiting_ack: None,
        };

        let branch = self.next_branch();
        let req = Self::build_invite_request(&self.config, &call, &branch, &local_sdp, None);
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

        let tx_events = self.transactions.send_server_response(&tx_id, resp, now)?;
        self.process_transaction_events(tx_events, now);

        if let Some(call) = self.calls.get_mut(call_id) {
            call.state = CallState::Ringing;
        }
        Ok(())
    }

    /// Answers an inbound call (`200 OK` with negotiated SDP) and starts 2xx ACK retransmission timer.
    pub fn answer(
        &mut self,
        call_id: &str,
        local_rtp_port: u16,
        now: Instant,
    ) -> Result<(), SipError> {
        let (tx_id, req, remote_sdp_opt, local_tag, sdp_sid) = {
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
            )
        };

        let Some(remote_sdp) = remote_sdp_opt else {
            self.reject_inbound_invite_488(call_id, &tx_id, &req, &local_tag, now);
            return Err(SipError::InvalidSdp(
                "inbound INVITE lacked SDP offer".to_string(),
            ));
        };

        let (mut answer_sdp, negotiated) = match negotiate_offer_answer(
            &remote_sdp,
            &self.config.supported_codecs,
            &self.config.local_host,
            local_rtp_port,
        ) {
            Ok(pair) => pair,
            Err(err) => {
                self.reject_inbound_invite_488(call_id, &tx_id, &req, &local_tag, now);
                return Err(err);
            }
        };
        answer_sdp.origin_username = self.config.username.clone();
        answer_sdp.session_id = sdp_sid;
        answer_sdp.session_version = "1".to_string();

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
        resp.headers
            .set("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS");

        let tx_events = self
            .transactions
            .send_server_response(&tx_id, resp.clone(), now)?;
        self.process_transaction_events(tx_events, now);

        let t1 = self.config.timers.t1.max(Duration::from_millis(1));
        if let Some(call) = self.calls.get_mut(call_id) {
            call.state = CallState::Established;
            call.local_rtp_port = local_rtp_port;
            call.local_sdp = Some(answer_sdp.clone());
            call.negotiated_codecs = negotiated.clone();
            call.inbound_invite_tx = None;
            call.inbound_invite_req = None;
            call.awaiting_ack = Some(Pending2xxAck {
                response: resp,
                next_send_at: now + t1,
                interval: t1,
                deadline: now + t1 * 64,
            });
        }

        self.pending_events.push_back(UaEvent::CallEstablished {
            call_id: call_id.to_string(),
            local_sdp: answer_sdp,
            remote_sdp,
            negotiated_codecs: negotiated,
        });
        Ok(())
    }

    /// Rejects, cancels, or terminates an active call (`486`, `CANCEL`, or `BYE`).
    pub fn hangup(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
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
                // RFC 3261 §9.1: CANCEL MUST NOT be sent until a 1xx provisional response arrives.
                if let Some(call) = self.calls.get_mut(call_id) {
                    call.pending_cancel = true;
                    call.state = CallState::Cancelling;
                }
                Ok(())
            }
            (CallDirection::Outbound, CallState::Ringing) => {
                self.send_cancel_for_call(call_id, now)?;
                Ok(())
            }
            (CallDirection::Inbound, CallState::Incoming | CallState::Ringing) => {
                if let (Some(tx_id), Some(req)) = (inbound_tx, inbound_req) {
                    let mut resp = req.create_response(486, "Busy Here")?;
                    let mut to = resp.to()?;
                    to.tag = Some(local_tag);
                    resp.headers.set("To", to.to_string());
                    let tx_events = self.transactions.send_server_response(&tx_id, resp, now)?;
                    self.process_transaction_events(tx_events, now);
                }
                self.terminate_call(call_id, Some(486), "Rejected locally".to_string());
                Ok(())
            }
            (_, CallState::Established | CallState::ReInviting) => {
                self.send_bye_for_call(call_id, None, now)?;
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

    /// Initiates an in-dialog `re-INVITE` updating local IP/port and incrementing SDP `o=` version.
    pub fn reinvite(
        &mut self,
        call_id: &str,
        new_local_ip: &str,
        new_local_rtp_port: u16,
        now: Instant,
    ) -> Result<(), SipError> {
        let branch = self.next_branch();
        let (req, new_sdp) = {
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
            call.local_cseq += 1;
            call.local_rtp_port = new_local_rtp_port;
            call.sdp_version += 1;
            call.state = CallState::ReInviting;
            call.invite_auth_attempts = 0;

            let codecs = if call.negotiated_codecs.is_empty() {
                self.config.supported_codecs.clone()
            } else {
                call.negotiated_codecs.clone()
            };
            let sdp = SdpSession {
                origin_username: self.config.username.clone(),
                session_id: call.sdp_session_id.clone(),
                session_version: call.sdp_version.to_string(),
                connection_ip: new_local_ip.to_string(),
                audio_port: new_local_rtp_port,
                direction: crate::sdp::Direction::SendRecv,
                codecs,
                ptime: Some(20),
            };
            call.local_sdp = Some(sdp.clone());

            let req = Self::build_in_dialog_invite(&self.config, call, &branch, &sdp, None);
            (req, sdp)
        };

        let tx_id = self
            .transactions
            .start_client_transaction(req.clone(), now)?;
        if let Some(call) = self.calls.get_mut(call_id) {
            call.active_invite_tx = Some(tx_id.clone());
            call.active_invite_req = Some(req);
            call.local_sdp = Some(new_sdp);
        }
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::ReInvite));
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

        let established_calls: Vec<(String, u16)> = self
            .calls
            .iter()
            .filter(|(_, call)| call.state == CallState::Established)
            .map(|(id, call)| {
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

    /// Returns the earliest deadline across transactions, registration refresh, and 2xx retransmits.
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

        [tx_dl, reg_dl, ack_dl].into_iter().flatten().min()
    }

    /// Advances transaction, registration refresh, and UAS 2xx retransmission timers up to `now`.
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
                self.terminate_call(
                    &call_id,
                    None,
                    "ACK timeout for 200 OK (RFC 3261 §13.3.1.4)".to_string(),
                );
            } else if let Some(resp) = resend_resp {
                self.transactions.send_stateless_response(resp);
            }
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
        if self.config.instance_seed == 0 {
            String::new()
        } else {
            format!("-{:08x}", (self.config.instance_seed & 0xffff_ffff) as u32)
        }
    }

    fn next_numeric_id(&mut self) -> String {
        let seq = self.next_seq();
        if self.config.instance_seed == 0 {
            format!("{}{}", self.config.local_sip_port, seq)
        } else {
            format!(
                "{}{}{}",
                (self.config.instance_seed % 1_000_000),
                self.config.local_sip_port,
                seq
            )
        }
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
        if self.config.instance_seed == 0 {
            format!("bmcnonce{:04x}{:08x}", self.config.local_sip_port, seq)
        } else {
            format!(
                "bmcnonce{:08x}{:04x}{:08x}",
                (self.config.instance_seed & 0xffff_ffff) as u32,
                self.config.local_sip_port,
                seq
            )
        }
    }

    fn reject_inbound_invite_488(
        &mut self,
        call_id: &str,
        tx_id: &TransactionId,
        req: &SipRequest,
        local_tag: &str,
        now: Instant,
    ) {
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
        auth_header: Option<(&'static str, String)>,
        auth_attempts: u8,
        now: Instant,
    ) -> Result<(), SipError> {
        self.reg_session.cseq += 1;
        self.reg_session.auth_attempts = auth_attempts;
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
                "UDP",
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
        req.headers
            .set("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS");
        req.headers.set("User-Agent", DEFAULT_USER_AGENT);
        if let Some((hdr_name, hdr_val)) = auth_header {
            req.headers.set(hdr_name, hdr_val);
        }

        let tx_id = self.transactions.start_client_transaction(req, now)?;
        self.reg_session.active_tx = Some(tx_id);
        Ok(())
    }

    fn build_invite_request(
        config: &UaConfig,
        call: &CallSession,
        branch: &str,
        sdp: &SdpSession,
        auth_header: Option<(&'static str, String)>,
    ) -> SipRequest {
        let mut req = SipRequest::new(Method::Invite, call.remote_uri.clone())
            .with_body("application/sdp", sdp.to_string().into_bytes());
        req.headers.add(
            "Via",
            Via::new(
                "UDP",
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
        req.headers
            .set("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS");
        req.headers.set("User-Agent", DEFAULT_USER_AGENT);
        if let Some((hdr_name, hdr_val)) = auth_header {
            req.headers.set(hdr_name, hdr_val);
        }
        req
    }

    fn build_in_dialog_invite(
        config: &UaConfig,
        call: &CallSession,
        branch: &str,
        sdp: &SdpSession,
        auth_header: Option<(&'static str, String)>,
    ) -> SipRequest {
        let mut req = SipRequest::new(Method::Invite, call.remote_target.clone())
            .with_body("application/sdp", sdp.to_string().into_bytes());
        req.headers.add(
            "Via",
            Via::new(
                "UDP",
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
        if let Some((hdr_name, hdr_val)) = auth_header {
            req.headers.set(hdr_name, hdr_val);
        }
        req
    }

    fn build_ack_for_2xx(&mut self, call: &CallSession, invite_cseq: u32) -> SipRequest {
        let branch = self.next_branch();
        let mut ack = SipRequest::new(Method::Ack, call.remote_target.clone());
        ack.headers.add(
            "Via",
            Via::new(
                "UDP",
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
        ack
    }

    fn send_cancel_for_call(&mut self, call_id: &str, now: Instant) -> Result<(), SipError> {
        let orig_req = {
            let call = self
                .calls
                .get_mut(call_id)
                .ok_or_else(|| SipError::TransactionError(format!("unknown call {call_id}")))?;
            call.state = CallState::Cancelling;
            call.pending_cancel = false;
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

        let tx_id = self.transactions.start_client_transaction(cancel, now)?;
        self.tx_to_call
            .insert(tx_id, (call_id.to_string(), CallTxKind::Cancel));
        Ok(())
    }

    fn send_bye_for_call(
        &mut self,
        call_id: &str,
        auth_header: Option<(&'static str, String)>,
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
            if auth_header.is_some() {
                call.bye_auth_attempts = call.bye_auth_attempts.saturating_add(1);
            } else {
                call.bye_auth_attempts = 0;
            }

            let mut bye = SipRequest::new(Method::Bye, call.remote_target.clone());
            bye.headers.add(
                "Via",
                Via::new(
                    "UDP",
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
            if let Some((hdr_name, hdr_val)) = auth_header {
                bye.headers.set(hdr_name, hdr_val);
            }
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
                    self.on_ack_for_2xx(ack);
                }
                TransactionEvent::ServerAckReceived(_) => {}
                TransactionEvent::ClientProvisional { tx_id, response } => {
                    self.on_client_provisional(tx_id, response, now);
                }
                TransactionEvent::ClientFinal { tx_id, response } => {
                    self.on_client_final(tx_id, response, now);
                }
                TransactionEvent::Unmatched2xx(response) => {
                    self.on_unmatched_2xx(response);
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

    fn on_server_request(&mut self, tx_id: TransactionId, request: SipRequest, now: Instant) {
        match request.method {
            Method::Options => {
                if let Ok(mut resp) = request.create_response(200, "OK") {
                    resp.headers
                        .set("Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS");
                    if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                        self.process_transaction_events(events, now);
                    }
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
            _ => {
                if let Ok(resp) = request.create_response(405, "Method Not Allowed") {
                    if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                        self.process_transaction_events(events, now);
                    }
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
                Glare491,
                OutOfOrder500,
                NotFound481,
            }

            let action = if let Some(existing) = self.calls.get_mut(&call_id) {
                let remote_tag_matches = match (&existing.remote_tag, &from_tag) {
                    (Some(expected), Some(actual)) => expected == actual,
                    (None, _) => true,
                    (Some(_), None) => false,
                };
                if existing.local_tag == to_tag && remote_tag_matches {
                    if let (Some(rc), Some(prev)) = (req_cseq, existing.remote_cseq) {
                        if rc <= prev {
                            ReInviteAction::OutOfOrder500
                        } else {
                            existing.remote_cseq = Some(rc);
                            match existing.state {
                                CallState::Established => ReInviteAction::Process,
                                CallState::ReInviting => ReInviteAction::Glare491,
                                _ => ReInviteAction::NotFound481,
                            }
                        }
                    } else {
                        if let Some(rc) = req_cseq {
                            existing.remote_cseq = Some(rc);
                        }
                        match existing.state {
                            CallState::Established => ReInviteAction::Process,
                            CallState::ReInviting => ReInviteAction::Glare491,
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
                ReInviteAction::Glare491 => {
                    if let Ok(resp) = request.create_response(491, "Request Pending") {
                        if let Ok(events) =
                            self.transactions.send_server_response(&tx_id, resp, now)
                        {
                            self.process_transaction_events(events, now);
                        }
                    }
                }
                ReInviteAction::OutOfOrder500 => {
                    if let Ok(resp) = request.create_response(500, "Server Internal Error") {
                        if let Ok(events) =
                            self.transactions.send_server_response(&tx_id, resp, now)
                        {
                            self.process_transaction_events(events, now);
                        }
                    }
                }
                ReInviteAction::NotFound481 => {
                    if let Ok(resp) =
                        request.create_response(481, "Call/Transaction Does Not Exist")
                    {
                        if let Ok(events) =
                            self.transactions.send_server_response(&tx_id, resp, now)
                        {
                            self.process_transaction_events(events, now);
                        }
                    }
                }
            }
            return;
        }

        if self.calls.contains_key(&call_id) {
            if let Ok(resp) = request.create_response(482, "Loop Detected") {
                if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                    self.process_transaction_events(events, now);
                }
            }
            return;
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
            active_invite_tx: None,
            active_invite_req: None,
            active_bye_tx: None,
            inbound_invite_tx: Some(tx_id),
            inbound_invite_req: Some(request),
            inbound_invite_branch: Some(branch),
            pending_cancel: false,
            invite_auth_attempts: 0,
            bye_auth_attempts: 0,
            last_ack_for_2xx: None,
            awaiting_ack: None,
        };
        self.calls.insert(call_id.clone(), call);

        self.pending_events.push_back(UaEvent::IncomingCall {
            call_id,
            from,
            to,
            remote_sdp,
        });
    }

    fn handle_inbound_reinvite(
        &mut self,
        call_id: &str,
        tx_id: TransactionId,
        request: SipRequest,
        now: Instant,
    ) {
        let Some(remote_sdp) = parse_optional_sdp(&request.body) else {
            if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                let _ = self.transactions.send_server_response(&tx_id, resp, now);
            }
            return;
        };

        let (local_rtp_port, sdp_sid, sdp_version) = match self.calls.get_mut(call_id) {
            Some(c) => {
                c.sdp_version += 1;
                (c.local_rtp_port, c.sdp_session_id.clone(), c.sdp_version)
            }
            None => return,
        };

        let negotiated_res = negotiate_offer_answer(
            &remote_sdp,
            &self.config.supported_codecs,
            &self.config.local_host,
            local_rtp_port,
        );
        let (mut answer_sdp, negotiated) = match negotiated_res {
            Ok(pair) => pair,
            Err(_) => {
                if let Ok(resp) = request.create_response(488, "Not Acceptable Here") {
                    let _ = self.transactions.send_server_response(&tx_id, resp, now);
                }
                return;
            }
        };
        answer_sdp.origin_username = self.config.username.clone();
        answer_sdp.session_id = sdp_sid;
        answer_sdp.session_version = sdp_version.to_string();

        let Ok(mut resp) = request.create_response(200, "OK") else {
            return;
        };
        resp = resp.with_body("application/sdp", answer_sdp.to_string().into_bytes());
        resp.headers.set(
            "Contact",
            NameAddr::new(self.config.contact_uri()).to_string(),
        );

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
            call.negotiated_codecs = negotiated.clone();
            if let Ok(Some(c)) = request.contact() {
                call.remote_target = c.uri;
            }
            call.awaiting_ack = Some(Pending2xxAck {
                response: resp,
                next_send_at: now + t1,
                interval: t1,
                deadline: now + t1 * 64,
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
        let cancel_branch = request.top_via().ok().and_then(|v| v.branch);
        let call_id = request.call_id().ok().map(str::to_string);

        let matching_call = call_id.and_then(|cid| {
            let call = self.calls.get(&cid)?;
            if call.direction == CallDirection::Inbound
                && matches!(call.state, CallState::Incoming | CallState::Ringing)
                && call.inbound_invite_branch.as_deref() == cancel_branch.as_deref()
            {
                Some(cid)
            } else {
                None
            }
        });

        let resp_code = if matching_call.is_some() {
            (200, "OK")
        } else {
            (481, "Call/Transaction Does Not Exist")
        };
        if let Ok(resp) = request.create_response(resp_code.0, resp_code.1) {
            if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                self.process_transaction_events(events, now);
            }
        }

        if let Some(cid) = matching_call {
            if let Some(call) = self.calls.get(&cid) {
                if let (Some(inv_tx), Some(inv_req)) =
                    (&call.inbound_invite_tx, &call.inbound_invite_req)
                {
                    if let Ok(mut r487) = inv_req.create_response(487, "Request Terminated") {
                        if let Ok(mut to) = r487.to() {
                            to.tag = Some(call.local_tag.clone());
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
            Accept(String),
            OutOfOrder500,
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
                            ByeAction::OutOfOrder500
                        } else {
                            call.remote_cseq = Some(rc);
                            ByeAction::Accept(cid)
                        }
                    } else {
                        if let Some(rc) = req_cseq {
                            call.remote_cseq = Some(rc);
                        }
                        ByeAction::Accept(cid)
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
            ByeAction::Accept(cid) => {
                if let Ok(resp) = request.create_response(200, "OK") {
                    if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                        self.process_transaction_events(events, now);
                    }
                }
                self.terminate_call(&cid, Some(200), "Remote hangup".to_string());
            }
            ByeAction::OutOfOrder500 => {
                if let Ok(resp) = request.create_response(500, "Server Internal Error") {
                    if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                        self.process_transaction_events(events, now);
                    }
                }
            }
            ByeAction::NotFound481 => {
                if let Ok(resp) = request.create_response(481, "Call/Transaction Does Not Exist") {
                    if let Ok(events) = self.transactions.send_server_response(&tx_id, resp, now) {
                        self.process_transaction_events(events, now);
                    }
                }
            }
        }
    }

    fn on_ack_for_2xx(&mut self, ack: SipRequest) {
        if let Ok(cid) = ack.call_id() {
            if let Some(call) = self.calls.get_mut(cid) {
                call.awaiting_ack = None;
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
        let Some(call) = self.calls.get_mut(&call_id) else {
            return;
        };
        if call.active_invite_tx.as_ref() != Some(&tx_id) {
            return;
        }

        if let Ok(to) = response.to() {
            if let Some(tag) = to.tag {
                call.remote_tag = Some(tag);
            }
        }

        if response.status_code > 100 {
            let early_sdp = parse_optional_sdp(&response.body);
            if call.state == CallState::Calling {
                call.state = CallState::Ringing;
            }
            self.pending_events.push_back(UaEvent::CallRinging {
                call_id: call_id.clone(),
                status_code: response.status_code,
                early_sdp,
            });
        }

        // Send deferred CANCEL as soon as any 1xx provisional response arrives (RFC 3261 §9.1).
        if self.calls.get(&call_id).is_some_and(|c| c.pending_cancel) {
            if let Err(err) = self.send_cancel_for_call(&call_id, now) {
                self.pending_events
                    .push_back(UaEvent::ProtocolWarning(err.to_string()));
            }
        }
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
            CallTxKind::Cancel => {}
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
                self.reg_session.auth_attempts = 0;
                self.set_registration_state(RegistrationState::Unregistered);
                return;
            }
            let local_contact = self.config.contact_uri();
            let expires = extract_register_expires(&response, &local_contact)
                .unwrap_or(self.reg_session.pending_expires)
                .max(1);
            let refresh_secs = ((expires as u64) * 4 / 5).max(1);
            let refresh_at = now + Duration::from_secs(refresh_secs);
            let expires_at = now + Duration::from_secs(expires as u64);
            self.reg_session.auth_attempts = 0;
            self.set_registration_state(RegistrationState::Registered {
                expires_secs: expires,
                refresh_at,
                expires_at,
            });
            return;
        }

        if code == 401 || code == 407 {
            let attempts = self.reg_session.auth_attempts;
            if let Ok((hdr_name, hdr_val, stale)) = self.compute_auth_header(
                &response,
                &Method::Register,
                &self.config.registrar_uri.to_string(),
            ) {
                let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                if can_retry {
                    let exp = self.reg_session.pending_expires;
                    if let Err(err) = self.start_register_with_expires(
                        exp,
                        Some((hdr_name, hdr_val)),
                        attempts.saturating_add(1),
                        now,
                    ) {
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

            if let Some(call) = self.calls.get_mut(call_id) {
                call.active_invite_tx = None;
                call.active_invite_req = None;
                call.pending_cancel = false;
                call.invite_auth_attempts = 0;

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
                        let negotiated = intersect_answer_codecs(&local_sdp, &remote_sdp);
                        call.remote_sdp = Some(remote_sdp.clone());
                        call.negotiated_codecs = negotiated.clone();
                        call.state = CallState::Established;
                        established_payload = Some((local_sdp, remote_sdp, negotiated));
                    }
                }

                let ack_snapshot = call.clone();
                let ack = self.build_ack_for_2xx(&ack_snapshot, cseq_num);
                if let Some(call_mut) = self.calls.get_mut(call_id) {
                    call_mut.last_ack_for_2xx = Some(ack.clone());
                }
                let _ = self.transactions.send_ack_for_2xx(ack);
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
            return;
        }

        if code == 401 || code == 407 {
            let retry_state = self.calls.get(call_id).and_then(|c| {
                if !c.pending_cancel && c.state != CallState::Cancelling {
                    let target_uri = if is_reinvite {
                        c.remote_target.to_string()
                    } else {
                        c.remote_uri.to_string()
                    };
                    Some((c.invite_auth_attempts, target_uri))
                } else {
                    None
                }
            });
            if let Some((attempts, target_uri)) = retry_state {
                if let Ok((hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Invite, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry {
                        let branch = self.next_branch();
                        let config_ref = &self.config;
                        let auth_hdr = (hdr_name, hdr_val);
                        let next_req = if let Some(call) = self.calls.get_mut(call_id) {
                            call.invite_auth_attempts = attempts.saturating_add(1);
                            call.local_cseq += 1;
                            call.local_sdp.clone().map(|sdp| {
                                if is_reinvite {
                                    Self::build_in_dialog_invite(
                                        config_ref,
                                        call,
                                        &branch,
                                        &sdp,
                                        Some(auth_hdr),
                                    )
                                } else {
                                    Self::build_invite_request(
                                        config_ref,
                                        call,
                                        &branch,
                                        &sdp,
                                        Some(auth_hdr),
                                    )
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

        if is_reinvite {
            // Re-INVITE rejection does not tear down an established dialog (RFC 3261 §14.1).
            if let Some(call) = self.calls.get_mut(call_id) {
                call.active_invite_tx = None;
                call.active_invite_req = None;
                call.state = CallState::Established;
            }
            self.pending_events
                .push_back(UaEvent::ProtocolWarning(format!(
                    "re-INVITE rejected with {code} {}",
                    response.reason_phrase
                )));
            return;
        }

        self.terminate_call(call_id, Some(code), response.reason_phrase);
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
                .map(|c| (c.bye_auth_attempts, c.remote_target.to_string()));
            if let Some((attempts, target_uri)) = retry_state {
                if let Ok((hdr_name, hdr_val, stale)) =
                    self.compute_auth_header(&response, &Method::Bye, &target_uri)
                {
                    let can_retry = attempts == 0 || (stale && attempts < MAX_STALE_AUTH_RETRIES);
                    if can_retry
                        && self
                            .send_bye_for_call(call_id, Some((hdr_name, hdr_val)), now)
                            .is_ok()
                    {
                        return;
                    }
                }
            }
        }

        self.terminate_call(call_id, Some(code), response.reason_phrase);
    }

    fn on_unmatched_2xx(&mut self, response: SipResponse) {
        let Ok(call_id) = response.call_id() else {
            return;
        };
        if let Some(call) = self.calls.get(call_id) {
            if let Some(ack) = &call.last_ack_for_2xx {
                let _ = self.transactions.send_ack_for_2xx(ack.clone());
            }
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
                    if let Some(call) = self.calls.get_mut(&call_id) {
                        call.active_invite_tx = None;
                        call.state = CallState::Established;
                    }
                    self.pending_events.push_back(UaEvent::ProtocolWarning(
                        "re-INVITE transaction timed out".to_string(),
                    ));
                }
                CallTxKind::Cancel => {}
            }
        }
    }

    fn terminate_call(&mut self, call_id: &str, status_code: Option<u16>, reason: String) {
        if let Some(mut call) = self.calls.remove(call_id) {
            call.state = CallState::Terminated;
            self.tx_to_call.retain(|_, (cid, _)| cid != call_id);
            self.pending_events.push_back(UaEvent::CallTerminated {
                call_id: call_id.to_string(),
                status_code,
                reason,
            });
        }
    }

    fn compute_auth_header(
        &mut self,
        response: &SipResponse,
        method: &Method,
        digest_uri: &str,
    ) -> Result<(&'static str, String, bool), SipError> {
        let (challenge_str, auth_header_name) = if response.status_code == 407 {
            (
                response
                    .headers
                    .get("Proxy-Authenticate")
                    .ok_or(SipError::MissingHeader("Proxy-Authenticate"))?,
                "Proxy-Authorization",
            )
        } else {
            (
                response
                    .headers
                    .get("WWW-Authenticate")
                    .ok_or(SipError::MissingHeader("WWW-Authenticate"))?,
                "Authorization",
            )
        };

        let challenge = DigestChallenge::parse(challenge_str)?;
        let stale = challenge.stale;
        let cnonce = self.next_cnonce();
        let creds = DigestCredentials::new(
            self.config.username.clone(),
            self.config.password.clone(),
            Some(cnonce),
        );
        let value = creds.authorize(&challenge, method, digest_uri)?;
        Ok((auth_header_name, value, stale))
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
