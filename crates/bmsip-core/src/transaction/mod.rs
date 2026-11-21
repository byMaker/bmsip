//! MODULE_CONTRACT: Sans-I/O RFC 3261 Section 17 transaction manager (`ICT`, `NICT`, `IST`, `NIST`).
//! INVARIANTS: All time progresses strictly via injected `now: Instant`; `ICT` auto-emits `ACK` on `3xx..=6xx` and terminates immediately on `2xx`; unmatched `2xx` responses (including in `IctState::Completed`) surface as `Unmatched2xx` for dialog-layer `ACK` retransmission; `IST` enters `Accepted` for `Timer L` (`64*T1`) on `2xx` per RFC 6026 to absorb `INVITE` retransmissions and routes `ACK` to `ServerAckReceived` or `AckFor2xx`; terminated transactions are immediately evicted.
//! RFC_REFS: RFC 3261 Sections 13.3.1.4, 17.1, 17.2, 18.1.2; RFC 6026 Sections 7.1, 7.2, 8.5.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::error::SipError;
use crate::sip::headers::CSeq;
use crate::sip::message::{SipMessage, SipRequest, SipResponse};
use crate::sip::method::Method;

/// RFC 3261 Section 17 transaction timer configuration (UDP defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RfcTimers {
    /// Base RTT estimate (`T1`), default 500 ms.
    pub t1: Duration,
    /// Maximum retransmit interval for non-INVITE & IST responses (`T2`), default 4 s.
    pub t2: Duration,
    /// Maximum duration a message remains in the network (`T4`), default 5 s.
    pub t4: Duration,
    /// Wait time for non-2xx INVITE response retransmits (`Timer D`), default 32 s.
    pub timer_d: Duration,
}

impl Default for RfcTimers {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
            timer_d: Duration::from_secs(32),
        }
    }
}

impl RfcTimers {
    fn safe_t1(self) -> Duration {
        self.t1.max(Duration::from_millis(1))
    }

    fn safe_t2(self) -> Duration {
        self.t2.max(self.safe_t1())
    }

    fn timer_b(self) -> Duration {
        self.safe_t1() * 64
    }

    fn timer_f(self) -> Duration {
        self.safe_t1() * 64
    }

    fn timer_h(self) -> Duration {
        self.safe_t1() * 64
    }

    fn timer_j(self) -> Duration {
        self.safe_t1() * 64
    }

    fn timer_l(self) -> Duration {
        self.safe_t1() * 64
    }
}

/// Unique key identifying a SIP transaction (`Via` branch + CSeq/request method).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId {
    pub branch: String,
    pub method: Method,
}

/// Events emitted by the Sans-I/O [`TransactionManager`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionEvent {
    /// A new incoming SIP request created a server transaction.
    ServerRequest {
        tx_id: TransactionId,
        request: SipRequest,
    },
    /// An end-to-end `ACK` for a `2xx` INVITE response (outside server transaction).
    AckFor2xx(SipRequest),
    /// Server INVITE transaction received `ACK` for its `300..=699` final response.
    ServerAckReceived(TransactionId),
    /// Client transaction received a provisional (`100..=199`) response.
    ClientProvisional {
        tx_id: TransactionId,
        response: SipResponse,
    },
    /// Client transaction received a final (`200..=699`) response.
    ClientFinal {
        tx_id: TransactionId,
        response: SipResponse,
    },
    /// A `2xx` response arrived after the client transaction terminated (RFC 3261 18.1.2).
    Unmatched2xx(SipResponse),
    /// Transaction timed out (Timer B, F, or H fired).
    TransactionTimeout(TransactionId),
    /// Transaction completed and was reclaimed.
    TransactionTerminated(TransactionId),
    /// Incoming SIP message was ignored due to missing/invalid transaction headers.
    ProtocolWarning(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NictState {
    Trying,
    Proceeding,
    Completed,
    Terminated,
}

#[derive(Debug, Clone)]
struct ClientNonInviteTransaction {
    state: NictState,
    reliable: bool,
    request_bytes: Vec<u8>,
    timer_e: Option<Instant>,
    timer_e_interval: Duration,
    timer_f: Option<Instant>,
    timer_k: Option<Instant>,
}

impl ClientNonInviteTransaction {
    fn new(request_bytes: Vec<u8>, reliable: bool, now: Instant, timers: RfcTimers) -> Self {
        let t1 = timers.safe_t1();
        Self {
            state: NictState::Trying,
            reliable,
            request_bytes,
            // RFC 3261 §17.1.2.2: Timer E is only used on unreliable transports (UDP).
            timer_e: if reliable { None } else { Some(now + t1) },
            timer_e_interval: t1,
            timer_f: Some(now + timers.timer_f()),
            timer_k: None,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        earliest_instant([self.timer_e, self.timer_f, self.timer_k])
    }

    fn on_response(
        &mut self,
        tx_id: &TransactionId,
        resp: SipResponse,
        now: Instant,
        timers: RfcTimers,
        events: &mut Vec<TransactionEvent>,
    ) {
        let code = resp.status_code;
        match self.state {
            NictState::Trying | NictState::Proceeding => {
                if (100..200).contains(&code) {
                    if self.state == NictState::Trying {
                        self.state = NictState::Proceeding;
                        if !self.reliable {
                            let t2 = timers.safe_t2();
                            self.timer_e_interval = t2;
                            self.timer_e = Some(now + t2);
                        }
                    }
                    events.push(TransactionEvent::ClientProvisional {
                        tx_id: tx_id.clone(),
                        response: resp,
                    });
                } else if (200..700).contains(&code) {
                    self.timer_e = None;
                    self.timer_f = None;
                    events.push(TransactionEvent::ClientFinal {
                        tx_id: tx_id.clone(),
                        response: resp,
                    });
                    // RFC 3261 §17.1.2.2: Timer K = 0 s for reliable transports.
                    if self.reliable || timers.t4.is_zero() {
                        self.state = NictState::Terminated;
                        events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                    } else {
                        self.state = NictState::Completed;
                        self.timer_k = Some(now + timers.t4);
                    }
                }
            }
            NictState::Completed | NictState::Terminated => {}
        }
    }

    fn on_timeout(
        &mut self,
        tx_id: &TransactionId,
        now: Instant,
        timers: RfcTimers,
        outbound: &mut VecDeque<Vec<u8>>,
        events: &mut Vec<TransactionEvent>,
    ) {
        match self.state {
            NictState::Trying | NictState::Proceeding => {
                if self.timer_f.is_some_and(|dl| now >= dl) {
                    self.state = NictState::Terminated;
                    self.timer_e = None;
                    self.timer_f = None;
                    events.push(TransactionEvent::TransactionTimeout(tx_id.clone()));
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                    return;
                }
                if self.timer_e.is_some_and(|dl| now >= dl) {
                    outbound.push_back(self.request_bytes.clone());
                    let next_interval = match self.state {
                        NictState::Trying => (self.timer_e_interval * 2).min(timers.safe_t2()),
                        NictState::Proceeding => timers.safe_t2(),
                        NictState::Completed | NictState::Terminated => timers.safe_t2(),
                    };
                    self.timer_e_interval = next_interval;
                    self.timer_e = Some(now + next_interval);
                }
            }
            NictState::Completed => {
                if self.timer_k.is_some_and(|dl| now >= dl) {
                    self.state = NictState::Terminated;
                    self.timer_k = None;
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                }
            }
            NictState::Terminated => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IctState {
    Calling,
    Proceeding,
    Completed,
    Terminated,
}

#[derive(Debug, Clone)]
struct ClientInviteTransaction {
    state: IctState,
    reliable: bool,
    original_request: SipRequest,
    request_bytes: Vec<u8>,
    ack_bytes: Option<Vec<u8>>,
    timer_a: Option<Instant>,
    timer_a_interval: Duration,
    timer_b: Option<Instant>,
    timer_d: Option<Instant>,
}

impl ClientInviteTransaction {
    fn new(
        original_request: SipRequest,
        request_bytes: Vec<u8>,
        reliable: bool,
        now: Instant,
        timers: RfcTimers,
    ) -> Self {
        let t1 = timers.safe_t1();
        Self {
            state: IctState::Calling,
            reliable,
            original_request,
            request_bytes,
            ack_bytes: None,
            // RFC 3261 §17.1.1.2: Timer A is only used on unreliable transports (UDP).
            timer_a: if reliable { None } else { Some(now + t1) },
            timer_a_interval: t1,
            timer_b: Some(now + timers.timer_b()),
            timer_d: None,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        earliest_instant([self.timer_a, self.timer_b, self.timer_d])
    }

    fn on_response(
        &mut self,
        tx_id: &TransactionId,
        resp: SipResponse,
        now: Instant,
        timers: RfcTimers,
        outbound: &mut VecDeque<Vec<u8>>,
        events: &mut Vec<TransactionEvent>,
    ) {
        let code = resp.status_code;
        match self.state {
            IctState::Calling | IctState::Proceeding => {
                if (100..200).contains(&code) {
                    self.state = IctState::Proceeding;
                    self.timer_a = None;
                    self.timer_b = None;
                    events.push(TransactionEvent::ClientProvisional {
                        tx_id: tx_id.clone(),
                        response: resp,
                    });
                } else if (200..300).contains(&code) {
                    self.timer_a = None;
                    self.timer_b = None;
                    self.state = IctState::Terminated;
                    events.push(TransactionEvent::ClientFinal {
                        tx_id: tx_id.clone(),
                        response: resp,
                    });
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                } else if (300..700).contains(&code) {
                    self.timer_a = None;
                    self.timer_b = None;
                    let ack_bytes = build_non2xx_ack(&self.original_request, &resp);
                    outbound.push_back(ack_bytes.clone());
                    self.ack_bytes = Some(ack_bytes);
                    events.push(TransactionEvent::ClientFinal {
                        tx_id: tx_id.clone(),
                        response: resp,
                    });
                    // RFC 3261 §17.1.1.2: Timer D = 0 s for reliable transports.
                    if self.reliable || timers.timer_d.is_zero() {
                        self.state = IctState::Terminated;
                        events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                    } else {
                        self.state = IctState::Completed;
                        self.timer_d = Some(now + timers.timer_d);
                    }
                }
            }
            IctState::Completed => {
                if (200..300).contains(&code) {
                    // RFC 6026 §7.2: 2xx arriving during Timer D must reach TU for ACK+BYE.
                    events.push(TransactionEvent::Unmatched2xx(resp));
                } else if (300..700).contains(&code) {
                    if let Some(ack) = &self.ack_bytes {
                        outbound.push_back(ack.clone());
                    }
                }
            }
            IctState::Terminated => {}
        }
    }

    fn on_timeout(
        &mut self,
        tx_id: &TransactionId,
        now: Instant,
        outbound: &mut VecDeque<Vec<u8>>,
        events: &mut Vec<TransactionEvent>,
    ) {
        match self.state {
            IctState::Calling => {
                if self.timer_b.is_some_and(|dl| now >= dl) {
                    self.state = IctState::Terminated;
                    self.timer_a = None;
                    self.timer_b = None;
                    events.push(TransactionEvent::TransactionTimeout(tx_id.clone()));
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                    return;
                }
                if self.timer_a.is_some_and(|dl| now >= dl) {
                    outbound.push_back(self.request_bytes.clone());
                    self.timer_a_interval *= 2;
                    self.timer_a = Some(now + self.timer_a_interval);
                }
            }
            IctState::Completed => {
                if self.timer_d.is_some_and(|dl| now >= dl) {
                    self.state = IctState::Terminated;
                    self.timer_d = None;
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                }
            }
            IctState::Proceeding | IctState::Terminated => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NistState {
    Trying,
    Proceeding,
    Completed,
    Terminated,
}

#[derive(Debug, Clone)]
struct ServerNonInviteTransaction {
    state: NistState,
    reliable: bool,
    last_response: Option<Vec<u8>>,
    timer_j: Option<Instant>,
}

impl ServerNonInviteTransaction {
    fn new(reliable: bool) -> Self {
        Self {
            state: NistState::Trying,
            reliable,
            last_response: None,
            timer_j: None,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        self.timer_j
    }

    fn on_retransmit(&self, outbound: &mut VecDeque<Vec<u8>>) {
        match self.state {
            NistState::Proceeding | NistState::Completed => {
                if let Some(resp) = &self.last_response {
                    outbound.push_back(resp.clone());
                }
            }
            NistState::Trying | NistState::Terminated => {}
        }
    }

    fn send_response(
        &mut self,
        tx_id: &TransactionId,
        resp: &SipResponse,
        now: Instant,
        timers: RfcTimers,
        outbound: &mut VecDeque<Vec<u8>>,
        events: &mut Vec<TransactionEvent>,
    ) -> Result<(), SipError> {
        let code = resp.status_code;
        match self.state {
            NistState::Trying | NistState::Proceeding => {
                let bytes = resp.to_bytes();
                outbound.push_back(bytes.clone());
                self.last_response = Some(bytes);
                if (100..200).contains(&code) {
                    self.state = NistState::Proceeding;
                } else if (200..700).contains(&code) {
                    self.state = NistState::Completed;
                    let j = timers.timer_j();
                    // RFC 3261 §17.2.2: Timer J = 0 s for reliable transports.
                    if self.reliable || j.is_zero() {
                        self.state = NistState::Terminated;
                        events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                    } else {
                        self.timer_j = Some(now + j);
                    }
                }
                Ok(())
            }
            NistState::Completed | NistState::Terminated => Err(SipError::TransactionError(
                "cannot send response on completed server transaction".to_string(),
            )),
        }
    }

    fn on_timeout(
        &mut self,
        tx_id: &TransactionId,
        now: Instant,
        events: &mut Vec<TransactionEvent>,
    ) {
        if self.state == NistState::Completed && self.timer_j.is_some_and(|dl| now >= dl) {
            self.state = NistState::Terminated;
            self.timer_j = None;
            events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IstState {
    Proceeding,
    Accepted,
    Completed,
    Confirmed,
    Terminated,
}

#[derive(Debug, Clone)]
struct ServerInviteTransaction {
    state: IstState,
    reliable: bool,
    last_provisional: Option<Vec<u8>>,
    final_response: Option<Vec<u8>>,
    timer_g: Option<Instant>,
    timer_g_interval: Duration,
    timer_h: Option<Instant>,
    timer_i: Option<Instant>,
    timer_l: Option<Instant>,
}

impl ServerInviteTransaction {
    fn new(reliable: bool) -> Self {
        Self {
            state: IstState::Proceeding,
            reliable,
            last_provisional: None,
            final_response: None,
            timer_g: None,
            timer_g_interval: Duration::ZERO,
            timer_h: None,
            timer_i: None,
            timer_l: None,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        earliest_instant([self.timer_g, self.timer_h, self.timer_i, self.timer_l])
    }

    fn on_retransmit(&self, outbound: &mut VecDeque<Vec<u8>>) {
        match self.state {
            IstState::Proceeding => {
                if let Some(prov) = &self.last_provisional {
                    outbound.push_back(prov.clone());
                }
            }
            IstState::Completed => {
                if let Some(fin) = &self.final_response {
                    outbound.push_back(fin.clone());
                }
            }
            IstState::Accepted | IstState::Confirmed | IstState::Terminated => {}
        }
    }

    fn on_ack(
        &mut self,
        tx_id: &TransactionId,
        now: Instant,
        timers: RfcTimers,
        events: &mut Vec<TransactionEvent>,
    ) {
        if self.state == IstState::Completed {
            self.timer_g = None;
            self.timer_h = None;
            events.push(TransactionEvent::ServerAckReceived(tx_id.clone()));
            // RFC 3261 §17.2.1: Timer I = 0 s for reliable transports.
            if self.reliable || timers.t4.is_zero() {
                self.state = IstState::Terminated;
                events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
            } else {
                self.state = IstState::Confirmed;
                self.timer_i = Some(now + timers.t4);
            }
        }
    }

    fn send_response(
        &mut self,
        _tx_id: &TransactionId,
        resp: &SipResponse,
        now: Instant,
        timers: RfcTimers,
        outbound: &mut VecDeque<Vec<u8>>,
        _events: &mut Vec<TransactionEvent>,
    ) -> Result<(), SipError> {
        let code = resp.status_code;
        if self.state != IstState::Proceeding {
            return Err(SipError::TransactionError(
                "cannot send response on non-proceeding INVITE server transaction".to_string(),
            ));
        }

        let bytes = resp.to_bytes();
        outbound.push_back(bytes.clone());

        if (100..200).contains(&code) {
            self.last_provisional = Some(bytes);
        } else if (200..300).contains(&code) {
            // RFC 6026 §7.1: enter `Accepted` for Timer L (64*T1) to absorb retransmitted INVITEs
            // regardless of transport reliability.
            self.state = IstState::Accepted;
            self.timer_l = Some(now + timers.timer_l());
        } else if (300..700).contains(&code) {
            self.final_response = Some(bytes);
            self.state = IstState::Completed;
            let t1 = timers.safe_t1();
            self.timer_g_interval = t1;
            // RFC 3261 §17.2.1: Timer G is only used on unreliable transports (UDP).
            self.timer_g = if self.reliable { None } else { Some(now + t1) };
            self.timer_h = Some(now + timers.timer_h());
        }
        Ok(())
    }

    fn on_timeout(
        &mut self,
        tx_id: &TransactionId,
        now: Instant,
        timers: RfcTimers,
        outbound: &mut VecDeque<Vec<u8>>,
        events: &mut Vec<TransactionEvent>,
    ) {
        match self.state {
            IstState::Completed => {
                if self.timer_h.is_some_and(|dl| now >= dl) {
                    self.state = IstState::Terminated;
                    self.timer_g = None;
                    self.timer_h = None;
                    events.push(TransactionEvent::TransactionTimeout(tx_id.clone()));
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                    return;
                }
                if self.timer_g.is_some_and(|dl| now >= dl) {
                    if let Some(fin) = &self.final_response {
                        outbound.push_back(fin.clone());
                    }
                    self.timer_g_interval = (self.timer_g_interval * 2).min(timers.safe_t2());
                    self.timer_g = Some(now + self.timer_g_interval);
                }
            }
            IstState::Accepted => {
                if self.timer_l.is_some_and(|dl| now >= dl) {
                    self.state = IstState::Terminated;
                    self.timer_l = None;
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                }
            }
            IstState::Confirmed => {
                if self.timer_i.is_some_and(|dl| now >= dl) {
                    self.state = IstState::Terminated;
                    self.timer_i = None;
                    events.push(TransactionEvent::TransactionTerminated(tx_id.clone()));
                }
            }
            IstState::Proceeding | IstState::Terminated => {}
        }
    }
}

#[derive(Debug, Clone)]
enum ClientTx {
    Invite(Box<ClientInviteTransaction>),
    NonInvite(ClientNonInviteTransaction),
}

impl ClientTx {
    fn is_terminated(&self) -> bool {
        match self {
            Self::Invite(tx) => tx.state == IctState::Terminated,
            Self::NonInvite(tx) => tx.state == NictState::Terminated,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        match self {
            Self::Invite(tx) => tx.next_timeout(),
            Self::NonInvite(tx) => tx.next_timeout(),
        }
    }
}

#[derive(Debug, Clone)]
enum ServerTx {
    Invite(ServerInviteTransaction),
    NonInvite(ServerNonInviteTransaction),
}

impl ServerTx {
    fn is_terminated(&self) -> bool {
        match self {
            Self::Invite(tx) => tx.state == IstState::Terminated,
            Self::NonInvite(tx) => tx.state == NistState::Terminated,
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        match self {
            Self::Invite(tx) => tx.next_timeout(),
            Self::NonInvite(tx) => tx.next_timeout(),
        }
    }
}

/// Pure Sans-I/O RFC 3261 Section 17 transaction manager.
#[derive(Debug, Clone)]
pub struct TransactionManager {
    timers: RfcTimers,
    client_txs: HashMap<TransactionId, ClientTx>,
    server_txs: HashMap<TransactionId, ServerTx>,
    outbound: VecDeque<Vec<u8>>,
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new(RfcTimers::default())
    }
}

impl TransactionManager {
    /// Creates a new transaction manager with the specified RFC 3261 timers.
    pub fn new(timers: RfcTimers) -> Self {
        Self {
            timers,
            client_txs: HashMap::new(),
            server_txs: HashMap::new(),
            outbound: VecDeque::new(),
        }
    }

    /// Starts a new client transaction (`INVITE` or non-`INVITE`) and queues its wire bytes.
    pub fn start_client_transaction(
        &mut self,
        request: SipRequest,
        now: Instant,
    ) -> Result<TransactionId, SipError> {
        if request.method == Method::Ack {
            return Err(SipError::TransactionError(
                "ACK does not create a client transaction; use send_ack_for_2xx".to_string(),
            ));
        }

        let via = request.top_via()?;
        let reliable = is_reliable_via_transport(&via.transport);
        let branch = via
            .branch
            .filter(|b| !b.is_empty())
            .ok_or(SipError::MissingHeader("Via branch"))?;
        let cseq = request.cseq()?;
        if cseq.method != request.method {
            return Err(SipError::TransactionError(format!(
                "CSeq method {} does not match request method {}",
                cseq.method, request.method
            )));
        }
        let _ = request.from()?;
        let _ = request.to()?;
        let _ = request.call_id()?;

        let tx_id = TransactionId {
            branch,
            method: request.method.clone(),
        };
        if self.client_txs.contains_key(&tx_id) {
            return Err(SipError::TransactionError(format!(
                "duplicate client transaction {:?}",
                tx_id
            )));
        }

        let bytes = request.to_bytes();
        self.outbound.push_back(bytes.clone());

        let tx = if request.method == Method::Invite {
            ClientTx::Invite(Box::new(ClientInviteTransaction::new(
                request,
                bytes,
                reliable,
                now,
                self.timers,
            )))
        } else {
            ClientTx::NonInvite(ClientNonInviteTransaction::new(
                bytes,
                reliable,
                now,
                self.timers,
            ))
        };

        self.client_txs.insert(tx_id.clone(), tx);
        Ok(tx_id)
    }

    /// Queues an end-to-end `ACK` request for a `2xx` `INVITE` response.
    pub fn send_ack_for_2xx(&mut self, ack: SipRequest) -> Result<(), SipError> {
        if ack.method != Method::Ack {
            return Err(SipError::TransactionError(
                "send_ack_for_2xx requires an ACK request".to_string(),
            ));
        }
        self.outbound.push_back(ack.to_bytes());
        Ok(())
    }

    /// Queues a stateless or TU-retransmitted response (e.g. `2xx` `INVITE` retransmit).
    pub fn send_stateless_response(&mut self, response: SipResponse) {
        self.outbound.push_back(response.to_bytes());
    }

    /// Processes an inbound parsed SIP message against active transactions.
    pub fn receive_message(&mut self, msg: SipMessage, now: Instant) -> Vec<TransactionEvent> {
        let mut events = Vec::new();
        match msg {
            SipMessage::Response(resp) => {
                let branch = match resp.top_via().and_then(|v| {
                    v.branch
                        .filter(|b| !b.is_empty())
                        .ok_or(SipError::MissingHeader("Via branch"))
                }) {
                    Ok(b) => b,
                    Err(err) => {
                        events.push(TransactionEvent::ProtocolWarning(err.to_string()));
                        return events;
                    }
                };
                let cseq = match resp.cseq() {
                    Ok(c) => c,
                    Err(err) => {
                        events.push(TransactionEvent::ProtocolWarning(err.to_string()));
                        return events;
                    }
                };
                let tx_id = TransactionId {
                    branch,
                    method: cseq.method,
                };

                if let Some(tx) = self.client_txs.get_mut(&tx_id) {
                    match tx {
                        ClientTx::Invite(ict) => ict.on_response(
                            &tx_id,
                            resp,
                            now,
                            self.timers,
                            &mut self.outbound,
                            &mut events,
                        ),
                        ClientTx::NonInvite(nict) => {
                            nict.on_response(&tx_id, resp, now, self.timers, &mut events)
                        }
                    }
                    if tx.is_terminated() {
                        self.client_txs.remove(&tx_id);
                    }
                } else if (200..300).contains(&resp.status_code) {
                    events.push(TransactionEvent::Unmatched2xx(resp));
                }
            }
            SipMessage::Request(req) => {
                let (branch, reliable) = match req.top_via().and_then(|v| {
                    let rel = is_reliable_via_transport(&v.transport);
                    let b = v
                        .branch
                        .filter(|b| !b.is_empty())
                        .ok_or(SipError::MissingHeader("Via branch"))?;
                    Ok((b, rel))
                }) {
                    Ok(pair) => pair,
                    Err(err) => {
                        events.push(TransactionEvent::ProtocolWarning(err.to_string()));
                        return events;
                    }
                };

                if req.method == Method::Ack {
                    let invite_id = TransactionId {
                        branch,
                        method: Method::Invite,
                    };
                    if let Some(ServerTx::Invite(ist)) = self.server_txs.get_mut(&invite_id) {
                        if ist.state == IstState::Accepted {
                            events.push(TransactionEvent::AckFor2xx(req));
                        } else {
                            ist.on_ack(&invite_id, now, self.timers, &mut events);
                            if ist.state == IstState::Terminated {
                                self.server_txs.remove(&invite_id);
                            }
                        }
                    } else {
                        events.push(TransactionEvent::AckFor2xx(req));
                    }
                    return events;
                }

                let tx_id = TransactionId {
                    branch,
                    method: req.method.clone(),
                };
                if let Some(existing) = self.server_txs.get(&tx_id) {
                    match existing {
                        ServerTx::Invite(ist) => ist.on_retransmit(&mut self.outbound),
                        ServerTx::NonInvite(nist) => nist.on_retransmit(&mut self.outbound),
                    }
                    return events;
                }

                let tx = if req.method == Method::Invite {
                    ServerTx::Invite(ServerInviteTransaction::new(reliable))
                } else {
                    ServerTx::NonInvite(ServerNonInviteTransaction::new(reliable))
                };
                self.server_txs.insert(tx_id.clone(), tx);
                events.push(TransactionEvent::ServerRequest {
                    tx_id,
                    request: req,
                });
            }
        }
        events
    }

    /// Sends a provisional or final response for an active server transaction.
    pub fn send_server_response(
        &mut self,
        tx_id: &TransactionId,
        response: SipResponse,
        now: Instant,
    ) -> Result<Vec<TransactionEvent>, SipError> {
        let mut events = Vec::new();
        let tx = self.server_txs.get_mut(tx_id).ok_or_else(|| {
            SipError::TransactionError(format!("unknown server transaction {:?}", tx_id))
        })?;

        match tx {
            ServerTx::Invite(ist) => {
                ist.send_response(
                    tx_id,
                    &response,
                    now,
                    self.timers,
                    &mut self.outbound,
                    &mut events,
                )?;
            }
            ServerTx::NonInvite(nist) => {
                nist.send_response(
                    tx_id,
                    &response,
                    now,
                    self.timers,
                    &mut self.outbound,
                    &mut events,
                )?;
            }
        }

        if tx.is_terminated() {
            self.server_txs.remove(tx_id);
        }
        Ok(events)
    }

    /// Returns the earliest pending timer deadline across all active transactions.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let client_min = self
            .client_txs
            .values()
            .filter_map(ClientTx::next_timeout)
            .min();
        let server_min = self
            .server_txs
            .values()
            .filter_map(ServerTx::next_timeout)
            .min();
        earliest_instant([client_min, server_min])
    }

    /// Advances transaction timers up to `now`, queuing retransmissions and emitting events.
    pub fn handle_timeout(&mut self, now: Instant) -> Vec<TransactionEvent> {
        let mut events = Vec::new();

        let client_keys: Vec<TransactionId> = self.client_txs.keys().cloned().collect();
        for key in client_keys {
            let terminated = if let Some(tx) = self.client_txs.get_mut(&key) {
                match tx {
                    ClientTx::Invite(ict) => {
                        ict.on_timeout(&key, now, &mut self.outbound, &mut events)
                    }
                    ClientTx::NonInvite(nict) => {
                        nict.on_timeout(&key, now, self.timers, &mut self.outbound, &mut events)
                    }
                }
                tx.is_terminated()
            } else {
                false
            };
            if terminated {
                self.client_txs.remove(&key);
            }
        }

        let server_keys: Vec<TransactionId> = self.server_txs.keys().cloned().collect();
        for key in server_keys {
            let terminated = if let Some(tx) = self.server_txs.get_mut(&key) {
                match tx {
                    ServerTx::Invite(ist) => {
                        ist.on_timeout(&key, now, self.timers, &mut self.outbound, &mut events)
                    }
                    ServerTx::NonInvite(nist) => nist.on_timeout(&key, now, &mut events),
                }
                tx.is_terminated()
            } else {
                false
            };
            if terminated {
                self.server_txs.remove(&key);
            }
        }

        events
    }

    /// Drains all outbound SIP messages queued for network transmission.
    pub fn poll_transmit(&mut self) -> Vec<Vec<u8>> {
        self.outbound.drain(..).collect()
    }

    /// Returns the number of active (unterminated) client transactions.
    pub fn active_client_count(&self) -> usize {
        self.client_txs.len()
    }

    /// Returns the number of active (unterminated) server transactions.
    pub fn active_server_count(&self) -> usize {
        self.server_txs.len()
    }
}

fn earliest_instant<const N: usize>(candidates: [Option<Instant>; N]) -> Option<Instant> {
    candidates.into_iter().flatten().min()
}

fn is_reliable_via_transport(proto: &str) -> bool {
    proto.eq_ignore_ascii_case("TCP") || proto.eq_ignore_ascii_case("TLS")
}

/// Builds a hop-by-hop `ACK` request for a `300..=699` `INVITE` response (RFC 3261 Section 17.1.1.3).
fn build_non2xx_ack(invite: &SipRequest, response: &SipResponse) -> Vec<u8> {
    let mut ack = SipRequest::new(Method::Ack, invite.uri.clone());

    if let Some(via) = invite.headers.get("Via") {
        ack.headers.add("Via", via);
    }
    for route in invite.headers.get_all("Route") {
        ack.headers.add("Route", route);
    }
    if let Some(from) = invite.headers.get("From") {
        ack.headers.set("From", from);
    }
    if let Some(to) = response.headers.get("To") {
        ack.headers.set("To", to);
    } else if let Some(to) = invite.headers.get("To") {
        ack.headers.set("To", to);
    }
    if let Some(call_id) = invite.headers.get("Call-ID") {
        ack.headers.set("Call-ID", call_id);
    }
    let seq = invite.cseq().map(|c| c.seq).unwrap_or(1);
    ack.headers
        .set("CSeq", CSeq::new(seq, Method::Ack).to_string());
    ack.headers.set("Max-Forwards", "70");
    ack.headers.set("Content-Length", "0");

    ack.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::SipUri;

    #[test]
    fn reliable_tcp_tls_transactions_disable_retransmits_and_terminate_immediately() {
        let t0 = Instant::now();
        let mut client = TransactionManager::default();
        let mut server = TransactionManager::default();

        let mut req = SipRequest::new(Method::Options, SipUri::parse("sip:bob@10.0.0.2").unwrap());
        req.headers
            .add("Via", "SIP/2.0/TLS 10.0.0.1:5061;branch=z9hG4bK-tls-1");
        req.headers.set("From", "<sip:alice@pbx.local>;tag=a1");
        req.headers.set("To", "<sip:bob@pbx.local>");
        req.headers.set("Call-ID", "tls-tx-1");
        req.headers.set("CSeq", "1 OPTIONS");

        let _ = client.start_client_transaction(req, t0).unwrap();
        let out = client.poll_transmit();
        assert_eq!(out.len(), 1);

        // Advance past T1 (500ms) and T2 (4s) — reliable NICT must NOT retransmit (Timer E = None).
        let _ = client.handle_timeout(t0 + Duration::from_secs(10));
        assert!(client.poll_transmit().is_empty());
        assert_eq!(client.active_client_count(), 1);

        // Server receives request and replies 200 OK -> NIST terminates immediately (Timer J = 0).
        let srv_evs = server.receive_message(SipMessage::parse(&out[0]).unwrap(), t0);
        let TransactionEvent::ServerRequest { tx_id, request } = &srv_evs[0] else {
            panic!("expected ServerRequest");
        };
        let r200 = request.create_response(200, "OK").unwrap();
        let _ = server.send_server_response(tx_id, r200, t0).unwrap();
        assert_eq!(server.active_server_count(), 0);

        // Client receives 200 OK -> NICT terminates immediately (Timer K = 0).
        let resp_wire = server.poll_transmit();
        let cli_evs = client.receive_message(SipMessage::parse(&resp_wire[0]).unwrap(), t0);
        assert!(cli_evs
            .iter()
            .any(|e| matches!(e, TransactionEvent::ClientFinal { .. })));
        assert_eq!(client.active_client_count(), 0);
    }
}
