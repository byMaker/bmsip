//! MODULE_CONTRACT: Multi-instance [`SipEngine`] runtime driving `bmsip_core::dialog::UserAgent` and `bmsip_media::MediaSession` over UDP/TCP/TLS (`rustls`) sockets and monotonic timers.
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero global state or `static mut`; zero callbacks invoked under held locks; thread-safe `Send + Sync` queues; deterministic cleanup on `Shutdown` or `Drop`.
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733, RFC 5626, RFC 5922, RFC 5923.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bmsip_core::dialog::{CallState, RegistrationState, UaEvent, UserAgent};
use bmsip_core::sdp::{NegotiatedSrtp, RtpCodec, SrtpMode};
use bmsip_core::sip::{Method, NameAddr, SipMessage, SipTransport, SipUri};
use bmsip_media::{
    AudioCodecPlugin, CodecRegistry, G711Kind, JitterBufferConfig, MediaSession, OpusCodecBackend,
    SessionCodec, CN_PAYLOAD_TYPE, G722_PAYLOAD_TYPE, PCM_FRAME_SAMPLES_16KHZ_20MS,
    PCM_FRAME_SAMPLES_48KHZ_20MS, PCM_FRAME_SAMPLES_8KHZ_20MS,
};
use ring::rand::{SecureRandom, SystemRandom};

use crate::audio::AudioPort;
use crate::command::{EngineCommand, EngineConfig, EngineEvent};
use crate::error::EngineError;
use crate::opus_native::LibOpusCodec;
use crate::telemetry::{FlightRecorder, TelemetryCategory};
use crate::transport::SipTransportDriver;

const MEDIA_TICK_MS: u64 = 20;
const WORKER_ACTIVE_POLL_MS: u64 = 5;
const WORKER_IDLE_POLL_MS: u64 = 20;
const RTCP_REPORT_INTERVAL_MS: u64 = 5_000;
const MAX_TRACKED_SIP_ROUTES: usize = 512;
const DNS_POSITIVE_TTL: Duration = Duration::from_secs(60);
const DNS_NEGATIVE_TTL: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum DnsCacheEntry {
    Positive {
        addr: SocketAddr,
        expires_at: Instant,
        seq: u64,
    },
    Negative {
        expires_at: Instant,
        seq: u64,
    },
}

impl DnsCacheEntry {
    fn expires_at(self) -> Instant {
        match self {
            Self::Positive { expires_at, .. } | Self::Negative { expires_at, .. } => expires_at,
        }
    }

    fn seq(self) -> u64 {
        match self {
            Self::Positive { seq, .. } | Self::Negative { seq, .. } => seq,
        }
    }

    fn set_seq(&mut self, new_seq: u64) {
        match self {
            Self::Positive { seq, .. } | Self::Negative { seq, .. } => *seq = new_seq,
        }
    }
}

fn generate_csprng_u64() -> Result<u64, EngineError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 8];
    rng.fill(&mut bytes)
        .map_err(|_| EngineError::Io("OS CSPRNG failed to generate instance seed".to_string()))?;
    let val = u64::from_le_bytes(bytes);
    Ok(if val == 0 { 1 } else { val })
}

fn generate_crypto_seed() -> Result<[u8; 32], EngineError> {
    let rng = SystemRandom::new();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).map_err(|_| {
        EngineError::Io("OS CSPRNG failed to generate SDES crypto seed".to_string())
    })?;
    Ok(seed)
}

struct CallMediaRuntime {
    rtp_socket: UdpSocket,
    rtcp_socket: Option<UdpSocket>,
    remote_rtp: SocketAddr,
    remote_rtcp: SocketAddr,
    rtcp_mux: bool,
    latched_rtp_source: Option<SocketAddr>,
    latched_rtcp_source: Option<SocketAddr>,
    session: MediaSession,
    started_at: Instant,
    rtp_packets_sent: u32,
    initial_rtcp_sent: bool,
    next_rtcp_at: Instant,
    local_hold: bool,
    remote_hold: bool,
}

struct SharedState {
    commands: Mutex<VecDeque<EngineCommand>>,
    cmd_cv: Condvar,
    events: Mutex<(VecDeque<EngineEvent>, bool)>,
    event_cv: Condvar,
    local_sip_addr: Mutex<SocketAddr>,
}

/// Cloneable receiver handle for [`EngineEvent`] notifications that does not contend on engine locks.
#[derive(Clone)]
pub struct EngineEventReceiver {
    shared: Arc<SharedState>,
}

impl EngineEventReceiver {
    /// Pops the next available [`EngineEvent`] without blocking.
    pub fn try_recv(&self) -> Option<EngineEvent> {
        let mut guard = self.shared.events.lock().unwrap_or_else(|e| e.into_inner());
        guard.0.pop_front()
    }

    /// Waits up to `timeout` for the next [`EngineEvent`].
    pub fn recv_timeout(&self, timeout: Duration) -> Option<EngineEvent> {
        let guard = self.shared.events.lock().unwrap_or_else(|e| e.into_inner());
        let (mut guard, _) = self
            .shared
            .event_cv
            .wait_timeout_while(guard, timeout, |state| state.0.is_empty() && !state.1)
            .unwrap_or_else(|e| e.into_inner());
        guard.0.pop_front()
    }
}

/// Lock-safe, multi-instance SIP & RTP runtime engine.
pub struct SipEngine {
    shared: Arc<SharedState>,
    worker: Option<JoinHandle<()>>,
}

impl SipEngine {
    /// Spawns a new independent [`SipEngine`] worker thread bound to `config.bind_ip:config.sip_port`.
    pub fn spawn(
        mut config: EngineConfig,
        audio_port: Box<dyn AudioPort>,
    ) -> Result<Self, EngineError> {
        if config.ua_config.srtp_mode == SrtpMode::SdesRequired
            && config.ua_config.transport != SipTransport::Tls
            && !config.ua_config.allow_insecure_cleartext_sdes
        {
            return Err(EngineError::InvalidConfig(
                "SrtpMode::SdesRequired requires SipTransport::Tls (RFC 4568 §8); set allow_insecure_cleartext_sdes only for isolated lab testing".to_string(),
            ));
        }

        let sip_transport = SipTransportDriver::new(
            config.ua_config.transport,
            config.bind_ip,
            config.sip_port,
            config.registrar_addr,
            config.ua_config.domain.clone(),
            &config.tls_config,
        )?;
        let advertised_addr = sip_transport.local_addr();
        let reachable_ip = advertised_addr.ip();
        let actual_port = advertised_addr.port();

        config.ua_config.local_host = reachable_ip.to_string();
        config.ua_config.local_sip_port = actual_port;
        if config.ua_config.instance_seed == 0 {
            config.ua_config.instance_seed = generate_csprng_u64()?;
        }
        if config.ua_config.crypto_seed == [0u8; 32] {
            config.ua_config.crypto_seed = generate_crypto_seed()?;
        }

        let opus_available = LibOpusCodec::new().is_ok();
        if !opus_available {
            config
                .ua_config
                .supported_codecs
                .retain(|c| !c.encoding_name.eq_ignore_ascii_case("opus"));
        }

        let shared = Arc::new(SharedState {
            commands: Mutex::new(VecDeque::new()),
            cmd_cv: Condvar::new(),
            events: Mutex::new((VecDeque::new(), false)),
            event_cv: Condvar::new(),
            local_sip_addr: Mutex::new(advertised_addr),
        });

        let worker_shared = Arc::clone(&shared);
        let panic_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("bmsip-engine".to_string())
            .spawn(move || {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(
                        config,
                        sip_transport,
                        advertised_addr,
                        audio_port,
                        opus_available,
                        worker_shared,
                    );
                }));
                if res.is_err() {
                    let mut guard = panic_shared
                        .events
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    guard.0.push_back(EngineEvent::Warning(
                        "engine worker panicked and stopped".to_string(),
                    ));
                    guard.0.push_back(EngineEvent::Stopped);
                    guard.1 = true;
                    panic_shared.event_cv.notify_all();
                }
            })
            .map_err(|e| EngineError::Io(e.to_string()))?;

        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    /// Returns a cloneable [`EngineEventReceiver`] for concurrent event polling.
    pub fn event_receiver(&self) -> EngineEventReceiver {
        EngineEventReceiver {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Enqueues a non-blocking command to the engine worker and wakes it immediately.
    pub fn send_command(&self, cmd: EngineCommand) -> Result<(), EngineError> {
        if self
            .shared
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
        {
            return Err(EngineError::ChannelClosed);
        }
        let mut guard = self
            .shared
            .commands
            .lock()
            .map_err(|_| EngineError::ChannelClosed)?;
        if self
            .shared
            .events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
        {
            return Err(EngineError::ChannelClosed);
        }
        guard.push_back(cmd);
        self.shared.cmd_cv.notify_one();
        Ok(())
    }

    /// Pops the next available [`EngineEvent`] without blocking.
    pub fn try_recv_event(&self) -> Option<EngineEvent> {
        let mut guard = self.shared.events.lock().unwrap_or_else(|e| e.into_inner());
        guard.0.pop_front()
    }

    /// Waits up to `timeout` for the next [`EngineEvent`].
    pub fn recv_event_timeout(&self, timeout: Duration) -> Option<EngineEvent> {
        let guard = self.shared.events.lock().unwrap_or_else(|e| e.into_inner());
        let (mut guard, _) = self
            .shared
            .event_cv
            .wait_timeout_while(guard, timeout, |state| state.0.is_empty() && !state.1)
            .unwrap_or_else(|e| e.into_inner());
        guard.0.pop_front()
    }

    /// Returns the currently active advertised SIP socket address.
    pub fn local_sip_addr(&self) -> SocketAddr {
        self.shared
            .local_sip_addr
            .lock()
            .map(|g| *g)
            .unwrap_or_else(|e| *e.into_inner())
    }

    /// Gracefully stops the engine worker and joins its thread.
    pub fn shutdown(mut self) -> Result<(), EngineError> {
        let _ = self.send_command(EngineCommand::Shutdown);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

impl Drop for SipEngine {
    fn drop(&mut self) {
        let _ = self.send_command(EngineCommand::Shutdown);
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

struct WorkerCtx {
    registrar_addr: SocketAddr,
    bind_ip: IpAddr,
    local_sip_addr: SocketAddr,
    sip_transport: SipTransportDriver,
    ua: UserAgent,
    codec_registry: CodecRegistry,
    opus_available: bool,
    audio_port: Box<dyn AudioPort>,
    recorder: FlightRecorder,
    pending_rtp_sockets: HashMap<String, (UdpSocket, Option<UdpSocket>)>,
    active_media: HashMap<String, CallMediaRuntime>,
    call_order: Vec<String>,
    focused_call_id: Option<String>,
    inbound_tx_sources: HashMap<(String, String, String), (SocketAddr, u64)>,
    inbound_call_sources: HashMap<String, (SocketAddr, u64)>,
    outbound_tx_targets: HashMap<String, (SocketAddr, u64)>,
    dns_cache: HashMap<(String, u16), DnsCacheEntry>,
    peer_tls_hosts: HashMap<SocketAddr, (String, u64)>,
    route_seq: u64,
    suspended: bool,
    was_registered_before_suspend: bool,
    udp_keepalive_interval: Option<Duration>,
    next_udp_keepalive_at: Option<Instant>,
    ssrc_counter: u32,
    shared: Arc<SharedState>,
}

const MAX_EVENT_QUEUE: usize = 4096;
const MAX_RTP_PACKETS_PER_TICK: usize = 128;

impl WorkerCtx {
    fn next_route_seq(&mut self) -> u64 {
        self.route_seq = self.route_seq.wrapping_add(1);
        self.route_seq
    }

    fn push_event(&self, ev: EngineEvent) {
        if let Ok(mut guard) = self.shared.events.lock() {
            while guard.0.len() >= MAX_EVENT_QUEUE {
                if let Some(pos) = guard
                    .0
                    .iter()
                    .position(|queued| !matches!(queued, EngineEvent::Stopped))
                {
                    guard.0.remove(pos);
                } else {
                    break;
                }
            }
            guard.0.push_back(ev);
            self.shared.event_cv.notify_all();
        }
    }

    fn resolve_sip_destination(&mut self, pkt: &[u8], now: Instant) -> SocketAddr {
        let Ok(msg) = SipMessage::parse(pkt) else {
            return self.registrar_addr;
        };
        let default_port = self.ua.transport().default_port();
        match msg {
            SipMessage::Response(resp) => {
                // RFC 3581 / RFC 3261 §18.2.2: route server responses back to the exact peer source.
                if let (Ok(via), Ok(cseq)) = (resp.top_via(), resp.cseq()) {
                    if let Some(branch) = via.branch.as_deref() {
                        let key = (
                            branch.to_string(),
                            via.sent_by.trim().to_ascii_lowercase(),
                            cseq.method.as_str().to_string(),
                        );
                        if let Some((src, _)) = self.inbound_tx_sources.get(&key) {
                            let src = *src;
                            let seq = self.next_route_seq();
                            if let Some(entry) = self.inbound_tx_sources.get_mut(&key) {
                                entry.1 = seq;
                            }
                            return src;
                        }
                    }
                    if let Ok(cid) = resp.call_id() {
                        if let Some((src, _)) = self.inbound_call_sources.get(cid) {
                            let src = *src;
                            let seq = self.next_route_seq();
                            if let Some(entry) = self.inbound_call_sources.get_mut(cid) {
                                entry.1 = seq;
                            }
                            return src;
                        }
                    }
                    if let Some(addr) = resolve_via_response_addr(&via, default_port) {
                        return addr;
                    }
                }
                self.registrar_addr
            }
            SipMessage::Request(req) => {
                if req.method == Method::Register {
                    return self.registrar_addr;
                }
                let via_branch = req.top_via().ok().and_then(|v| v.branch);

                // RFC 3261 §9.1 & §17.1.1.3: CANCEL and hop-by-hop non-2xx ACK reuse the INVITE's Via branch
                // and MUST go to the exact same next-hop target as that INVITE.
                if matches!(req.method, Method::Cancel | Method::Ack) {
                    if let Some(branch) = via_branch.as_deref() {
                        if let Some((target, _)) = self.outbound_tx_targets.get(branch) {
                            let target = *target;
                            let seq = self.next_route_seq();
                            if let Some(entry) = self.outbound_tx_targets.get_mut(branch) {
                                entry.1 = seq;
                            }
                            return target;
                        }
                    }
                }

                // RFC 5923 / RFC 5626: for reliable stream transports (TCP/TLS), reuse the active
                // inbound peer connection for in-dialog requests (NAT-safe & pure-client friendly).
                let is_in_dialog = req.to().ok().and_then(|t| t.tag).is_some();
                if is_in_dialog && self.ua.transport().is_reliable() {
                    if let Ok(cid) = req.call_id() {
                        if let Some((src, _)) = self.inbound_call_sources.get(cid) {
                            let src = *src;
                            if self.sip_transport.has_connection(src) {
                                let seq = self.next_route_seq();
                                if let Some(entry) = self.inbound_call_sources.get_mut(cid) {
                                    entry.1 = seq;
                                }
                                if req.method == Method::Invite {
                                    self.record_outbound_tx_target(via_branch, src);
                                }
                                return src;
                            }
                        }
                    }
                }

                // RFC 3261 §12.2.1.1: if a Route header is present, forward to the topmost Route URI.
                if let Some(raw_route) = req.headers.get("Route") {
                    if let Ok(routes) = NameAddr::parse_list(raw_route) {
                        if let Some(first) = routes.first() {
                            if let Some(addr) =
                                self.resolve_sip_uri_cached(&first.uri, default_port, now)
                            {
                                if req.method == Method::Invite {
                                    self.record_outbound_tx_target(via_branch, addr);
                                }
                                return addr;
                            }
                        }
                    }
                }

                if req.uri.scheme == bmsip_core::sip::SipScheme::Tel || req.uri.host.is_empty() {
                    if req.method == Method::Invite {
                        self.record_outbound_tx_target(via_branch, self.registrar_addr);
                    }
                    return self.registrar_addr;
                }

                // In-dialog requests without a Route set (To tag present: 2xx ACK, BYE, re-INVITE)
                // route directly to the remote Contact (Request-URI) when it carries a concrete IP.
                if is_in_dialog {
                    if let Some(addr) = resolve_sip_uri_literal_ip(&req.uri, default_port) {
                        if req.method == Method::Invite {
                            self.record_outbound_tx_target(via_branch, addr);
                        }
                        return addr;
                    }
                }

                if req.method == Method::Invite {
                    self.record_outbound_tx_target(via_branch, self.registrar_addr);
                }
                self.registrar_addr
            }
        }
    }

    fn record_peer_tls_host(&mut self, addr: SocketAddr, raw_host: &str) {
        let host = raw_host.trim().trim_matches(['[', ']']);
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            return;
        }
        let seq = self.next_route_seq();
        if self.peer_tls_hosts.len() >= MAX_TRACKED_SIP_ROUTES
            && !self.peer_tls_hosts.contains_key(&addr)
        {
            if let Some(evict) = self
                .peer_tls_hosts
                .iter()
                .filter(|(a, _)| **a != self.registrar_addr)
                .min_by_key(|(_, (_, s))| *s)
                .map(|(a, _)| *a)
            {
                self.peer_tls_hosts.remove(&evict);
            }
        }
        self.peer_tls_hosts.insert(addr, (host.to_string(), seq));
    }

    fn resolve_sip_uri_cached(
        &mut self,
        uri: &SipUri,
        fallback_port: u16,
        now: Instant,
    ) -> Option<SocketAddr> {
        if uri.scheme == bmsip_core::sip::SipScheme::Tel || uri.host.is_empty() {
            return None;
        }
        if let Some(addr) = resolve_sip_uri_literal_ip(uri, fallback_port) {
            return Some(addr);
        }
        let port = uri
            .port
            .unwrap_or_else(|| default_port_for_uri(uri, fallback_port));
        let key = (uri.host.to_ascii_lowercase(), port);
        if let Some(entry) = self.dns_cache.get(&key).copied() {
            if now < entry.expires_at() {
                let seq = self.next_route_seq();
                if let Some(slot) = self.dns_cache.get_mut(&key) {
                    slot.set_seq(seq);
                }
                return match entry {
                    DnsCacheEntry::Positive { addr, .. } => {
                        self.record_peer_tls_host(addr, &uri.host);
                        Some(addr)
                    }
                    DnsCacheEntry::Negative { .. } => None,
                };
            }
            self.dns_cache.remove(&key);
        }

        let resolved = resolve_sip_uri_addr(uri, fallback_port);
        if self.dns_cache.len() >= MAX_TRACKED_SIP_ROUTES {
            self.dns_cache.retain(|_, v| now < v.expires_at());
            if self.dns_cache.len() >= MAX_TRACKED_SIP_ROUTES {
                if let Some(evict) = self
                    .dns_cache
                    .iter()
                    .min_by_key(|(_, v)| v.seq())
                    .map(|(k, _)| k.clone())
                {
                    self.dns_cache.remove(&evict);
                }
            }
        }
        let seq = self.next_route_seq();
        match resolved {
            Some(addr) => {
                self.dns_cache.insert(
                    key,
                    DnsCacheEntry::Positive {
                        addr,
                        expires_at: now + DNS_POSITIVE_TTL,
                        seq,
                    },
                );
                self.record_peer_tls_host(addr, &uri.host);
                Some(addr)
            }
            None => {
                self.dns_cache.insert(
                    key,
                    DnsCacheEntry::Negative {
                        expires_at: now + DNS_NEGATIVE_TTL,
                        seq,
                    },
                );
                None
            }
        }
    }

    fn sync_call_srtp(&mut self, call_id: &str, now: Instant) {
        let negotiated = self.ua.negotiated_srtp(call_id).cloned();
        if let Some(NegotiatedSrtp::Sdes {
            suite,
            local_key_salt,
            remote_key_salt,
        }) = negotiated
        {
            if let Some(media) = self.active_media.get_mut(call_id) {
                if media
                    .session
                    .update_srtp_keys(suite, &local_key_salt, &remote_key_salt)
                {
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(call_id),
                        format!("SRTP (SDES) keys active suite={suite}"),
                    );
                }
            }
        }
    }

    fn record_outbound_tx_target(&mut self, branch: Option<String>, target: SocketAddr) {
        if let Some(b) = branch {
            let seq = self.next_route_seq();
            if self.outbound_tx_targets.len() >= MAX_TRACKED_SIP_ROUTES
                && !self.outbound_tx_targets.contains_key(&b)
            {
                if let Some(evict) = self
                    .outbound_tx_targets
                    .iter()
                    .min_by_key(|(_, (_, s))| *s)
                    .map(|(k, _)| k.clone())
                {
                    self.outbound_tx_targets.remove(&evict);
                }
            }
            self.outbound_tx_targets.insert(b, (target, seq));
        }
    }

    fn record_inbound_source(&mut self, raw: &[u8], src_addr: SocketAddr) {
        if let Ok(SipMessage::Request(req)) = SipMessage::parse(raw) {
            if let Ok(via) = req.top_via() {
                if let Some(branch) = via.branch {
                    let key = (
                        branch,
                        via.sent_by.trim().to_ascii_lowercase(),
                        req.method.as_str().to_string(),
                    );
                    let seq = self.next_route_seq();
                    if self.inbound_tx_sources.len() >= MAX_TRACKED_SIP_ROUTES
                        && !self.inbound_tx_sources.contains_key(&key)
                    {
                        if let Some(evict) = self
                            .inbound_tx_sources
                            .iter()
                            .min_by_key(|(_, (_, s))| *s)
                            .map(|(k, _)| k.clone())
                        {
                            self.inbound_tx_sources.remove(&evict);
                        }
                    }
                    self.inbound_tx_sources.insert(key, (src_addr, seq));
                }
            }
            if req.method == Method::Invite {
                if let Ok(cid) = req.call_id() {
                    let cid_str = cid.to_string();
                    let seq = self.next_route_seq();
                    if self.inbound_call_sources.len() >= MAX_TRACKED_SIP_ROUTES
                        && !self.inbound_call_sources.contains_key(&cid_str)
                    {
                        let evict = self
                            .inbound_call_sources
                            .iter()
                            .filter(|(k, _)| {
                                !self.active_media.contains_key(k.as_str())
                                    && !self.pending_rtp_sockets.contains_key(k.as_str())
                            })
                            .min_by_key(|(_, (_, s))| *s)
                            .map(|(k, _)| k.clone())
                            .or_else(|| {
                                self.inbound_call_sources
                                    .iter()
                                    .min_by_key(|(_, (_, s))| *s)
                                    .map(|(k, _)| k.clone())
                            });
                        if let Some(k) = evict {
                            self.inbound_call_sources.remove(&k);
                        }
                    }
                    self.inbound_call_sources.insert(cid_str, (src_addr, seq));
                }
            }
        }
    }

    fn flush_sip_outbound(&mut self, now: Instant) {
        for pkt in self.ua.poll_transmit() {
            let dest = self.resolve_sip_destination(&pkt, now);
            if let Some(summary) = summarize_sip_datagram(&pkt) {
                self.recorder.record(
                    now,
                    TelemetryCategory::SipTx,
                    summary.0.as_deref(),
                    summary.1,
                );
            }
            let tls_host_hint = self.peer_tls_hosts.get(&dest).map(|(h, _)| h.clone());
            match self
                .sip_transport
                .send(dest, &pkt, tls_host_hint.as_deref(), now)
            {
                Ok(()) => {
                    self.note_udp_tx_to_registrar(dest, now);
                }
                Err(msg) => {
                    self.recorder
                        .record(now, TelemetryCategory::Warning, None, msg.clone());
                    self.push_event(EngineEvent::Warning(msg));
                }
            }
        }
    }

    fn is_udp_keepalive_eligible(&self) -> bool {
        !self.suspended
            && matches!(
                self.ua.registration_state(),
                RegistrationState::Registered { expires_secs, .. } if *expires_secs > 0
            )
    }

    fn refresh_udp_keepalive_deadline(&mut self, now: Instant) {
        let Some(interval) = self.udp_keepalive_interval else {
            self.next_udp_keepalive_at = None;
            return;
        };
        if self.is_udp_keepalive_eligible() {
            if self.next_udp_keepalive_at.is_none() {
                self.next_udp_keepalive_at = Some(now + interval);
            }
        } else {
            self.next_udp_keepalive_at = None;
        }
    }

    fn note_udp_tx_to_registrar(&mut self, dest: SocketAddr, now: Instant) {
        if dest == self.registrar_addr {
            if let Some(interval) = self.udp_keepalive_interval {
                if self.is_udp_keepalive_eligible() {
                    self.next_udp_keepalive_at = Some(now + interval);
                }
            }
        }
    }

    fn poll_udp_keepalive(&mut self, now: Instant) {
        self.refresh_udp_keepalive_deadline(now);
        if let (Some(interval), Some(dl)) =
            (self.udp_keepalive_interval, self.next_udp_keepalive_at)
        {
            if now >= dl {
                let _ = self.sip_transport.send(
                    self.registrar_addr,
                    bmsip_core::sip::RFC5626_KEEPALIVE_PING,
                    None,
                    now,
                );
                self.next_udp_keepalive_at = Some(now + interval);
            }
        }
    }

    fn handle_ua_events(&mut self, events: Vec<UaEvent>, now: Instant) {
        for ev in events {
            match ev {
                UaEvent::RegistrationChanged(state) => {
                    self.recorder.record(
                        now,
                        TelemetryCategory::RegistrationFsm,
                        None,
                        format!("registration state -> {state:?}"),
                    );
                    self.refresh_udp_keepalive_deadline(now);
                    self.push_event(EngineEvent::RegistrationChanged(state));
                }
                UaEvent::IncomingCall {
                    call_id, from, to, ..
                } => {
                    self.recorder.begin_call(&call_id, "inbound");
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        format!("incoming call from {} to {}", from.uri, to.uri),
                    );
                    self.push_event(EngineEvent::IncomingCall {
                        call_id,
                        from: from.to_string(),
                        to: to.to_string(),
                    });
                }
                UaEvent::CallRinging {
                    call_id,
                    status_code,
                    early_sdp,
                } => {
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        format!("ringing status={status_code}"),
                    );
                    self.push_event(EngineEvent::CallRinging {
                        call_id: call_id.clone(),
                        status_code,
                    });
                    if let Some(remote_sdp) = early_sdp {
                        if remote_sdp.audio_port > 0
                            && (self.active_media.contains_key(&call_id)
                                || self.pending_rtp_sockets.contains_key(&call_id))
                        {
                            let codecs = self
                                .ua
                                .negotiated_codecs(&call_id)
                                .map(|s| s.to_vec())
                                .unwrap_or_else(|| remote_sdp.codecs.clone());
                            if let Some((codec_name, remote_rtp)) =
                                self.activate_or_update_media(&call_id, &remote_sdp, &codecs, now)
                            {
                                self.recorder.record(
                                    now,
                                    TelemetryCategory::DialogFsm,
                                    Some(&call_id),
                                    format!(
                                        "early media started codec={codec_name} remote_rtp={remote_rtp}"
                                    ),
                                );
                                self.push_event(EngineEvent::EarlyMediaStarted {
                                    call_id,
                                    codec: codec_name,
                                    remote_rtp,
                                });
                            }
                        }
                    }
                }
                UaEvent::CallEstablished {
                    call_id,
                    remote_sdp,
                    negotiated_codecs,
                    ..
                } => {
                    self.on_call_established(&call_id, &remote_sdp, &negotiated_codecs, now);
                }
                UaEvent::CallMediaUpdated {
                    call_id,
                    remote_sdp,
                    negotiated_codecs,
                    ..
                } => {
                    if let Ok(ip) = remote_sdp.connection_ip.parse::<IpAddr>() {
                        let remote_rtp = SocketAddr::new(ip, remote_sdp.audio_port);
                        let (remote_rtcp, rtcp_mux) = resolve_remote_rtcp_addr(&remote_sdp, ip);
                        let mut updated_codec_label: Option<String> = None;
                        if !negotiated_codecs.is_empty() {
                            let (session_codec, codec_name, custom_plugin, dtmf_pt, dtmf_clock, _) =
                                self.select_media_codecs(&negotiated_codecs);
                            if let Some(media) = self.active_media.get_mut(&call_id) {
                                media.remote_rtp = remote_rtp;
                                media.remote_rtcp = remote_rtcp;
                                media.rtcp_mux = rtcp_mux;
                                media.latched_rtp_source = None;
                                media.latched_rtcp_source = None;
                                if media.session.codec() != session_codec
                                    || media.session.dtmf_payload_type() != dtmf_pt
                                    || media.session.dtmf_clock_rate_hz() != dtmf_clock
                                {
                                    media.session.reconfigure_codec(
                                        session_codec,
                                        dtmf_pt,
                                        dtmf_clock,
                                        custom_plugin,
                                    );
                                    updated_codec_label = Some(codec_name);
                                }
                            }
                        } else if let Some(media) = self.active_media.get_mut(&call_id) {
                            media.remote_rtp = remote_rtp;
                            media.remote_rtcp = remote_rtcp;
                            media.rtcp_mux = rtcp_mux;
                            media.latched_rtp_source = None;
                            media.latched_rtcp_source = None;
                        }
                        self.sync_call_srtp(&call_id, now);
                        let detail = match updated_codec_label {
                            Some(c) => format!("media updated codec={c} remote_rtp={remote_rtp}"),
                            None => format!("media updated remote_rtp={remote_rtp}"),
                        };
                        self.recorder.record(
                            now,
                            TelemetryCategory::DialogFsm,
                            Some(&call_id),
                            detail,
                        );
                        self.push_event(EngineEvent::CallMediaUpdated {
                            call_id,
                            remote_rtp,
                        });
                    }
                }
                UaEvent::CallTerminated {
                    call_id,
                    status_code,
                    reason,
                    ..
                } => {
                    self.on_call_terminated(&call_id, status_code, reason, now);
                }
                UaEvent::CallHoldChanged {
                    call_id,
                    local_hold,
                    remote_hold,
                } => {
                    if let Some(media) = self.active_media.get_mut(&call_id) {
                        media.local_hold = local_hold;
                        media.remote_hold = remote_hold;
                    }
                    if !local_hold
                        && self.focused_call_id.as_deref().is_none_or(|fid| {
                            fid == call_id
                                || self.active_media.get(fid).is_none_or(|m| m.local_hold)
                        })
                    {
                        self.focused_call_id = Some(call_id.clone());
                    }
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        format!("hold changed local={local_hold} remote={remote_hold}"),
                    );
                    self.push_event(EngineEvent::CallHoldChanged {
                        call_id,
                        local_hold,
                        remote_hold,
                    });
                }
                UaEvent::CallTransferRequested {
                    call_id, refer_to, ..
                } => {
                    let target_str = refer_to.to_string();
                    let _ = self.ua.notify_refer_status(&call_id, 200, "OK", true, now);
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        format!("transfer requested -> {target_str}"),
                    );
                    self.push_event(EngineEvent::CallTransferRequested {
                        call_id,
                        refer_to: target_str,
                    });
                }
                UaEvent::TransferNotify {
                    call_id,
                    status_code,
                    reason,
                    terminated,
                } => {
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        format!("transfer notify {status_code} {reason} terminated={terminated}"),
                    );
                    self.push_event(EngineEvent::TransferStatus {
                        call_id,
                        status_code,
                        reason,
                        terminated,
                    });
                }
                UaEvent::DtmfReceived {
                    call_id,
                    digit,
                    duration_ms,
                } => {
                    if let Ok(d) = bmsip_media::DtmfDigit::from_char(digit) {
                        self.recorder.record_dtmf(&call_id, d.to_char());
                        self.recorder.record(
                            now,
                            TelemetryCategory::SipRx,
                            Some(&call_id),
                            format!(
                                "received SIP INFO DTMF '{}' duration={duration_ms}ms",
                                d.to_char()
                            ),
                        );
                        self.push_event(EngineEvent::DtmfReceived { call_id, digit: d });
                    }
                }
                UaEvent::ProtocolWarning(msg) => {
                    self.recorder
                        .record(now, TelemetryCategory::Warning, None, msg.clone());
                    self.push_event(EngineEvent::Warning(msg));
                }
            }
        }
    }

    fn select_media_codecs(
        &self,
        negotiated_codecs: &[RtpCodec],
    ) -> (
        SessionCodec,
        String,
        Option<Box<dyn AudioCodecPlugin>>,
        u8,
        u32,
        u8,
    ) {
        let (session_codec, codec_name, custom_plugin) = negotiated_codecs
            .iter()
            .filter(|c| {
                !c.encoding_name.eq_ignore_ascii_case("telephone-event") && !c.is_comfort_noise()
            })
            .find_map(|c| {
                if c.encoding_name.eq_ignore_ascii_case("opus") && self.opus_available {
                    Some((
                        SessionCodec::Opus {
                            payload_type: c.payload_type,
                        },
                        "OPUS".to_string(),
                        None,
                    ))
                } else if c.encoding_name.eq_ignore_ascii_case("g722")
                    || c.payload_type == G722_PAYLOAD_TYPE
                {
                    Some((
                        SessionCodec::G722 {
                            payload_type: c.payload_type,
                        },
                        "G722".to_string(),
                        None,
                    ))
                } else if let Some(k) = G711Kind::from_payload_type(c.payload_type) {
                    let label = match k {
                        G711Kind::Pcmu => "PCMU",
                        G711Kind::Pcma => "PCMA",
                    };
                    Some((SessionCodec::G711(k), label.to_string(), None))
                } else {
                    self.codec_registry.instantiate(c).map(|plugin| {
                        let sc = SessionCodec::Custom {
                            payload_type: c.payload_type,
                            rtp_clock_rate_hz: plugin.descriptor().rtp_clock_rate_hz,
                        };
                        (sc, c.encoding_name.to_ascii_uppercase(), Some(plugin))
                    })
                }
            })
            .unwrap_or((SessionCodec::G711(G711Kind::Pcmu), "PCMU".to_string(), None));

        let target_clock = session_codec.clock_rate_hz();
        let (dtmf_pt, dtmf_clock_rate_hz) = negotiated_codecs
            .iter()
            .find(|c| {
                c.encoding_name.eq_ignore_ascii_case("telephone-event")
                    && c.clock_rate == target_clock
            })
            .or_else(|| {
                negotiated_codecs
                    .iter()
                    .find(|c| c.encoding_name.eq_ignore_ascii_case("telephone-event"))
            })
            .map(|c| (c.payload_type, c.clock_rate.max(8_000)))
            .unwrap_or((101, 8_000));

        let cn_pt = negotiated_codecs
            .iter()
            .find(|c| c.is_comfort_noise())
            .map_or(CN_PAYLOAD_TYPE, |c| c.payload_type);

        (
            session_codec,
            codec_name,
            custom_plugin,
            dtmf_pt,
            dtmf_clock_rate_hz,
            cn_pt,
        )
    }

    fn activate_or_update_media(
        &mut self,
        call_id: &str,
        remote_sdp: &bmsip_core::sdp::SdpSession,
        negotiated_codecs: &[RtpCodec],
        now: Instant,
    ) -> Option<(String, SocketAddr)> {
        if remote_sdp.audio_port == 0 {
            return None;
        }
        let remote_ip: IpAddr = match remote_sdp.connection_ip.parse() {
            Ok(ip) => ip,
            Err(err) => {
                let msg = format!(
                    "invalid remote SDP IP '{}': {err}",
                    remote_sdp.connection_ip
                );
                self.recorder
                    .record(now, TelemetryCategory::Warning, Some(call_id), msg.clone());
                self.push_event(EngineEvent::Warning(msg));
                return None;
            }
        };
        let remote_rtp = SocketAddr::new(remote_ip, remote_sdp.audio_port);
        let (remote_rtcp, rtcp_mux) = resolve_remote_rtcp_addr(remote_sdp, remote_ip);

        let (session_codec, codec_name, custom_plugin, dtmf_pt, dtmf_clock_rate_hz, cn_pt) =
            self.select_media_codecs(negotiated_codecs);
        let (local_hold, remote_hold) = self.ua.hold_state(call_id).unwrap_or((false, false));
        let negotiated_srtp = self.ua.negotiated_srtp(call_id).cloned();

        if let Some(media) = self.active_media.get_mut(call_id) {
            media.remote_rtp = remote_rtp;
            media.remote_rtcp = remote_rtcp;
            media.rtcp_mux = rtcp_mux;
            media.latched_rtp_source = None;
            media.latched_rtcp_source = None;
            media.local_hold = local_hold;
            media.remote_hold = remote_hold;
            if let Some(NegotiatedSrtp::Sdes {
                suite,
                local_key_salt,
                remote_key_salt,
            }) = &negotiated_srtp
            {
                if media
                    .session
                    .update_srtp_keys(*suite, local_key_salt, remote_key_salt)
                {
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(call_id),
                        format!("SRTP (SDES) keys updated suite={suite}"),
                    );
                }
            }
            if media.session.codec() != session_codec
                || media.session.dtmf_payload_type() != dtmf_pt
                || media.session.dtmf_clock_rate_hz() != dtmf_clock_rate_hz
            {
                media.session.reconfigure_codec(
                    session_codec,
                    dtmf_pt,
                    dtmf_clock_rate_hz,
                    custom_plugin,
                );
            }
            return Some((codec_name, remote_rtp));
        }

        let Some((rtp_socket, rtcp_socket)) = self.pending_rtp_sockets.remove(call_id) else {
            let msg = format!("missing bound RTP socket for call {call_id}");
            self.recorder
                .record(now, TelemetryCategory::Warning, Some(call_id), msg.clone());
            self.push_event(EngineEvent::Warning(msg));
            return None;
        };

        let port_rate = self.audio_port.sample_rate_hz();
        let frame_samples = match port_rate {
            48_000 => PCM_FRAME_SAMPLES_48KHZ_20MS,
            16_000 => PCM_FRAME_SAMPLES_16KHZ_20MS,
            _ => PCM_FRAME_SAMPLES_8KHZ_20MS,
        };
        self.ssrc_counter = self.ssrc_counter.wrapping_add(1);
        let jb_cfg = JitterBufferConfig {
            frame_samples,
            ..JitterBufferConfig::default()
        };
        let opus_backend: Option<Box<dyn OpusCodecBackend>> = match (
            self.opus_available,
            LibOpusCodec::new(),
        ) {
            (true, Ok(native)) => Some(Box::new(native)),
            (true, Err(err)) => {
                let msg = format!(
                        "native libopus init failed for call {call_id}; falling back away from Opus: {err}"
                    );
                self.recorder
                    .record(now, TelemetryCategory::Warning, Some(call_id), msg.clone());
                self.push_event(EngineEvent::Warning(msg));
                None
            }
            (false, _) => None,
        };
        let (session_codec, codec_name) =
            if opus_backend.is_none() && matches!(session_codec, SessionCodec::Opus { .. }) {
                (SessionCodec::G711(G711Kind::Pcmu), "PCMU".to_string())
            } else {
                (session_codec, codec_name)
            };
        let mut session =
            MediaSession::new_with_session_codec(session_codec, dtmf_pt, self.ssrc_counter, jb_cfg)
                .with_dtmf_clock_rate(dtmf_clock_rate_hz)
                .with_cn_payload_type(cn_pt);
        if let Some(opus) = opus_backend {
            session = session.with_opus_backend(opus);
        }
        if let Some(plugin) = custom_plugin {
            session = session.with_codec_plugin(plugin);
        }

        if let Some(NegotiatedSrtp::Sdes {
            suite,
            local_key_salt,
            remote_key_salt,
        }) = negotiated_srtp
        {
            session.set_srtp_keys(suite, &local_key_salt, &remote_key_salt);
            self.recorder.record(
                now,
                TelemetryCategory::DialogFsm,
                Some(call_id),
                format!("SRTP (SDES) enabled suite={suite}"),
            );
        }

        self.active_media.insert(
            call_id.to_string(),
            CallMediaRuntime {
                rtp_socket,
                rtcp_socket,
                remote_rtp,
                remote_rtcp,
                rtcp_mux,
                latched_rtp_source: None,
                latched_rtcp_source: None,
                session,
                started_at: now,
                rtp_packets_sent: 0,
                initial_rtcp_sent: false,
                next_rtcp_at: now + Duration::from_millis(RTCP_REPORT_INTERVAL_MS),
                local_hold,
                remote_hold,
            },
        );
        if !self.call_order.iter().any(|id| id == call_id) {
            self.call_order.push(call_id.to_string());
        }
        self.focused_call_id = Some(call_id.to_string());
        Some((codec_name, remote_rtp))
    }

    fn on_call_established(
        &mut self,
        call_id: &str,
        remote_sdp: &bmsip_core::sdp::SdpSession,
        negotiated_codecs: &[RtpCodec],
        now: Instant,
    ) {
        let Some((codec_name, remote_rtp)) =
            self.activate_or_update_media(call_id, remote_sdp, negotiated_codecs, now)
        else {
            return;
        };
        self.recorder.record(
            now,
            TelemetryCategory::DialogFsm,
            Some(call_id),
            format!("call established codec={codec_name} remote_rtp={remote_rtp}"),
        );
        self.push_event(EngineEvent::CallEstablished {
            call_id: call_id.to_string(),
            codec: codec_name,
            remote_rtp,
        });
    }

    fn on_call_terminated(
        &mut self,
        call_id: &str,
        status_code: Option<u16>,
        reason: String,
        now: Instant,
    ) {
        self.pending_rtp_sockets.remove(call_id);
        self.inbound_call_sources.remove(call_id);
        self.call_order.retain(|id| id != call_id);
        if self.focused_call_id.as_deref() == Some(call_id) {
            self.focused_call_id = None;
        }
        let (sent, rx, lost, jitter) = match self.active_media.remove(call_id) {
            Some(media) => {
                let stats = media.session.stats();
                (
                    media.rtp_packets_sent,
                    stats.received_count(),
                    stats.cumulative_lost(),
                    stats.jitter(),
                )
            }
            None => (0, 0, 0, 0),
        };
        self.recorder.record(
            now,
            TelemetryCategory::DialogFsm,
            Some(call_id),
            format!("call terminated code={status_code:?} reason={reason}"),
        );
        let snap = self.recorder.finish_call(
            call_id,
            &format!("terminated ({reason})"),
            sent,
            rx,
            lost,
            jitter,
        );
        let black_box_json = snap.to_json();
        self.push_event(EngineEvent::CallTerminated {
            call_id: call_id.to_string(),
            status_code,
            reason,
            black_box_json,
        });
    }

    fn handle_command(&mut self, cmd: EngineCommand, now: Instant) -> bool {
        match cmd {
            EngineCommand::Register => {
                if let Err(err) = self.ua.register(now) {
                    self.emit_cmd_error("register", err);
                }
            }
            EngineCommand::Unregister => {
                if let Err(err) = self.ua.unregister(now) {
                    self.emit_cmd_error("unregister", err);
                }
            }
            EngineCommand::Dial { target_uri } => {
                match bind_rtp_socket(self.bind_ip, self.local_sip_addr.ip()) {
                    Ok((rtp_sock, rtcp_sock, rtp_port)) => {
                        match self.ua.dial(target_uri.clone(), rtp_port, now) {
                            Ok(call_id) => {
                                self.pending_rtp_sockets
                                    .insert(call_id.clone(), (rtp_sock, rtcp_sock));
                                self.recorder.begin_call(&call_id, "outbound");
                                self.recorder.record(
                                    now,
                                    TelemetryCategory::DialogFsm,
                                    Some(&call_id),
                                    format!("dial target={target_uri} local_rtp_port={rtp_port}"),
                                );
                                self.push_event(EngineEvent::OutboundCallStarted { call_id });
                            }
                            Err(err) => self.emit_cmd_error("dial", err),
                        }
                    }
                    Err(err) => {
                        let msg = format!("RTP bind failed: {err}");
                        self.recorder
                            .record(now, TelemetryCategory::Warning, None, msg.clone());
                        self.push_event(EngineEvent::Warning(msg));
                    }
                }
            }
            EngineCommand::Ring { call_id } => {
                if let Err(err) = self.ua.ring(&call_id, now) {
                    self.emit_cmd_error("ring", err);
                }
            }
            EngineCommand::RingEarlyMedia { call_id } => {
                let mut freshly_bound = false;
                let rtp_port_res = if self.active_media.contains_key(&call_id)
                    || self.pending_rtp_sockets.contains_key(&call_id)
                {
                    Ok(self.ua.local_rtp_port(&call_id).unwrap_or(0))
                } else {
                    match bind_rtp_socket(self.bind_ip, self.local_sip_addr.ip()) {
                        Ok((rtp_sock, rtcp_sock, rtp_port)) => {
                            self.pending_rtp_sockets
                                .insert(call_id.clone(), (rtp_sock, rtcp_sock));
                            freshly_bound = true;
                            Ok(rtp_port)
                        }
                        Err(err) => Err(err),
                    }
                };
                match rtp_port_res {
                    Ok(rtp_port) => {
                        match self
                            .ua
                            .ring_early_media(&call_id, 183, rtp_port, false, now)
                        {
                            Ok(_) => {
                                if let (Some(rsdp), Some(codecs)) = (
                                    self.ua.remote_sdp(&call_id).cloned(),
                                    self.ua.negotiated_codecs(&call_id).map(|s| s.to_vec()),
                                ) {
                                    if let Some((codec_name, remote_rtp)) =
                                        self.activate_or_update_media(&call_id, &rsdp, &codecs, now)
                                    {
                                        self.recorder.record(
                                            now,
                                            TelemetryCategory::DialogFsm,
                                            Some(&call_id),
                                            format!(
                                                "early media (183) started codec={codec_name} remote_rtp={remote_rtp}"
                                            ),
                                        );
                                        self.push_event(EngineEvent::EarlyMediaStarted {
                                            call_id,
                                            codec: codec_name,
                                            remote_rtp,
                                        });
                                    }
                                }
                            }
                            Err(err) => {
                                if freshly_bound {
                                    self.pending_rtp_sockets.remove(&call_id);
                                }
                                self.emit_cmd_error("ring_early_media", err);
                            }
                        }
                    }
                    Err(err) => {
                        let msg = format!("RTP bind failed on ring_early_media: {err}");
                        self.recorder.record(
                            now,
                            TelemetryCategory::Warning,
                            Some(&call_id),
                            msg.clone(),
                        );
                        self.push_event(EngineEvent::Warning(msg));
                    }
                }
            }
            EngineCommand::Answer { call_id } => {
                if self.active_media.contains_key(&call_id)
                    || self.pending_rtp_sockets.contains_key(&call_id)
                {
                    let existing_port = self.ua.local_rtp_port(&call_id).unwrap_or(0);
                    if let Err(err) = self.ua.answer(&call_id, existing_port, now) {
                        self.emit_cmd_error("answer", err);
                    }
                } else {
                    match bind_rtp_socket(self.bind_ip, self.local_sip_addr.ip()) {
                        Ok((rtp_sock, rtcp_sock, rtp_port)) => {
                            self.pending_rtp_sockets
                                .insert(call_id.clone(), (rtp_sock, rtcp_sock));
                            if let Err(err) = self.ua.answer(&call_id, rtp_port, now) {
                                self.pending_rtp_sockets.remove(&call_id);
                                self.emit_cmd_error("answer", err);
                            }
                        }
                        Err(err) => {
                            let msg = format!("RTP bind failed on answer: {err}");
                            self.recorder.record(
                                now,
                                TelemetryCategory::Warning,
                                Some(&call_id),
                                msg.clone(),
                            );
                            self.push_event(EngineEvent::Warning(msg));
                        }
                    }
                }
            }
            EngineCommand::Hangup { call_id } => {
                if let Err(err) = self.ua.hangup(&call_id, now) {
                    self.emit_cmd_error("hangup", err);
                }
            }
            EngineCommand::Hold { call_id } => {
                if let Err(err) = self.ua.hold(&call_id, now) {
                    self.emit_cmd_error("hold", err);
                }
            }
            EngineCommand::ResumeCall { call_id } => {
                if let Err(err) = self.ua.resume_call(&call_id, now) {
                    self.emit_cmd_error("resume_call", err);
                }
            }
            EngineCommand::Transfer {
                call_id,
                target_uri,
            } => {
                if let Err(err) = self.ua.refer(&call_id, target_uri, now) {
                    self.emit_cmd_error("transfer", err);
                }
            }
            EngineCommand::AttendedTransfer {
                call_id,
                target_call_id,
            } => {
                if let Err(err) = self.ua.attended_transfer(&call_id, &target_call_id, now) {
                    self.emit_cmd_error("attended_transfer", err);
                }
            }
            EngineCommand::SetActiveCall { call_id } => {
                if self.call_order.iter().any(|id| id == &call_id)
                    || self.active_media.contains_key(&call_id)
                {
                    self.focused_call_id = Some(call_id.clone());
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        "active audio focus switched to call",
                    );
                } else {
                    self.push_event(EngineEvent::Warning(format!(
                        "cannot focus unknown call {call_id}"
                    )));
                }
            }
            EngineCommand::SendDtmf { call_id, digit } => {
                if let Some(media) = self.active_media.get_mut(&call_id) {
                    media.session.queue_dtmf(digit);
                    self.recorder.record(
                        now,
                        TelemetryCategory::RtpStats,
                        Some(&call_id),
                        format!("queued DTMF '{}'", digit.to_char()),
                    );
                } else {
                    self.push_event(EngineEvent::Warning(format!(
                        "cannot send DTMF on inactive call {call_id}"
                    )));
                }
            }
            EngineCommand::SendInfoDtmf {
                call_id,
                digit,
                duration_ms,
            } => {
                if let Err(err) =
                    self.ua
                        .send_info_dtmf(&call_id, digit.to_char(), duration_ms, now)
                {
                    self.emit_cmd_error("send_info_dtmf", err);
                } else {
                    self.recorder.record(
                        now,
                        TelemetryCategory::SipTx,
                        Some(&call_id),
                        format!(
                            "sent SIP INFO DTMF '{}' duration={duration_ms}ms",
                            digit.to_char()
                        ),
                    );
                }
            }
            EngineCommand::NetworkChanged {
                new_bind_ip,
                new_sip_port,
            } => match self
                .sip_transport
                .rebind(new_bind_ip, new_sip_port, self.registrar_addr)
            {
                Ok(new_local_addr) => {
                    let reachable_ip = new_local_addr.ip();
                    let actual_port = new_local_addr.port();
                    self.bind_ip = new_bind_ip;
                    self.local_sip_addr = new_local_addr;
                    if let Ok(mut g) = self.shared.local_sip_addr.lock() {
                        *g = self.local_sip_addr;
                    }
                    // Rebind active and pending RTP/RTCP sockets onto the new interface so media survives IP handover.
                    let mut rebound_rtp_ports = HashMap::new();
                    let active_ids: Vec<String> = self.active_media.keys().cloned().collect();
                    for cid in active_ids {
                        if let Ok((new_rtp, new_rtcp, new_port)) =
                            bind_rtp_socket(new_bind_ip, reachable_ip)
                        {
                            if let Some(media) = self.active_media.get_mut(&cid) {
                                media.rtp_socket = new_rtp;
                                media.rtcp_socket = new_rtcp;
                                media.latched_rtp_source = None;
                                media.latched_rtcp_source = None;
                                rebound_rtp_ports.insert(cid, new_port);
                            }
                        }
                    }
                    let pending_ids: Vec<String> =
                        self.pending_rtp_sockets.keys().cloned().collect();
                    for cid in pending_ids {
                        if let Ok((new_rtp, new_rtcp, new_port)) =
                            bind_rtp_socket(new_bind_ip, reachable_ip)
                        {
                            self.pending_rtp_sockets
                                .insert(cid.clone(), (new_rtp, new_rtcp));
                            rebound_rtp_ports.insert(cid, new_port);
                        }
                    }
                    if let Err(err) = self.ua.notify_network_changed_with_rtp_ports(
                        reachable_ip.to_string(),
                        actual_port,
                        &rebound_rtp_ports,
                        now,
                    ) {
                        self.emit_cmd_error("network_changed", err);
                    } else {
                        self.recorder.record(
                            now,
                            TelemetryCategory::Lifecycle,
                            None,
                            format!("network changed -> {}", self.local_sip_addr),
                        );
                        self.push_event(EngineEvent::NetworkUpdated {
                            local_sip_addr: self.local_sip_addr,
                        });
                    }
                }
                Err(err) => {
                    self.push_event(EngineEvent::Warning(format!(
                        "network rebind failed: {err}"
                    )));
                }
            },
            EngineCommand::Suspend => {
                self.suspended = true;
                self.next_udp_keepalive_at = None;
                self.was_registered_before_suspend = matches!(
                    self.ua.registration_state(),
                    RegistrationState::Registered { .. } | RegistrationState::Registering
                );
                self.recorder
                    .record(now, TelemetryCategory::Lifecycle, None, "engine suspended");
                self.push_event(EngineEvent::Suspended);
            }
            EngineCommand::Resume => {
                self.suspended = false;
                if self.was_registered_before_suspend {
                    if let Err(err) = self.ua.register(now) {
                        self.emit_cmd_error("resume register", err);
                    }
                }
                self.refresh_udp_keepalive_deadline(now);
                self.recorder
                    .record(now, TelemetryCategory::Lifecycle, None, "engine resumed");
                self.push_event(EngineEvent::Resumed {
                    local_sip_addr: self.local_sip_addr,
                });
            }
            EngineCommand::ExportTelemetry { call_id } => {
                let json = match &call_id {
                    Some(cid) => self.recorder.call_to_json(cid),
                    None => self.recorder.to_json(),
                };
                self.push_event(EngineEvent::TelemetryExported { call_id, json });
            }
            EngineCommand::Shutdown => {
                // Best-effort graceful BYE/CANCEL for active dialogs and de-REGISTER before closing sockets.
                for cid in self.ua.active_call_ids() {
                    let _ = self.ua.hangup(&cid, now);
                }
                if matches!(
                    self.ua.registration_state(),
                    RegistrationState::Registered { .. } | RegistrationState::Registering
                ) {
                    let _ = self.ua.unregister(now);
                }
                let immediate = self.ua.drain_events();
                self.handle_ua_events(immediate, now);
                self.flush_sip_outbound(now);
                return false;
            }
        }

        let immediate = self.ua.drain_events();
        self.handle_ua_events(immediate, now);
        self.flush_sip_outbound(now);
        true
    }

    fn emit_cmd_error(&mut self, action: &str, err: bmsip_core::SipError) {
        let msg = format!("{action} failed: {err}");
        self.recorder.record(
            Instant::now(),
            TelemetryCategory::Warning,
            None,
            msg.clone(),
        );
        self.push_event(EngineEvent::Warning(msg));
    }

    fn pump_sip_rx(&mut self, now: Instant) {
        let (messages, warnings) = self.sip_transport.poll_rx(now);
        for msg in warnings {
            self.recorder
                .record(now, TelemetryCategory::Warning, None, msg.clone());
            self.push_event(EngineEvent::Warning(msg));
        }
        for (src_addr, raw) in messages {
            self.record_inbound_source(&raw, src_addr);
            if let Some(summary) = summarize_sip_datagram(&raw) {
                self.recorder.record(
                    now,
                    TelemetryCategory::SipRx,
                    summary.0.as_deref(),
                    summary.1,
                );
            }
            let events = self.ua.receive_datagram(&raw, now);
            self.handle_ua_events(events, now);
        }
        self.flush_sip_outbound(now);
    }

    fn pump_rtp_rx(&mut self, now: Instant) {
        if self.suspended || self.active_media.is_empty() {
            return;
        }

        let call_ids: Vec<String> = self.active_media.keys().cloned().collect();
        let mut dtmf_events: Vec<(String, bmsip_media::DtmfDigit)> = Vec::new();
        let mut stats_updates: Vec<(String, u32, u32, i32, u32)> = Vec::new();

        for call_id in &call_ids {
            let Some(media) = self.active_media.get_mut(call_id) else {
                continue;
            };
            if !matches!(
                self.ua.call_state(call_id),
                Some(CallState::Ringing | CallState::Established | CallState::ReInviting)
            ) {
                continue;
            }

            let elapsed_ms = now.saturating_duration_since(media.started_at).as_millis() as u64;
            let mut rtp_buf = [0u8; 4096];
            for _ in 0..MAX_RTP_PACKETS_PER_TICK {
                match media.rtp_socket.recv_from(&mut rtp_buf) {
                    Ok((len, src_addr)) => {
                        if !media.session.is_srtp_active()
                            && !media.remote_rtp.ip().is_unspecified()
                        {
                            if src_addr.ip() != media.remote_rtp.ip() {
                                continue;
                            }
                            if let Some(latched) = media.latched_rtp_source {
                                if src_addr != latched {
                                    continue;
                                }
                            }
                        }
                        let pkt_slice = &rtp_buf[..len];
                        let is_muxed_rtcp = media.rtcp_mux
                            && pkt_slice.len() >= 4
                            && (pkt_slice[0] >> 6) == 2
                            && matches!(pkt_slice[1], 200..=204);
                        if is_muxed_rtcp {
                            if media.session.receive_rtcp_at(pkt_slice, elapsed_ms).is_ok()
                                && !media.session.is_srtp_active()
                                && !media.remote_rtp.ip().is_unspecified()
                                && media.latched_rtp_source.is_none()
                            {
                                media.latched_rtp_source = Some(src_addr);
                            }
                        } else {
                            let samples_per_ms = media.session.clock_rate_hz() / 1000;
                            let arrival_samples = (elapsed_ms.min(u64::from(u32::MAX)) as u32)
                                .saturating_mul(samples_per_ms);
                            if let Ok(opt_digit) =
                                media.session.receive_rtp(pkt_slice, arrival_samples)
                            {
                                if !media.session.is_srtp_active()
                                    && !media.remote_rtp.ip().is_unspecified()
                                    && media.latched_rtp_source.is_none()
                                {
                                    media.latched_rtp_source = Some(src_addr);
                                }
                                if let Some(digit) = opt_digit {
                                    dtmf_events.push((call_id.clone(), digit));
                                }
                            }
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break;
                    }
                    Err(_) => break,
                }
            }

            if let Some(rtcp_sock) = media.rtcp_socket.as_ref() {
                let mut rtcp_buf = [0u8; 1024];
                for _ in 0..MAX_RTP_PACKETS_PER_TICK {
                    match rtcp_sock.recv_from(&mut rtcp_buf) {
                        Ok((len, src_addr)) => {
                            if !media.session.is_srtp_active()
                                && !media.remote_rtcp.ip().is_unspecified()
                            {
                                if src_addr.ip() != media.remote_rtcp.ip() {
                                    continue;
                                }
                                if let Some(latched) = media.latched_rtcp_source {
                                    if src_addr != latched {
                                        continue;
                                    }
                                }
                            }
                            if media
                                .session
                                .receive_rtcp_at(&rtcp_buf[..len], elapsed_ms)
                                .is_ok()
                                && !media.session.is_srtp_active()
                                && !media.remote_rtcp.ip().is_unspecified()
                                && media.latched_rtcp_source.is_none()
                            {
                                media.latched_rtcp_source = Some(src_addr);
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }

            let st = media.session.stats();
            stats_updates.push((
                call_id.clone(),
                media.rtp_packets_sent,
                st.received_count(),
                st.cumulative_lost(),
                st.jitter(),
            ));
        }

        for (cid, digit) in dtmf_events {
            self.recorder.record_dtmf(&cid, digit.to_char());
            self.recorder.record(
                now,
                TelemetryCategory::RtpStats,
                Some(&cid),
                format!("received DTMF '{}'", digit.to_char()),
            );
            self.push_event(EngineEvent::DtmfReceived {
                call_id: cid,
                digit,
            });
        }

        for (cid, sent, rx, lost, jitter) in stats_updates {
            self.recorder.update_rtp_stats(&cid, sent, rx, lost, jitter);
        }
    }

    fn pump_media_tick(&mut self, now: Instant) {
        if self.suspended || self.active_media.is_empty() {
            return;
        }

        self.pump_rtp_rx(now);

        let active_call_ids: Vec<String> = self
            .call_order
            .iter()
            .filter(|cid| {
                self.active_media.contains_key(cid.as_str())
                    && matches!(
                        self.ua.call_state(cid),
                        Some(CallState::Ringing | CallState::Established | CallState::ReInviting)
                    )
            })
            .cloned()
            .collect();

        // Select audio focus: explicit non-held focused call -> newest non-held call -> newest call.
        let primary_call_id: Option<String> = self
            .focused_call_id
            .as_ref()
            .filter(|cid| {
                active_call_ids.iter().any(|id| id == *cid)
                    && self
                        .active_media
                        .get(cid.as_str())
                        .is_some_and(|m| !m.local_hold)
            })
            .cloned()
            .or_else(|| {
                active_call_ids
                    .iter()
                    .rev()
                    .find(|cid| {
                        self.active_media
                            .get(cid.as_str())
                            .is_some_and(|m| !m.local_hold)
                    })
                    .cloned()
            })
            .or_else(|| active_call_ids.last().cloned());

        let mut stats_updates: Vec<(String, u32, u32, i32, u32)> = Vec::new();
        let mut rtcp_sent_calls: Vec<String> = Vec::new();

        for call_id in &active_call_ids {
            let Some(media) = self.active_media.get_mut(call_id) else {
                continue;
            };

            if primary_call_id.as_deref() == Some(call_id.as_str()) {
                // Always capture from the audio port to keep host capture buffers fresh,
                // but skip outbound RTP media transmission while the call is on hold.
                let tx_pcm = self.audio_port.capture_frame_20ms();
                if !(media.local_hold || media.remote_hold) {
                    if let Ok(pkt) = media.session.encode_pcm_frame(&tx_pcm) {
                        if media.rtp_socket.send_to(&pkt, media.remote_rtp).is_ok() {
                            media.rtp_packets_sent = media.rtp_packets_sent.saturating_add(1);
                        }
                    }
                    if media.rtp_packets_sent >= 2 {
                        if let Some(dtmf_pkt) = media.session.pop_dtmf_packet() {
                            if media
                                .rtp_socket
                                .send_to(&dtmf_pkt, media.remote_rtp)
                                .is_ok()
                            {
                                media.rtp_packets_sent = media.rtp_packets_sent.saturating_add(1);
                            }
                        }
                    }
                }
                let playout = media.session.pop_playout_frame();
                self.audio_port.playout_20ms(playout.samples());
            } else {
                // Keep secondary active calls synchronized by draining their jitter buffers and DTMF queue.
                if let Some(dtmf_pkt) = media.session.pop_dtmf_packet() {
                    if media
                        .rtp_socket
                        .send_to(&dtmf_pkt, media.remote_rtp)
                        .is_ok()
                    {
                        media.rtp_packets_sent = media.rtp_packets_sent.saturating_add(1);
                    }
                }
                let _ = media.session.pop_playout_frame();
            }

            if media.rtcp_mux || media.rtcp_socket.is_some() {
                let rx_count = media.session.stats().received_count();
                if rx_count >= 20 && (!media.initial_rtcp_sent || now >= media.next_rtcp_at) {
                    let now_ms = now.saturating_duration_since(media.started_at).as_millis() as u64;
                    let rr = media.session.build_rtcp_receiver_report_at(Some(now_ms));
                    let send_ok = if media.rtcp_mux {
                        media.rtp_socket.send_to(&rr, media.remote_rtp).is_ok()
                    } else if let Some(rtcp_sock) = media.rtcp_socket.as_ref() {
                        rtcp_sock.send_to(&rr, media.remote_rtcp).is_ok()
                    } else {
                        false
                    };
                    if send_ok {
                        media.initial_rtcp_sent = true;
                        media.next_rtcp_at = now + Duration::from_millis(RTCP_REPORT_INTERVAL_MS);
                        rtcp_sent_calls.push(call_id.clone());
                    }
                }
            }

            let st = media.session.stats();
            stats_updates.push((
                call_id.clone(),
                media.rtp_packets_sent,
                st.received_count(),
                st.cumulative_lost(),
                st.jitter(),
            ));
        }

        for cid in rtcp_sent_calls {
            self.recorder.record(
                now,
                TelemetryCategory::RtpStats,
                Some(&cid),
                "sent RTCP ReceiverReport",
            );
        }

        for (cid, sent, rx, lost, jitter) in stats_updates {
            self.recorder.update_rtp_stats(&cid, sent, rx, lost, jitter);
        }
    }
}

fn run_worker(
    config: EngineConfig,
    sip_transport: SipTransportDriver,
    local_sip_addr: SocketAddr,
    audio_port: Box<dyn AudioPort>,
    opus_available: bool,
    shared: Arc<SharedState>,
) {
    let now = Instant::now();
    let reg_host_hint = config.ua_config.registrar_uri.host.clone();
    let udp_keepalive_interval =
        if config.ua_config.transport == SipTransport::Udp && config.udp_keepalive_secs > 0 {
            Some(Duration::from_secs(u64::from(config.udp_keepalive_secs)))
        } else {
            None
        };
    let mut ctx = WorkerCtx {
        registrar_addr: config.registrar_addr,
        bind_ip: config.bind_ip,
        local_sip_addr,
        sip_transport,
        ua: UserAgent::new(config.ua_config),
        codec_registry: config.codec_registry,
        opus_available,
        audio_port,
        recorder: FlightRecorder::new(now, config.telemetry_capacity),
        pending_rtp_sockets: HashMap::new(),
        active_media: HashMap::new(),
        call_order: Vec::new(),
        focused_call_id: None,
        inbound_tx_sources: HashMap::new(),
        inbound_call_sources: HashMap::new(),
        outbound_tx_targets: HashMap::new(),
        dns_cache: HashMap::new(),
        peer_tls_hosts: HashMap::new(),
        route_seq: 0,
        suspended: false,
        was_registered_before_suspend: false,
        udp_keepalive_interval,
        next_udp_keepalive_at: None,
        ssrc_counter: 0x2000_0000u32.wrapping_add(u32::from(local_sip_addr.port())),
        shared,
    };
    ctx.record_peer_tls_host(config.registrar_addr, &reg_host_hint);

    let mut next_media_tick = now + Duration::from_millis(MEDIA_TICK_MS);
    let mut running = true;

    while running {
        let mut drained_cmds = Vec::new();
        if let Ok(mut guard) = ctx.shared.commands.lock() {
            drained_cmds.extend(guard.drain(..));
        }

        let cmd_now = Instant::now();
        for cmd in drained_cmds {
            if !ctx.handle_command(cmd, cmd_now) {
                running = false;
                break;
            }
        }
        if !running {
            break;
        }

        if ctx.suspended {
            if let Ok(guard) = ctx.shared.commands.lock() {
                let wait_res = ctx.shared.cmd_cv.wait_while(guard, |cmds| cmds.is_empty());
                drop(wait_res);
            }
            continue;
        }

        let now = Instant::now();
        ctx.pump_sip_rx(now);
        ctx.pump_rtp_rx(now);

        if let Some(dl) = ctx.ua.poll_timeout() {
            if now >= dl {
                let timeout_events = ctx.ua.handle_timeout(now);
                ctx.handle_ua_events(timeout_events, now);
                ctx.flush_sip_outbound(now);
            }
        }
        ctx.poll_udp_keepalive(now);

        let now = Instant::now();
        if now >= next_media_tick {
            ctx.pump_media_tick(now);
            next_media_tick += Duration::from_millis(MEDIA_TICK_MS);
            if next_media_tick + Duration::from_millis(MEDIA_TICK_MS * 4) < now {
                next_media_tick = now + Duration::from_millis(MEDIA_TICK_MS);
            }
        }

        let has_active_work = !ctx.active_media.is_empty()
            || !ctx.pending_rtp_sockets.is_empty()
            || ctx.sip_transport.has_pending_io();
        let poll_ms = if has_active_work {
            WORKER_ACTIVE_POLL_MS
        } else {
            WORKER_IDLE_POLL_MS
        };
        let sleep_cap = Duration::from_millis(poll_ms);
        let until_media = if ctx.active_media.is_empty() {
            sleep_cap
        } else {
            next_media_tick.saturating_duration_since(Instant::now())
        };
        let until_sip = ctx
            .ua
            .poll_timeout()
            .map(|dl| dl.saturating_duration_since(Instant::now()))
            .unwrap_or(sleep_cap);
        let until_udp_ka = ctx
            .next_udp_keepalive_at
            .map(|dl| dl.saturating_duration_since(Instant::now()))
            .unwrap_or(sleep_cap);
        let wait_dur = sleep_cap.min(until_media).min(until_sip).min(until_udp_ka);
        if !wait_dur.is_zero() {
            if let Ok(guard) = ctx.shared.commands.lock() {
                let _ = ctx
                    .shared
                    .cmd_cv
                    .wait_timeout_while(guard, wait_dur, |cmds| cmds.is_empty());
            }
        }
    }

    let shared = Arc::clone(&ctx.shared);
    drop(ctx);
    if let Ok(mut guard) = shared.events.lock() {
        guard.0.push_back(EngineEvent::Stopped);
        guard.1 = true;
        shared.event_cv.notify_all();
    };
}

fn bind_rtp_socket(
    bind_ip: IpAddr,
    advertised_ip: IpAddr,
) -> Result<(UdpSocket, Option<UdpSocket>, u16), EngineError> {
    let target_ip = if bind_ip.is_unspecified() {
        bind_ip
    } else {
        advertised_ip
    };
    let mut fallback: Option<(UdpSocket, u16)> = None;
    for _ in 0..16 {
        let rtp_sock = UdpSocket::bind((target_ip, 0))?;
        rtp_sock.set_nonblocking(true)?;
        let port = rtp_sock.local_addr()?.port();
        if port % 2 == 0 {
            if let Some(rtcp_sock) = port
                .checked_add(1)
                .and_then(|rtcp_port| UdpSocket::bind((target_ip, rtcp_port)).ok())
                .and_then(|sock| sock.set_nonblocking(true).ok().map(|()| sock))
            {
                return Ok((rtp_sock, Some(rtcp_sock), port));
            }
        }
        fallback = Some((rtp_sock, port));
    }
    let (rtp_sock, port) = fallback
        .ok_or_else(|| EngineError::Io("failed to bind ephemeral RTP UDP socket".to_string()))?;
    let rtcp_sock = port
        .checked_add(1)
        .and_then(|rtcp_port| UdpSocket::bind((target_ip, rtcp_port)).ok())
        .and_then(|sock| sock.set_nonblocking(true).ok().map(|()| sock));
    Ok((rtp_sock, rtcp_sock, port))
}

fn resolve_remote_rtcp_addr(
    remote_sdp: &bmsip_core::sdp::SdpSession,
    remote_ip: IpAddr,
) -> (SocketAddr, bool) {
    if remote_sdp.rtcp_mux {
        return (SocketAddr::new(remote_ip, remote_sdp.audio_port), true);
    }
    if let Some(port) = remote_sdp.rtcp_port {
        let ip = remote_sdp
            .rtcp_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified())
            .unwrap_or(remote_ip);
        return (SocketAddr::new(ip, port), false);
    }
    (
        SocketAddr::new(remote_ip, remote_sdp.audio_port.saturating_add(1)),
        false,
    )
}

fn default_port_for_uri(uri: &SipUri, fallback_port: u16) -> u16 {
    SipTransport::from_uri(uri)
        .map(SipTransport::default_port)
        .unwrap_or(fallback_port)
}

fn resolve_sip_uri_literal_ip(uri: &SipUri, fallback_port: u16) -> Option<SocketAddr> {
    let host = uri.host.trim_matches(['[', ']']);
    let ip = host.parse::<IpAddr>().ok()?;
    if ip.is_unspecified() {
        return None;
    }
    let port = uri
        .port
        .unwrap_or_else(|| default_port_for_uri(uri, fallback_port));
    Some(SocketAddr::new(ip, port))
}

fn resolve_sip_uri_addr(uri: &SipUri, fallback_port: u16) -> Option<SocketAddr> {
    if let Some(addr) = resolve_sip_uri_literal_ip(uri, fallback_port) {
        return Some(addr);
    }
    let port = uri
        .port
        .unwrap_or_else(|| default_port_for_uri(uri, fallback_port));
    (uri.host.as_str(), port)
        .to_socket_addrs()
        .ok()?
        .find(|addr| !addr.ip().is_unspecified())
}

fn resolve_via_response_addr(via: &bmsip_core::sip::Via, fallback_port: u16) -> Option<SocketAddr> {
    let sent_host_port = via.sent_by.trim();
    let (sent_host, sent_port) = if let Some(rest) = sent_host_port.strip_prefix('[') {
        if let Some((ip_part, tail)) = rest.split_once(']') {
            let port = tail
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(fallback_port);
            (ip_part, port)
        } else {
            (sent_host_port, fallback_port)
        }
    } else if let Some((h, p)) = sent_host_port.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            (h, port)
        } else {
            (sent_host_port, fallback_port)
        }
    } else {
        (sent_host_port, fallback_port)
    };

    let ip_str = via.received.as_deref().unwrap_or(sent_host);
    let ip = ip_str.trim_matches(['[', ']']).parse::<IpAddr>().ok()?;
    if ip.is_unspecified() {
        return None;
    }
    let port = via.rport.flatten().unwrap_or(sent_port);
    Some(SocketAddr::new(ip, port))
}

fn summarize_sip_datagram(raw: &[u8]) -> Option<(Option<String>, String)> {
    let msg = SipMessage::parse(raw).ok()?;
    match msg {
        SipMessage::Request(req) => {
            let cid = req.call_id().ok().map(str::to_string);
            let cseq = req.cseq().ok().map(|c| c.seq).unwrap_or(0);
            Some((cid, format!("{} {} cseq={cseq}", req.method, req.uri.host)))
        }
        SipMessage::Response(resp) => {
            let cid = resp.call_id().ok().map(str::to_string);
            let cseq = resp
                .cseq()
                .ok()
                .map(|c| format!("{} {}", c.seq, c.method))
                .unwrap_or_default();
            Some((
                cid,
                format!("{} {} ({cseq})", resp.status_code, resp.reason_phrase),
            ))
        }
    }
}
