//! MODULE_CONTRACT: Multi-instance [`SipEngine`] runtime driving `bmsip_core::dialog::UserAgent` and `bmsip_media::MediaSession` over UDP sockets and monotonic timers.
//! INVARIANTS: `#![forbid(unsafe_code)]`; zero global state or `static mut`; zero callbacks invoked under held locks; thread-safe `Send + Sync` queues; deterministic cleanup on `Shutdown` or `Drop`.
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bmsip_core::dialog::{CallState, RegistrationState, UaEvent, UserAgent};
use bmsip_core::sip::SipMessage;
use bmsip_media::{G711Kind, JitterBufferConfig, MediaSession, RtpPacket, SessionCodec};

use crate::audio::AudioPort;
use crate::command::{EngineCommand, EngineConfig, EngineEvent};
use crate::error::EngineError;
use crate::telemetry::{FlightRecorder, TelemetryCategory};

const MEDIA_TICK_MS: u64 = 20;
const WORKER_IDLE_POLL_MS: u64 = 5;

struct CallMediaRuntime {
    rtp_socket: UdpSocket,
    remote_rtp: SocketAddr,
    session: MediaSession,
    started_at: Instant,
    rtp_packets_sent: u32,
}

struct SharedState {
    commands: Mutex<VecDeque<EngineCommand>>,
    events: Mutex<(VecDeque<EngineEvent>, bool)>,
    event_cv: Condvar,
    local_sip_addr: Mutex<SocketAddr>,
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
        let (sip_socket, reachable_ip) =
            bind_sip_socket(config.bind_ip, config.sip_port, config.registrar_addr)?;
        let actual_port = sip_socket.local_addr()?.port();
        let advertised_addr = SocketAddr::new(reachable_ip, actual_port);

        config.ua_config.local_host = reachable_ip.to_string();
        config.ua_config.local_sip_port = actual_port;

        let shared = Arc::new(SharedState {
            commands: Mutex::new(VecDeque::new()),
            events: Mutex::new((VecDeque::new(), false)),
            event_cv: Condvar::new(),
            local_sip_addr: Mutex::new(advertised_addr),
        });

        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("bmsip-engine".to_string())
            .spawn(move || {
                run_worker(
                    config,
                    sip_socket,
                    advertised_addr,
                    audio_port,
                    worker_shared,
                );
            })
            .map_err(|e| EngineError::Io(e.to_string()))?;

        Ok(Self {
            shared,
            worker: Some(worker),
        })
    }

    /// Enqueues a non-blocking command to the engine worker.
    pub fn send_command(&self, cmd: EngineCommand) -> Result<(), EngineError> {
        let mut guard = self
            .shared
            .commands
            .lock()
            .map_err(|_| EngineError::ChannelClosed)?;
        guard.push_back(cmd);
        Ok(())
    }

    /// Pops the next available [`EngineEvent`] without blocking.
    pub fn try_recv_event(&self) -> Option<EngineEvent> {
        let mut guard = self.shared.events.lock().ok()?;
        guard.0.pop_front()
    }

    /// Waits up to `timeout` for the next [`EngineEvent`].
    pub fn recv_event_timeout(&self, timeout: Duration) -> Option<EngineEvent> {
        let guard = self.shared.events.lock().ok()?;
        let (mut guard, _) = self
            .shared
            .event_cv
            .wait_timeout_while(guard, timeout, |state| state.0.is_empty() && !state.1)
            .ok()?;
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
    sip_socket: UdpSocket,
    ua: UserAgent,
    audio_port: Box<dyn AudioPort>,
    recorder: FlightRecorder,
    pending_rtp_sockets: HashMap<String, UdpSocket>,
    active_media: HashMap<String, CallMediaRuntime>,
    suspended: bool,
    was_registered_before_suspend: bool,
    ssrc_counter: u32,
    shared: Arc<SharedState>,
}

impl WorkerCtx {
    fn push_event(&self, ev: EngineEvent) {
        if let Ok(mut guard) = self.shared.events.lock() {
            guard.0.push_back(ev);
            self.shared.event_cv.notify_all();
        }
    }

    fn flush_sip_outbound(&mut self, now: Instant) {
        for pkt in self.ua.poll_transmit() {
            if let Some(summary) = summarize_sip_datagram(&pkt) {
                self.recorder.record(
                    now,
                    TelemetryCategory::SipTx,
                    summary.0.as_deref(),
                    summary.1,
                );
            }
            if let Err(err) = self.sip_socket.send_to(&pkt, self.registrar_addr) {
                let msg = format!("SIP UDP send failed: {err}");
                self.recorder
                    .record(now, TelemetryCategory::Warning, None, msg.clone());
                self.push_event(EngineEvent::Warning(msg));
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
                    ..
                } => {
                    self.recorder.record(
                        now,
                        TelemetryCategory::DialogFsm,
                        Some(&call_id),
                        format!("ringing status={status_code}"),
                    );
                    self.push_event(EngineEvent::CallRinging {
                        call_id,
                        status_code,
                    });
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
                    ..
                } => {
                    if let Ok(ip) = remote_sdp.connection_ip.parse::<IpAddr>() {
                        let remote_rtp = SocketAddr::new(ip, remote_sdp.audio_port);
                        if let Some(media) = self.active_media.get_mut(&call_id) {
                            media.remote_rtp = remote_rtp;
                        }
                        self.recorder.record(
                            now,
                            TelemetryCategory::DialogFsm,
                            Some(&call_id),
                            format!("media updated remote_rtp={remote_rtp}"),
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
                } => {
                    self.on_call_terminated(&call_id, status_code, reason, now);
                }
                UaEvent::ProtocolWarning(msg) => {
                    self.recorder
                        .record(now, TelemetryCategory::Warning, None, msg.clone());
                    self.push_event(EngineEvent::Warning(msg));
                }
            }
        }
    }

    fn on_call_established(
        &mut self,
        call_id: &str,
        remote_sdp: &bmsip_core::sdp::SdpSession,
        negotiated_codecs: &[bmsip_core::sdp::RtpCodec],
        now: Instant,
    ) {
        let Some(rtp_socket) = self.pending_rtp_sockets.remove(call_id) else {
            let msg = format!("missing bound RTP socket for established call {call_id}");
            self.recorder
                .record(now, TelemetryCategory::Warning, Some(call_id), msg.clone());
            self.push_event(EngineEvent::Warning(msg));
            return;
        };

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
                return;
            }
        };
        let remote_rtp = SocketAddr::new(remote_ip, remote_sdp.audio_port);

        let (session_codec, codec_name) = negotiated_codecs
            .iter()
            .find_map(|c| {
                if c.encoding_name.eq_ignore_ascii_case("opus") {
                    Some((
                        SessionCodec::Opus {
                            payload_type: c.payload_type,
                        },
                        "OPUS".to_string(),
                    ))
                } else {
                    G711Kind::from_payload_type(c.payload_type).map(|k| {
                        let label = match k {
                            G711Kind::Pcmu => "PCMU",
                            G711Kind::Pcma => "PCMA",
                        };
                        (SessionCodec::G711(k), label.to_string())
                    })
                }
            })
            .unwrap_or((SessionCodec::G711(G711Kind::Pcmu), "PCMU".to_string()));
        let dtmf_pt = negotiated_codecs
            .iter()
            .find(|c| c.encoding_name.eq_ignore_ascii_case("telephone-event"))
            .map(|c| c.payload_type)
            .unwrap_or(101);

        self.ssrc_counter = self.ssrc_counter.wrapping_add(1);
        let session = MediaSession::new_with_session_codec(
            session_codec,
            dtmf_pt,
            self.ssrc_counter,
            JitterBufferConfig::default(),
        );
        self.active_media.insert(
            call_id.to_string(),
            CallMediaRuntime {
                rtp_socket,
                remote_rtp,
                session,
                started_at: now,
                rtp_packets_sent: 0,
            },
        );
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
                    Ok((rtp_sock, rtp_port)) => {
                        match self.ua.dial(target_uri.clone(), rtp_port, now) {
                            Ok(call_id) => {
                                self.pending_rtp_sockets.insert(call_id.clone(), rtp_sock);
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
            EngineCommand::Answer { call_id } => {
                match bind_rtp_socket(self.bind_ip, self.local_sip_addr.ip()) {
                    Ok((rtp_sock, rtp_port)) => {
                        self.pending_rtp_sockets.insert(call_id.clone(), rtp_sock);
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
            EngineCommand::Hangup { call_id } => {
                if let Err(err) = self.ua.hangup(&call_id, now) {
                    self.emit_cmd_error("hangup", err);
                }
            }
            EngineCommand::SendDtmf { call_id, digit } => {
                if let Some(media) = self.active_media.get_mut(&call_id) {
                    media.session.queue_dtmf(digit);
                    for dtmf_pkt in media.session.poll_dtmf_packets() {
                        let _ = media.rtp_socket.send_to(&dtmf_pkt, media.remote_rtp);
                        media.rtp_packets_sent = media.rtp_packets_sent.saturating_add(1);
                    }
                    self.recorder.record(
                        now,
                        TelemetryCategory::RtpStats,
                        Some(&call_id),
                        format!("sent DTMF '{}'", digit.to_char()),
                    );
                } else {
                    self.push_event(EngineEvent::Warning(format!(
                        "cannot send DTMF on inactive call {call_id}"
                    )));
                }
            }
            EngineCommand::NetworkChanged {
                new_bind_ip,
                new_sip_port,
            } => match bind_sip_socket(new_bind_ip, new_sip_port, self.registrar_addr) {
                Ok((new_sock, reachable_ip)) => {
                    let actual_port = match new_sock.local_addr() {
                        Ok(addr) => addr.port(),
                        Err(err) => {
                            self.push_event(EngineEvent::Warning(err.to_string()));
                            return true;
                        }
                    };
                    self.bind_ip = new_bind_ip;
                    self.sip_socket = new_sock;
                    self.local_sip_addr = SocketAddr::new(reachable_ip, actual_port);
                    if let Ok(mut g) = self.shared.local_sip_addr.lock() {
                        *g = self.local_sip_addr;
                    }
                    if let Err(err) =
                        self.ua
                            .notify_network_changed(reachable_ip.to_string(), actual_port, now)
                    {
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
        let mut buf = [0u8; 8192];
        loop {
            match self.sip_socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    if let Some(summary) = summarize_sip_datagram(&buf[..len]) {
                        self.recorder.record(
                            now,
                            TelemetryCategory::SipRx,
                            summary.0.as_deref(),
                            summary.1,
                        );
                    }
                    let events = self.ua.receive_datagram(&buf[..len], now);
                    self.handle_ua_events(events, now);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => {
                    let msg = format!("SIP UDP recv error: {err}");
                    self.recorder
                        .record(now, TelemetryCategory::Warning, None, msg.clone());
                    self.push_event(EngineEvent::Warning(msg));
                    break;
                }
            }
        }
        self.flush_sip_outbound(now);
    }

    fn pump_media_tick(&mut self, now: Instant) {
        if self.suspended || self.active_media.is_empty() {
            return;
        }

        let call_ids: Vec<String> = self.active_media.keys().cloned().collect();
        let mut dtmf_events: Vec<(String, bmsip_media::DtmfDigit)> = Vec::new();
        let mut stats_updates: Vec<(String, u32, u32, i32, u32)> = Vec::new();

        for (idx, call_id) in call_ids.iter().enumerate() {
            let Some(media) = self.active_media.get_mut(call_id) else {
                continue;
            };
            if self.ua.call_state(call_id) != Some(CallState::Established) {
                continue;
            }

            let mut rtp_buf = [0u8; 2048];
            loop {
                match media.rtp_socket.recv_from(&mut rtp_buf) {
                    Ok((len, _)) => {
                        let samples_per_ms = media.session.clock_rate_hz() / 1000;
                        let arrival_samples = (media.started_at.elapsed().as_millis() as u32)
                            .saturating_mul(samples_per_ms);
                        if RtpPacket::parse(&rtp_buf[..len]).is_ok() {
                            if let Ok(Some(digit)) =
                                media.session.receive_rtp(&rtp_buf[..len], arrival_samples)
                            {
                                dtmf_events.push((call_id.clone(), digit));
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

            // Capture and play out audio frames on the primary active call.
            if idx == 0 {
                let tx_pcm = self.audio_port.capture_20ms();
                if let Ok(pkt) = media.session.encode_pcm_frame(&tx_pcm) {
                    if media.rtp_socket.send_to(&pkt, media.remote_rtp).is_ok() {
                        media.rtp_packets_sent = media.rtp_packets_sent.saturating_add(1);
                    }
                }
                let playout = media.session.pop_playout_frame();
                self.audio_port.playout_20ms(playout.samples());
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
}

fn run_worker(
    config: EngineConfig,
    sip_socket: UdpSocket,
    local_sip_addr: SocketAddr,
    audio_port: Box<dyn AudioPort>,
    shared: Arc<SharedState>,
) {
    let now = Instant::now();
    let mut ctx = WorkerCtx {
        registrar_addr: config.registrar_addr,
        bind_ip: config.bind_ip,
        local_sip_addr,
        sip_socket,
        ua: UserAgent::new(config.ua_config),
        audio_port,
        recorder: FlightRecorder::new(now, config.telemetry_capacity),
        pending_rtp_sockets: HashMap::new(),
        active_media: HashMap::new(),
        suspended: false,
        was_registered_before_suspend: false,
        ssrc_counter: 0x2000_0000u32.wrapping_add(u32::from(local_sip_addr.port())),
        shared,
    };

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

        let now = Instant::now();
        ctx.pump_sip_rx(now);

        if let Some(dl) = ctx.ua.poll_timeout() {
            if now >= dl {
                let timeout_events = ctx.ua.handle_timeout(now);
                ctx.handle_ua_events(timeout_events, now);
                ctx.flush_sip_outbound(now);
            }
        }

        let now = Instant::now();
        if now >= next_media_tick {
            ctx.pump_media_tick(now);
            next_media_tick += Duration::from_millis(MEDIA_TICK_MS);
            if next_media_tick + Duration::from_millis(MEDIA_TICK_MS * 4) < now {
                next_media_tick = now + Duration::from_millis(MEDIA_TICK_MS);
            }
        }

        let sleep_cap = Duration::from_millis(WORKER_IDLE_POLL_MS);
        let until_media = next_media_tick.saturating_duration_since(Instant::now());
        let until_sip = ctx
            .ua
            .poll_timeout()
            .map(|dl| dl.saturating_duration_since(Instant::now()))
            .unwrap_or(sleep_cap);
        let wait_dur = sleep_cap.min(until_media).min(until_sip);
        if !wait_dur.is_zero() {
            thread::sleep(wait_dur);
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

fn bind_sip_socket(
    bind_ip: IpAddr,
    sip_port: u16,
    remote_probe: SocketAddr,
) -> Result<(UdpSocket, IpAddr), EngineError> {
    let sock = UdpSocket::bind((bind_ip, sip_port))?;
    sock.set_nonblocking(true)?;
    let bound_ip = sock.local_addr()?.ip();
    let reachable_ip = if bound_ip.is_unspecified() {
        let probe = UdpSocket::bind("0.0.0.0:0")?;
        probe.connect(remote_probe)?;
        probe.local_addr()?.ip()
    } else {
        bound_ip
    };
    Ok((sock, reachable_ip))
}

fn bind_rtp_socket(
    bind_ip: IpAddr,
    advertised_ip: IpAddr,
) -> Result<(UdpSocket, u16), EngineError> {
    let target_ip = if bind_ip.is_unspecified() {
        bind_ip
    } else {
        advertised_ip
    };
    let sock = UdpSocket::bind((target_ip, 0))?;
    sock.set_nonblocking(true)?;
    let port = sock.local_addr()?.port();
    Ok((sock, port))
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
