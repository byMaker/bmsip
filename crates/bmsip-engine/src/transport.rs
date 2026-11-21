//! MODULE_CONTRACT: Unified non-blocking SIP transport driver supporting UDP, TCP, and `rustls` TLS 1.2–1.3 (`SipTransportDriver`).
//! INVARIANTS: `#![forbid(unsafe_code)]`; non-blocking TCP/TLS I/O never stalls the 20 ms RTP media loop; reuses active client connections for NAT-safe inbound SIP requests; responds to RFC 5626 `\r\n\r\n` keep-alives with `\r\n`; drops all stale TCP/TLS sockets immediately on `rebind()`.
//! RFC_REFS: RFC 3261 Section 18; RFC 5626 Section 4.4.1; RFC 5922.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bmsip_core::sip::{
    SipStreamFramer, SipTransport, StreamFrame, StreamWriteQueue, RFC5626_KEEPALIVE_PING,
    RFC5626_KEEPALIVE_PONG,
};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

use crate::error::EngineError;
use crate::tls::{build_client_config, build_server_config, resolve_server_name, TlsConfig};

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const RFC5626_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const MAX_STREAM_PEERS: usize = 64;

enum TlsRole {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl TlsRole {
    fn read_tls(&mut self, rd: &mut dyn Read) -> io::Result<usize> {
        match self {
            Self::Client(c) => c.read_tls(rd),
            Self::Server(s) => s.read_tls(rd),
        }
    }

    fn write_tls(&mut self, wr: &mut dyn Write) -> io::Result<usize> {
        match self {
            Self::Client(c) => c.write_tls(wr),
            Self::Server(s) => s.write_tls(wr),
        }
    }

    fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        match self {
            Self::Client(c) => c.process_new_packets(),
            Self::Server(s) => s.process_new_packets(),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            Self::Client(c) => c.wants_write(),
            Self::Server(s) => s.wants_write(),
        }
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(c) => c.is_handshaking(),
            Self::Server(s) => s.is_handshaking(),
        }
    }

    fn read_plaintext(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Client(c) => c.reader().read(buf),
            Self::Server(s) => s.reader().read(buf),
        }
    }

    fn write_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Client(c) => c.writer().write(buf),
            Self::Server(s) => s.writer().write(buf),
        }
    }
}

struct StreamPeer {
    stream: TcpStream,
    tls: Option<TlsRole>,
    framer: SipStreamFramer,
    plain_tx: StreamWriteQueue,
    is_outbound: bool,
    next_keepalive_at: Instant,
}

struct PeerDriveOutput {
    messages: Vec<Vec<u8>>,
    closed: bool,
    warning: Option<String>,
}

impl StreamPeer {
    fn new(stream: TcpStream, tls: Option<TlsRole>, is_outbound: bool, now: Instant) -> Self {
        Self {
            stream,
            tls,
            framer: SipStreamFramer::new(),
            plain_tx: StreamWriteQueue::default(),
            is_outbound,
            next_keepalive_at: now + RFC5626_KEEPALIVE_INTERVAL,
        }
    }

    fn has_pending_io(&self) -> bool {
        !self.plain_tx.is_empty()
            || self
                .tls
                .as_ref()
                .is_some_and(|t| t.is_handshaking() || t.wants_write())
    }

    fn enqueue_plaintext(&mut self, bytes: Vec<u8>) {
        self.plain_tx.push(bytes);
    }

    fn drive_io(&mut self, now: Instant) -> PeerDriveOutput {
        let mut messages = Vec::new();
        let mut closed = false;
        let mut warning = None;

        for _ in 0..8 {
            let mut progressed = false;

            // 1. Read incoming bytes from TCP socket (decrypting via rustls when TLS is enabled).
            if let Some(role) = self.tls.as_mut() {
                loop {
                    match role.read_tls(&mut self.stream) {
                        Ok(0) => {
                            closed = true;
                            break;
                        }
                        Ok(_) => {
                            progressed = true;
                            if let Err(err) = role.process_new_packets() {
                                warning = Some(format!("TLS handshake/record error: {err}"));
                                closed = true;
                                break;
                            }
                        }
                        Err(e) if is_would_block(&e) => break,
                        Err(err) => {
                            warning = Some(format!("TLS TCP read error: {err}"));
                            closed = true;
                            break;
                        }
                    }
                }

                if !closed {
                    let mut plain_buf = [0u8; 8192];
                    loop {
                        match role.read_plaintext(&mut plain_buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                progressed = true;
                                if let Err(err) = self.framer.push(&plain_buf[..n]) {
                                    warning = Some(format!("SIP TLS framing error: {err}"));
                                    closed = true;
                                    break;
                                }
                            }
                            Err(e) if is_would_block(&e) => break,
                            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                                closed = true;
                                break;
                            }
                            Err(err) => {
                                warning = Some(format!("TLS plaintext read error: {err}"));
                                closed = true;
                                break;
                            }
                        }
                    }
                }
            } else {
                let mut buf = [0u8; 8192];
                loop {
                    match self.stream.read(&mut buf) {
                        Ok(0) => {
                            closed = true;
                            break;
                        }
                        Ok(n) => {
                            progressed = true;
                            if let Err(err) = self.framer.push(&buf[..n]) {
                                warning = Some(format!("SIP TCP framing error: {err}"));
                                closed = true;
                                break;
                            }
                        }
                        Err(e) if is_would_block(&e) => break,
                        Err(err) => {
                            warning = Some(format!("SIP TCP read error: {err}"));
                            closed = true;
                            break;
                        }
                    }
                }
            }

            // 2. Deframe complete SIP messages and respond to RFC 5626 keep-alive pings.
            if !closed {
                match self.framer.drain_frames() {
                    Ok(frames) => {
                        for frame in frames {
                            match frame {
                                StreamFrame::Message(msg) => {
                                    self.next_keepalive_at = now + RFC5626_KEEPALIVE_INTERVAL;
                                    messages.push(msg);
                                }
                                StreamFrame::KeepAlivePing => {
                                    self.plain_tx.push(RFC5626_KEEPALIVE_PONG.to_vec());
                                    progressed = true;
                                }
                                StreamFrame::KeepAlivePong => {
                                    self.next_keepalive_at = now + RFC5626_KEEPALIVE_INTERVAL;
                                }
                            }
                        }
                    }
                    Err(err) => {
                        warning = Some(format!("SIP stream frame error: {err}"));
                        closed = true;
                    }
                }
            }

            // 3. Emit periodic RFC 5626 CRLF keep-alive ping on idle outbound connections.
            let handshaking = self.tls.as_ref().is_some_and(TlsRole::is_handshaking);
            if !closed
                && self.is_outbound
                && !handshaking
                && now >= self.next_keepalive_at
                && self.plain_tx.is_empty()
            {
                self.plain_tx.push(RFC5626_KEEPALIVE_PING.to_vec());
                self.next_keepalive_at = now + RFC5626_KEEPALIVE_INTERVAL;
                progressed = true;
            }

            // 4. Flush outbound plaintext and TLS ciphertext to TCP socket without blocking.
            if !closed {
                if let Some(role) = self.tls.as_mut() {
                    if !role.is_handshaking() {
                        while let Some(slice) = self.plain_tx.front_slice() {
                            match role.write_plaintext(slice) {
                                Ok(0) => break,
                                Ok(n) => {
                                    self.plain_tx.consume(n);
                                    progressed = true;
                                }
                                Err(e) if is_would_block(&e) => break,
                                Err(err) => {
                                    warning = Some(format!("TLS write error: {err}"));
                                    closed = true;
                                    break;
                                }
                            }
                        }
                    }
                    if !closed {
                        while role.wants_write() {
                            match role.write_tls(&mut self.stream) {
                                Ok(0) => break,
                                Ok(_) => {
                                    progressed = true;
                                }
                                Err(e) if is_would_block(&e) => break,
                                Err(err) => {
                                    warning = Some(format!("TLS TCP write error: {err}"));
                                    closed = true;
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    while let Some(slice) = self.plain_tx.front_slice() {
                        match self.stream.write(slice) {
                            Ok(0) => break,
                            Ok(n) => {
                                self.plain_tx.consume(n);
                                progressed = true;
                            }
                            Err(e) if is_would_block(&e) => break,
                            Err(err) => {
                                warning = Some(format!("SIP TCP write error: {err}"));
                                closed = true;
                                break;
                            }
                        }
                    }
                }
            }

            if closed || !progressed {
                break;
            }
        }

        PeerDriveOutput {
            messages,
            closed,
            warning,
        }
    }
}

/// Multi-transport SIP network driver supporting UDP, TCP, and TLS (`rustls`).
pub(crate) struct SipTransportDriver {
    mode: SipTransport,
    udp_socket: Option<UdpSocket>,
    tcp_listener: Option<TcpListener>,
    connections: HashMap<SocketAddr, StreamPeer>,
    pending_rx: VecDeque<(SocketAddr, Vec<u8>)>,
    tls_client_cfg: Option<Arc<ClientConfig>>,
    tls_server_cfg: Option<Arc<ServerConfig>>,
    tls_server_name: Option<String>,
    default_domain: String,
    local_addr: SocketAddr,
}

impl SipTransportDriver {
    /// Binds a new SIP transport driver for `mode` (`Udp`, `Tcp`, or `Tls`).
    pub(crate) fn new(
        mode: SipTransport,
        bind_ip: IpAddr,
        sip_port: u16,
        remote_probe: SocketAddr,
        default_domain: String,
        tls_config: &TlsConfig,
    ) -> Result<Self, EngineError> {
        let (tls_client_cfg, tls_server_cfg) = if mode == SipTransport::Tls {
            (
                Some(build_client_config(tls_config)?),
                build_server_config(tls_config)?,
            )
        } else {
            (None, None)
        };

        let (udp_socket, tcp_listener, local_addr) =
            bind_transport_sockets(mode, bind_ip, sip_port, remote_probe)?;

        Ok(Self {
            mode,
            udp_socket,
            tcp_listener,
            connections: HashMap::new(),
            pending_rx: VecDeque::new(),
            tls_client_cfg,
            tls_server_cfg,
            tls_server_name: tls_config.server_name.clone(),
            default_domain,
            local_addr,
        })
    }

    /// Returns the advertised local SIP socket address (`reachable_ip:port`).
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns `true` when any TCP/TLS peer has queued writes, unread buffered frames, or an active TLS handshake in flight.
    pub(crate) fn has_pending_io(&self) -> bool {
        !self.pending_rx.is_empty() || self.connections.values().any(StreamPeer::has_pending_io)
    }

    /// Returns `true` if a live TCP/TLS peer connection is currently tracked for `addr`.
    pub(crate) fn has_connection(&self, addr: SocketAddr) -> bool {
        self.connections.contains_key(&addr)
    }

    /// Rebinds sockets onto `new_bind_ip:new_sip_port`, dropping any stale TCP/TLS connections immediately.
    pub(crate) fn rebind(
        &mut self,
        new_bind_ip: IpAddr,
        new_sip_port: u16,
        remote_probe: SocketAddr,
    ) -> Result<SocketAddr, EngineError> {
        let (udp_socket, tcp_listener, local_addr) =
            bind_transport_sockets(self.mode, new_bind_ip, new_sip_port, remote_probe)?;
        self.connections.clear();
        self.pending_rx.clear();
        self.udp_socket = udp_socket;
        self.tcp_listener = tcp_listener;
        self.local_addr = local_addr;
        Ok(local_addr)
    }

    /// Sends one SIP message over UDP, TCP, or TLS to `dest`.
    pub(crate) fn send(
        &mut self,
        dest: SocketAddr,
        bytes: &[u8],
        now: Instant,
    ) -> Result<(), String> {
        match self.mode {
            SipTransport::Udp => {
                let Some(sock) = self.udp_socket.as_ref() else {
                    return Err("UDP socket unavailable".to_string());
                };
                sock.send_to(bytes, dest)
                    .map(|_| ())
                    .map_err(|err| format!("SIP UDP send to {dest} failed: {err}"))
            }
            SipTransport::Tcp | SipTransport::Tls => {
                if !self.connections.contains_key(&dest) {
                    let peer = self.open_outbound_peer(dest, now)?;
                    if self.connections.len() >= MAX_STREAM_PEERS {
                        if let Some(evict_key) = self.connections.keys().next().copied() {
                            self.connections.remove(&evict_key);
                        }
                    }
                    self.connections.insert(dest, peer);
                }
                if let Some(peer) = self.connections.get_mut(&dest) {
                    peer.enqueue_plaintext(bytes.to_vec());
                    let out = peer.drive_io(now);
                    for msg in out.messages {
                        self.pending_rx.push_back((dest, msg));
                    }
                    if out.closed {
                        self.connections.remove(&dest);
                        if let Some(warn) = out.warning {
                            return Err(warn);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Polls all inbound UDP datagrams or TCP/TLS peer streams, driving TLS handshakes and queued writes.
    pub(crate) fn poll_rx(&mut self, now: Instant) -> (Vec<(SocketAddr, Vec<u8>)>, Vec<String>) {
        let mut received: Vec<(SocketAddr, Vec<u8>)> = self.pending_rx.drain(..).collect();
        let mut warnings = Vec::new();

        if self.mode == SipTransport::Udp {
            if let Some(sock) = self.udp_socket.as_ref() {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.recv_from(&mut buf) {
                        Ok((len, src_addr)) => {
                            received.push((src_addr, buf[..len].to_vec()));
                        }
                        Err(e) if is_would_block(&e) => break,
                        Err(err) => {
                            warnings.push(format!("SIP UDP recv error: {err}"));
                            break;
                        }
                    }
                }
            }
            return (received, warnings);
        }

        // Accept any new inbound TCP/TLS connections.
        if let Some(listener) = self.tcp_listener.as_ref() {
            loop {
                match listener.accept() {
                    Ok((stream, peer_addr)) => {
                        let _ = stream.set_nonblocking(true);
                        let _ = stream.set_nodelay(true);
                        let tls_role = if self.mode == SipTransport::Tls {
                            match self.tls_server_cfg.as_ref() {
                                Some(cfg) => match ServerConnection::new(Arc::clone(cfg)) {
                                    Ok(conn) => Some(TlsRole::Server(conn)),
                                    Err(err) => {
                                        warnings.push(format!(
                                            "failed to initialize inbound TLS session from {peer_addr}: {err}"
                                        ));
                                        continue;
                                    }
                                },
                                None => {
                                    warnings.push(format!(
                                        "rejected inbound TLS connection from {peer_addr}: no server certificate configured"
                                    ));
                                    continue;
                                }
                            }
                        } else {
                            None
                        };
                        if self.connections.len() >= MAX_STREAM_PEERS {
                            if let Some(evict_key) = self.connections.keys().next().copied() {
                                self.connections.remove(&evict_key);
                            }
                        }
                        self.connections
                            .insert(peer_addr, StreamPeer::new(stream, tls_role, false, now));
                    }
                    Err(e) if is_would_block(&e) => break,
                    Err(err) => {
                        warnings.push(format!("SIP TCP accept error: {err}"));
                        break;
                    }
                }
            }
        }

        // Drive I/O on all active TCP/TLS peers.
        let peer_addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
        let mut dead_peers = Vec::new();
        for addr in peer_addrs {
            if let Some(peer) = self.connections.get_mut(&addr) {
                let out = peer.drive_io(now);
                for msg in out.messages {
                    received.push((addr, msg));
                }
                if let Some(warn) = out.warning {
                    warnings.push(format!("peer {addr}: {warn}"));
                }
                if out.closed {
                    dead_peers.push(addr);
                }
            }
        }
        for addr in dead_peers {
            self.connections.remove(&addr);
        }

        (received, warnings)
    }

    fn open_outbound_peer(&self, dest: SocketAddr, now: Instant) -> Result<StreamPeer, String> {
        let stream = TcpStream::connect_timeout(&dest, TCP_CONNECT_TIMEOUT)
            .map_err(|err| format!("SIP TCP connect to {dest} failed: {err}"))?;
        stream
            .set_nonblocking(true)
            .map_err(|err| format!("failed to set TCP nonblocking: {err}"))?;
        let _ = stream.set_nodelay(true);

        let tls_role = if self.mode == SipTransport::Tls {
            let cfg = self
                .tls_client_cfg
                .as_ref()
                .ok_or_else(|| "missing rustls ClientConfig".to_string())?;
            let server_name =
                resolve_server_name(self.tls_server_name.as_deref(), &self.default_domain, dest)
                    .map_err(|e| e.to_string())?;
            let conn = ClientConnection::new(Arc::clone(cfg), server_name)
                .map_err(|err| format!("TLS ClientConnection init failed for {dest}: {err}"))?;
            Some(TlsRole::Client(conn))
        } else {
            None
        };

        Ok(StreamPeer::new(stream, tls_role, true, now))
    }
}

fn bind_transport_sockets(
    mode: SipTransport,
    bind_ip: IpAddr,
    sip_port: u16,
    remote_probe: SocketAddr,
) -> Result<(Option<UdpSocket>, Option<TcpListener>, SocketAddr), EngineError> {
    match mode {
        SipTransport::Udp => {
            let sock = UdpSocket::bind((bind_ip, sip_port))?;
            sock.set_nonblocking(true)?;
            let local = sock.local_addr()?;
            let reachable_ip = resolve_reachable_ip(local.ip(), remote_probe)?;
            Ok((
                Some(sock),
                None,
                SocketAddr::new(reachable_ip, local.port()),
            ))
        }
        SipTransport::Tcp | SipTransport::Tls => {
            let listener = TcpListener::bind((bind_ip, sip_port))?;
            listener.set_nonblocking(true)?;
            let local = listener.local_addr()?;
            let reachable_ip = resolve_reachable_ip(local.ip(), remote_probe)?;
            Ok((
                None,
                Some(listener),
                SocketAddr::new(reachable_ip, local.port()),
            ))
        }
    }
}

fn resolve_reachable_ip(bound_ip: IpAddr, remote_probe: SocketAddr) -> Result<IpAddr, EngineError> {
    if bound_ip.is_unspecified() {
        let probe = UdpSocket::bind("0.0.0.0:0")?;
        probe.connect(remote_probe)?;
        Ok(probe.local_addr()?.ip())
    } else {
        Ok(bound_ip)
    }
}

fn is_would_block(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}
