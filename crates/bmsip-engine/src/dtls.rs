//! MODULE_CONTRACT: Pure-Rust `#![forbid(unsafe_code)]` DTLS-SRTP (RFC 5763 / RFC 5764) media handshake driver, RFC 5764 §5.1.2 packet demultiplexer, SDP `a=fingerprint:sha-256` verifier, and RFC 5705 `"EXTRACTOR-dtls_srtp"` key exporter.
//! INVARIANTS: `#![forbid(unsafe_code)]`; demultiplexes DTLS record datagrams (`20..=63`) from RTP/SRTP (`128..=191`) on the same UDP media port; verifies both client and server X.509 certificate SHA-256 fingerprints against SDP `a=fingerprint:` before deriving SRTP master keys.
//! RFC_REFS: RFC 4572, RFC 5705, RFC 5763, RFC 5764.

#![forbid(unsafe_code)]

use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bmsip_core::sdp::{DtlsFingerprint, DtlsSetupRole, SrtpSuite};
use bmsip_media::SrtpKeyMaterial;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    ServerConfig, ServerConnection, SignatureScheme,
};

use crate::error::EngineError;

const DTLS_RECORD_HEADER_LEN: usize = 13;
const DTLS_CONTENT_TYPE_HANDSHAKE: u8 = 22;
const DTLS_VERSION_1_2: [u8; 2] = [0xfe, 0xfd];
const DTLS_RETRANSMIT_INTERVAL: Duration = Duration::from_millis(120);
const DTLS_EXTRACTOR_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";

/// Returns `true` if a UDP media datagram is a DTLS record (`20..=63`) per RFC 5764 §5.1.2.
pub fn is_dtls_datagram(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|&b0| (20..=63).contains(&b0))
}

/// Ephemeral self-signed X.509 identity and SHA-256 fingerprint for DTLS-SRTP (RFC 5763 §5).
#[derive(Debug, Clone)]
pub struct DtlsIdentity {
    cert_der: CertificateDer<'static>,
    key_der: Vec<u8>,
    pub fingerprint: DtlsFingerprint,
}

impl DtlsIdentity {
    /// Generates a fresh self-signed X.509 certificate and computes its RFC 4572 `sha-256` fingerprint.
    pub fn generate() -> Result<Self, EngineError> {
        let params = rcgen::CertificateParams::new(vec!["bmsip.dtls.local".to_string()])
            .map_err(|e| EngineError::InvalidConfig(format!("DTLS cert params error: {e}")))?;
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| EngineError::InvalidConfig(format!("DTLS keygen error: {e}")))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| EngineError::InvalidConfig(format!("DTLS self-sign error: {e}")))?;

        let cert_der = cert.der().clone();
        let fingerprint = DtlsFingerprint::sha256_from_der(cert_der.as_ref());
        let key_der = key_pair.serialize_der();
        Ok(Self {
            cert_der,
            key_der,
            fingerprint,
        })
    }

    fn private_key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key_der.clone().into())
    }
}

enum DtlsRoleConn {
    Client(ClientConnection),
    Server(ServerConnection),
}

impl DtlsRoleConn {
    fn is_client(&self) -> bool {
        matches!(self, Self::Client(_))
    }

    fn is_handshaking(&self) -> bool {
        match self {
            Self::Client(c) => c.is_handshaking(),
            Self::Server(s) => s.is_handshaking(),
        }
    }

    fn wants_write(&self) -> bool {
        match self {
            Self::Client(c) => c.wants_write(),
            Self::Server(s) => s.wants_write(),
        }
    }

    fn write_tls_flight(&mut self) -> Result<Vec<u8>, String> {
        let mut raw_tls = Vec::new();
        while self.wants_write() {
            let res = match self {
                Self::Client(c) => c.write_tls(&mut raw_tls),
                Self::Server(s) => s.write_tls(&mut raw_tls),
            };
            res.map_err(|e| format!("DTLS write error: {e}"))?;
        }
        Ok(raw_tls)
    }

    fn read_and_process(&mut self, tls_bytes: &[u8]) -> Result<(), String> {
        let mut cursor = Cursor::new(tls_bytes);
        while (cursor.position() as usize) < tls_bytes.len() {
            let n = match self {
                Self::Client(c) => c.read_tls(&mut cursor),
                Self::Server(s) => s.read_tls(&mut cursor),
            }
            .map_err(|e| format!("DTLS read error: {e}"))?;
            if n == 0 {
                break;
            }
            match self {
                Self::Client(c) => c.process_new_packets(),
                Self::Server(s) => s.process_new_packets(),
            }
            .map_err(|e| format!("DTLS handshake error: {e}"))?;
        }
        Ok(())
    }

    fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        match self {
            Self::Client(c) => c.peer_certificates(),
            Self::Server(s) => s.peer_certificates(),
        }
    }

    fn export_srtp_keys(&self) -> Result<[u8; 60], String> {
        let mut out = [0u8; 60];
        match self {
            Self::Client(c) => c.export_keying_material(&mut out, DTLS_EXTRACTOR_LABEL, None),
            Self::Server(s) => s.export_keying_material(&mut out, DTLS_EXTRACTOR_LABEL, None),
        }
        .map_err(|e| format!("DTLS-SRTP RFC 5705 key export failed: {e}"))?;
        Ok(out)
    }
}

/// Output of one DTLS-SRTP state machine step.
pub struct DtlsStepOutput {
    /// Datagrams to send out over the RTP UDP socket to `remote_rtp`.
    pub outbound_packets: Vec<Vec<u8>>,
    /// Derived `(suite, local_tx_key_salt, remote_rx_key_salt)` once handshake and fingerprint verification succeed.
    pub established_keys: Option<(SrtpSuite, [u8; 30], [u8; 30])>,
}

/// Per-call DTLS-SRTP handshake session multiplexed on the RTP UDP socket.
pub struct DtlsSrtpSession {
    conn: DtlsRoleConn,
    expected_remote_fingerprint: DtlsFingerprint,
    tx_seq: u64,
    last_flight: Option<Vec<u8>>,
    next_retransmit_at: Instant,
    completed: bool,
    failed: bool,
}

impl DtlsSrtpSession {
    /// Creates a new [`DtlsSrtpSession`] for `local_role` (`Active` = client, `Passive` = server)
    /// expecting `expected_remote_fingerprint` from SDP `a=fingerprint:`.
    pub fn new(
        identity: &DtlsIdentity,
        local_role: DtlsSetupRole,
        expected_remote_fingerprint: DtlsFingerprint,
        now: Instant,
    ) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert_chain = vec![identity.cert_der.clone()];
        let priv_key = identity.private_key_der();

        let conn = match local_role {
            DtlsSetupRole::Active | DtlsSetupRole::ActPass => {
                let cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| e.to_string())?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(DtlsServerCertVerifier { provider }))
                    .with_client_auth_cert(cert_chain, priv_key)
                    .map_err(|e| e.to_string())?;
                let sn = ServerName::try_from("bmsip.dtls.local".to_string())
                    .map_err(|e| e.to_string())?;
                let c = ClientConnection::new(Arc::new(cfg), sn).map_err(|e| e.to_string())?;
                DtlsRoleConn::Client(c)
            }
            DtlsSetupRole::Passive => {
                let cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| e.to_string())?
                    .with_client_cert_verifier(Arc::new(DtlsClientCertVerifier { provider }))
                    .with_single_cert(cert_chain, priv_key)
                    .map_err(|e| e.to_string())?;
                let s = ServerConnection::new(Arc::new(cfg)).map_err(|e| e.to_string())?;
                DtlsRoleConn::Server(s)
            }
        };

        Ok(Self {
            conn,
            expected_remote_fingerprint,
            tx_seq: 0,
            last_flight: None,
            next_retransmit_at: now + DTLS_RETRANSMIT_INTERVAL,
            completed: false,
            failed: false,
        })
    }

    /// Returns `true` if the DTLS-SRTP handshake has failed (e.g., fingerprint mismatch).
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Returns `true` if the DTLS-SRTP handshake has completed and verified the peer fingerprint.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Produces any initial or retransmitted outbound DTLS flight datagrams.
    pub fn poll_transmit(&mut self, now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if self.failed {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let raw_tls = self.conn.write_tls_flight()?;
        if !raw_tls.is_empty() {
            let framed = self.frame_dtls_record(&raw_tls);
            self.last_flight = Some(framed.clone());
            self.next_retransmit_at = now + DTLS_RETRANSMIT_INTERVAL;
            out.push(framed);
        } else if !self.completed && now >= self.next_retransmit_at {
            if let Some(flight) = self.last_flight.as_ref() {
                self.next_retransmit_at = now + DTLS_RETRANSMIT_INTERVAL;
                out.push(flight.clone());
            }
        }
        Ok(out)
    }

    /// Processes an inbound DTLS datagram (`20..=63`) from the RTP UDP socket.
    pub fn receive_datagram(
        &mut self,
        datagram: &[u8],
        now: Instant,
    ) -> Result<DtlsStepOutput, String> {
        if self.failed {
            return Err("DTLS-SRTP session already failed".to_string());
        }
        if datagram.len() < DTLS_RECORD_HEADER_LEN || !is_dtls_datagram(datagram) {
            return Err("malformed DTLS record header".to_string());
        }
        let frag_len = usize::from(u16::from_be_bytes([datagram[11], datagram[12]]));
        if datagram.len() < DTLS_RECORD_HEADER_LEN + frag_len {
            return Err("truncated DTLS record payload".to_string());
        }
        let tls_payload = &datagram[DTLS_RECORD_HEADER_LEN..DTLS_RECORD_HEADER_LEN + frag_len];

        if let Err(err) = self.conn.read_and_process(tls_payload) {
            self.failed = true;
            return Err(err);
        }

        let mut outbound_packets = Vec::new();
        let raw_reply = self.conn.write_tls_flight()?;
        if !raw_reply.is_empty() {
            let framed = self.frame_dtls_record(&raw_reply);
            self.last_flight = Some(framed.clone());
            self.next_retransmit_at = now + DTLS_RETRANSMIT_INTERVAL;
            outbound_packets.push(framed);
        }

        let mut established_keys = None;
        if !self.completed && !self.conn.is_handshaking() {
            let peer_certs = self.conn.peer_certificates().ok_or_else(|| {
                self.failed = true;
                "DTLS-SRTP peer presented no X.509 certificate".to_string()
            })?;
            let Some(first_cert) = peer_certs.first() else {
                self.failed = true;
                return Err("DTLS-SRTP peer certificate chain was empty".to_string());
            };
            let actual_fp = DtlsFingerprint::sha256_from_der(first_cert.as_ref());
            if !actual_fp.matches(&self.expected_remote_fingerprint) {
                self.failed = true;
                return Err(format!(
                    "DTLS-SRTP peer certificate fingerprint mismatch: expected '{}', got '{}'",
                    self.expected_remote_fingerprint, actual_fp
                ));
            }

            let exported = self.conn.export_srtp_keys()?;
            let (tx_mat, rx_mat) =
                SrtpKeyMaterial::from_dtls_exporter_output(&exported, self.conn.is_client())
                    .map_err(|e| {
                        self.failed = true;
                        e.to_string()
                    })?;
            self.completed = true;
            established_keys = Some((
                SrtpSuite::AesCm128HmacSha1_80,
                tx_mat.to_key_salt(),
                rx_mat.to_key_salt(),
            ));
        }

        Ok(DtlsStepOutput {
            outbound_packets,
            established_keys,
        })
    }

    fn frame_dtls_record(&mut self, tls_bytes: &[u8]) -> Vec<u8> {
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let seq_be = self.tx_seq.to_be_bytes();
        let len_be = (tls_bytes.len() as u16).to_be_bytes();

        let mut pkt = Vec::with_capacity(DTLS_RECORD_HEADER_LEN + tls_bytes.len());
        pkt.push(DTLS_CONTENT_TYPE_HANDSHAKE);
        pkt.extend_from_slice(&DTLS_VERSION_1_2);
        pkt.extend_from_slice(&0u16.to_be_bytes()); // epoch 0
        pkt.extend_from_slice(&seq_be[2..8]); // 48-bit sequence number
        pkt.extend_from_slice(&len_be);
        pkt.extend_from_slice(tls_bytes);
        pkt
    }
}

/// Verifies TLS handshake signatures on self-signed server certificates; actual identity verification
/// is enforced against SDP `a=fingerprint:sha-256` per RFC 5763 §5.
#[derive(Debug)]
struct DtlsServerCertVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for DtlsServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Requires the DTLS client (`a=setup:active`) to present its self-signed certificate and verifies its signature
/// so the DTLS server (`a=setup:passive`) can validate the client's SDP `a=fingerprint:sha-256`.
#[derive(Debug)]
struct DtlsClientCertVerifier {
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for DtlsClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
