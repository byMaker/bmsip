//! MODULE_CONTRACT: Safe Rust TLS 1.2–1.3 configuration (`TlsConfig`) and `rustls` client/server builders for SIP over TLS (RFC 5922).
//! INVARIANTS: `#![forbid(unsafe_code)]`; uses pure-Rust `rustls` with `ring` crypto provider (zero OpenSSL C dependency); verifies certificates and hostnames by default unless `accept_invalid_certs` is explicitly enabled.
//! RFC_REFS: RFC 5922 (Domain Certificates in SIP), RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2).

#![forbid(unsafe_code)]

use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, ServerConfig,
    SignatureScheme,
};

use crate::error::EngineError;

/// TLS configuration for SIP over TLS (`SipTransport::Tls`) client and optional direct-peer server connections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsConfig {
    /// Optional explicit TLS SNI / certificate hostname override (defaults to SIP domain or peer IP).
    pub server_name: Option<String>,
    /// Optional PEM-encoded root CA certificate(s) added to the trust store (and used for client verification if server mode is enabled).
    pub ca_cert_pem: Option<String>,
    /// Optional PEM-encoded client certificate chain for mutual TLS (mTLS).
    pub client_cert_pem: Option<String>,
    /// Optional PEM-encoded client private key (PKCS#8, RSA, or EC) for mutual TLS (mTLS).
    pub client_key_pem: Option<String>,
    /// Disables server certificate chain & hostname verification (development/self-signed lab testing only).
    pub accept_invalid_certs: bool,
    /// Optional PEM-encoded server certificate chain for accepting inbound direct P2P TLS connections.
    pub server_cert_pem: Option<String>,
    /// Optional PEM-encoded server private key for accepting inbound direct P2P TLS connections.
    pub server_key_pem: Option<String>,
}

impl TlsConfig {
    /// Creates a default [`TlsConfig`] with standard WebPKI root certificates and strict verification enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets an explicit SNI / hostname override for certificate validation.
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }

    /// Adds PEM-encoded trusted root CA certificate(s).
    pub fn with_ca_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    /// Configures a client certificate chain and private key for mutual TLS (mTLS).
    pub fn with_client_identity(
        mut self,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> Self {
        self.client_cert_pem = Some(cert_pem.into());
        self.client_key_pem = Some(key_pem.into());
        self
    }

    /// Configures a server certificate chain and private key for inbound direct TLS connections.
    pub fn with_server_identity(
        mut self,
        cert_pem: impl Into<String>,
        key_pem: impl Into<String>,
    ) -> Self {
        self.server_cert_pem = Some(cert_pem.into());
        self.server_key_pem = Some(key_pem.into());
        self
    }

    /// Enables or disables certificate verification (`true` accepts self-signed/untrusted certs for lab testing).
    pub fn with_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }
}

/// Builds a `rustls::ClientConfig` from [`TlsConfig`] using the `ring` crypto provider.
pub(crate) fn build_client_config(cfg: &TlsConfig) -> Result<Arc<ClientConfig>, EngineError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ca_pem) = cfg.ca_cert_pem.as_deref() {
        let extra_certs = parse_pem_certs(ca_pem)?;
        for cert in extra_certs {
            roots.add(cert).map_err(|e| {
                EngineError::InvalidConfig(format!("failed to add TLS CA certificate: {e}"))
            })?;
        }
    }

    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| EngineError::InvalidConfig(format!("TLS protocol config error: {e}")))?;

    let wants_auth = if cfg.accept_invalid_certs {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier::new(provider)))
    } else {
        builder.with_root_certificates(roots)
    };

    let client_cfg = match (
        cfg.client_cert_pem.as_deref(),
        cfg.client_key_pem.as_deref(),
    ) {
        (Some(cert_pem), Some(key_pem)) => {
            let certs = parse_pem_certs(cert_pem)?;
            let key = parse_pem_private_key(key_pem)?;
            wants_auth.with_client_auth_cert(certs, key).map_err(|e| {
                EngineError::InvalidConfig(format!("invalid mTLS client identity: {e}"))
            })?
        }
        (None, None) => wants_auth.with_no_client_auth(),
        _ => {
            return Err(EngineError::InvalidConfig(
                "mTLS requires both client_cert_pem and client_key_pem".to_string(),
            ));
        }
    };

    Ok(Arc::new(client_cfg))
}

/// Builds an optional `rustls::ServerConfig` when `server_cert_pem` and `server_key_pem` are configured.
pub(crate) fn build_server_config(
    cfg: &TlsConfig,
) -> Result<Option<Arc<ServerConfig>>, EngineError> {
    let (Some(cert_pem), Some(key_pem)) = (
        cfg.server_cert_pem.as_deref(),
        cfg.server_key_pem.as_deref(),
    ) else {
        return Ok(None);
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = parse_pem_certs(cert_pem)?;
    let key = parse_pem_private_key(key_pem)?;

    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| EngineError::InvalidConfig(format!("TLS server protocol error: {e}")))?;

    let server_cfg = if let Some(ca_pem) = cfg.ca_cert_pem.as_deref() {
        let mut roots = RootCertStore::empty();
        for cert in parse_pem_certs(ca_pem)? {
            roots.add(cert).map_err(|e| {
                EngineError::InvalidConfig(format!("failed to add server CA certificate: {e}"))
            })?;
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| {
                EngineError::InvalidConfig(format!("failed to build mTLS client verifier: {e}"))
            })?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| EngineError::InvalidConfig(format!("invalid TLS server identity: {e}")))?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| EngineError::InvalidConfig(format!("invalid TLS server identity: {e}")))?
    };

    Ok(Some(Arc::new(server_cfg)))
}

/// Resolves the RFC 5922 TLS `ServerName` from explicit override, target URI host hint, registrar fallback domain, or peer IP.
pub(crate) fn resolve_server_name(
    override_name: Option<&str>,
    peer_host_hint: Option<&str>,
    fallback_domain: Option<&str>,
    dest: SocketAddr,
) -> Result<ServerName<'static>, EngineError> {
    let candidates = [override_name, peer_host_hint, fallback_domain];
    for raw in candidates.into_iter().flatten() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let host_only = extract_host_only(trimmed);
        if host_only.is_empty() {
            continue;
        }
        if let Ok(ip) = host_only.parse::<IpAddr>() {
            return Ok(ServerName::from(ip));
        }
        if let Ok(sn) = ServerName::try_from(host_only.to_string()) {
            return Ok(sn);
        }
    }

    Ok(ServerName::from(dest.ip()))
}

fn extract_host_only(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((bracketed_host, _)) = rest.split_once(']') {
            return bracketed_host;
        }
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return trimmed;
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed.rsplit_once(':').map_or(trimmed, |(h, _)| h);
    }
    trimmed
}

fn parse_pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, EngineError> {
    let mut reader = Cursor::new(pem.as_bytes());
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| {
        EngineError::InvalidConfig(format!("failed to parse PEM certificate(s): {e}"))
    })?;
    if certs.is_empty() {
        return Err(EngineError::InvalidConfig(
            "PEM certificate input contained no CERTIFICATE blocks".to_string(),
        ));
    }
    Ok(certs)
}

fn parse_pem_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, EngineError> {
    let mut reader = Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| EngineError::InvalidConfig(format!("failed to parse PEM private key: {e}")))?
        .ok_or_else(|| {
            EngineError::InvalidConfig(
                "PEM private key input contained no PRIVATE KEY block".to_string(),
            )
        })
}

/// Development-only verifier accepting any server certificate when `TlsConfig::accept_invalid_certs` is `true`.
#[derive(Debug)]
struct AcceptAnyCertVerifier {
    provider: Arc<CryptoProvider>,
}

impl AcceptAnyCertVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for AcceptAnyCertVerifier {
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
        rustls::crypto::verify_tls12_signature(
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
        rustls::crypto::verify_tls13_signature(
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_ipv6_literals_peer_host_hints_and_overrides() {
        let v4_dest: SocketAddr = "10.0.0.10:5061".parse().unwrap();
        let v6_dest: SocketAddr = "[2001:db8::1]:5061".parse().unwrap();

        assert_eq!(
            resolve_server_name(
                Some("override.example.com:5061"),
                Some("route.example.com"),
                Some("domain.example.com"),
                v4_dest,
            )
            .unwrap(),
            ServerName::try_from("override.example.com".to_string()).unwrap()
        );

        assert_eq!(
            resolve_server_name(None, Some("proxy2.example.com:5061"), None, v4_dest).unwrap(),
            ServerName::try_from("proxy2.example.com".to_string()).unwrap()
        );

        assert_eq!(
            resolve_server_name(None, None, Some("[2001:db8::2]:5061"), v6_dest).unwrap(),
            ServerName::from("2001:db8::2".parse::<IpAddr>().unwrap())
        );

        assert_eq!(
            resolve_server_name(None, Some("2001:db8::3"), None, v6_dest).unwrap(),
            ServerName::from("2001:db8::3".parse::<IpAddr>().unwrap())
        );
    }
}
