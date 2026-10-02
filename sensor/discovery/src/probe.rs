//! Per-open-port fact collection: passive banner, TLS certificate summary, HTTP `HEAD`.
//!
//! Read-only by construction: the only bytes ever sent are a TLS ClientHello and
//! `HEAD / HTTP/1.0`. Certificates are recorded, never trusted or judged.

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::{Oid, OidRegistry};
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

use crate::guard::AuthorizedTarget;
use crate::job::{Banner, CertSummary, PortReport, Probe, TlsInfo};
use crate::scan::{Dialer, Halt, dial_error};

const BANNER_CAP: usize = 1024;
/// After the first bytes arrive, keep reading briefly for the rest of a multi-segment banner.
const READ_GRACE: Duration = Duration::from_millis(150);
const HTTP_HEAD: &[u8] = b"HEAD / HTTP/1.0\r\n\r\n";

pub async fn probe(
    dialer: &Dialer,
    target: &AuthorizedTarget,
    port: u16,
    mut stream: TcpStream,
) -> Result<PortReport, Halt> {
    let mut report = PortReport {
        port,
        proto: "tcp",
        state: "open",
        banner: None,
        tls: None,
    };
    let wait = dialer.banner_timeout;

    // 1. Server-first protocols (SSH, SMTP, FTP, NATS INFO…).
    if let Some(text) = read_banner(&mut stream, wait).await {
        report.banner = Some(Banner {
            probe: Probe::Passive,
            text,
        });
        return Ok(report);
    }
    drop(stream);

    // 2. TLS: record the certificate, then HEAD over the encrypted channel.
    if let Some(stream) = redial(dialer, target, port).await? {
        if let Some((tls, text)) = tls_probe(stream, target.ip(), wait).await {
            report.tls = Some(tls);
            report.banner = text.map(|text| Banner {
                probe: Probe::Https,
                text,
            });
            return Ok(report);
        }
    }

    // 3. Plain HTTP.
    if let Some(mut stream) = redial(dialer, target, port).await? {
        if let Some(text) = send_and_read(&mut stream, HTTP_HEAD, wait).await {
            report.banner = Some(Banner {
                probe: Probe::Http,
                text,
            });
        }
    }
    Ok(report)
}

/// Re-dial through the same guard + rate limiter. Only halting errors propagate.
async fn redial(
    dialer: &Dialer,
    target: &AuthorizedTarget,
    port: u16,
) -> Result<Option<TcpStream>, Halt> {
    match dialer.dial(target, port).await {
        Ok(s) => Ok(Some(s)),
        Err(e) => dial_error(e).map(|_| None),
    }
}

async fn read_banner<S: AsyncRead + Unpin>(stream: &mut S, wait: Duration) -> Option<String> {
    let mut buf = vec![0u8; BANNER_CAP];
    let mut n = match timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(k)) if k > 0 => k,
        _ => return None,
    };
    while n < BANNER_CAP {
        match timeout(READ_GRACE, stream.read(&mut buf[n..])).await {
            Ok(Ok(k)) if k > 0 => n += k,
            _ => break,
        }
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

async fn send_and_read<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    request: &[u8],
    wait: Duration,
) -> Option<String> {
    timeout(wait, stream.write_all(request)).await.ok()?.ok()?;
    read_banner(stream, wait).await
}

async fn tls_probe(
    stream: TcpStream,
    ip: IpAddr,
    wait: Duration,
) -> Option<(TlsInfo, Option<String>)> {
    let connector = TlsConnector::from(TLS_CONFIG.clone());
    // An IP server name means rustls sends no SNI.
    let name = ServerName::IpAddress(ip.into());
    let mut tls = timeout(wait, connector.connect(name, stream))
        .await
        .ok()?
        .ok()?;
    let info = {
        let (_, conn) = tls.get_ref();
        let chain = conn.peer_certificates()?;
        TlsInfo {
            version: conn.protocol_version()?.as_str()?.replace('_', "."),
            cipher_suite: conn.negotiated_cipher_suite()?.suite().as_str()?.to_owned(),
            cert: summarize(chain.first()?.as_ref())?,
            chain_length: chain.len(),
        }
    };
    let text = send_and_read(&mut tls, HTTP_HEAD, wait).await;
    Some((info, text))
}

pub fn summarize(der: &[u8]) -> Option<CertSummary> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let registry = OidRegistry::default().with_crypto().with_x509();
    let name = |oid: &Oid| {
        registry
            .get(oid)
            .map_or_else(|| oid.to_id_string(), |e| e.sn().to_owned())
    };
    let sans = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext.value.general_names.iter().map(general_name).collect(),
        _ => Vec::new(),
    };
    let public_key_bits = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(k)) => Some(k.key_size()),
        Ok(PublicKey::EC(k)) => Some(k.key_size()),
        _ => None,
    };
    Some(CertSummary {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        sans,
        not_before: cert.validity().not_before.to_datetime(),
        not_after: cert.validity().not_after.to_datetime(),
        signature_algorithm: name(&cert.signature_algorithm.algorithm),
        public_key_algorithm: name(&cert.public_key().algorithm.algorithm),
        public_key_bits,
        sha256: Sha256::digest(der)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    })
}

fn general_name(n: &GeneralName<'_>) -> String {
    match n {
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("URI:{s}"),
        GeneralName::IPAddress(b) => match <[u8; 4]>::try_from(*b) {
            Ok(v4) => format!("IP:{}", IpAddr::from(v4)),
            Err(_) => match <[u8; 16]>::try_from(*b) {
                Ok(v6) => format!("IP:{}", IpAddr::from(v6)),
                Err(_) => format!("IP:{b:02x?}"),
            },
        },
        other => format!("{other:?}"),
    }
}

static TLS_CONFIG: LazyLock<Arc<ClientConfig>> = LazyLock::new(|| {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(RecordOnly(provider)))
        .with_no_client_auth();
    Arc::new(config)
});

/// Accepts any certificate: the sensor records what a server presents so correlation
/// can judge it later. Nothing sensitive is sent over these connections.
#[derive(Debug)]
struct RecordOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for RecordOnly {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
