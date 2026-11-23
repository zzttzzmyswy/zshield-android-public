//! Upstream DNS transports: DNS over HTTPS (RFC 8484) and plaintext UDP.
//!
//! DoH uses HTTP/2 over TLS with `rustls` and certificate verification through
//! `rustls-platform-verifier` (the Android system trust store). Verification is never relaxed:
//! the only unusual thing here is that the TCP connection is opened to a configured bootstrap IP
//! while the TLS SNI and `:authority` use the configured hostname, because the system resolver is
//! what this app replaces.
//!
//! Connections are kept alive and multiplexed by HTTP/2; a broken connection is re-established
//! once before the query is reported as failed.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use crate::config::{DohEndpoint, UpstreamConfig};
use rustls_platform_verifier::BuilderVerifierExt;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";
/// DoH responses are small; anything larger is a broken or hostile upstream.
const MAX_DOH_RESPONSE: usize = 64 * 1024;
const MAX_UDP_RESPONSE: usize = 4096;

#[derive(Debug)]
pub enum UpstreamError {
    Io(String),
    Tls(String),
    Http(String),
    Timeout,
    TooLarge,
    BadStatus(u16),
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Io(e) => write!(f, "io: {e}"),
            UpstreamError::Tls(e) => write!(f, "tls: {e}"),
            UpstreamError::Http(e) => write!(f, "http: {e}"),
            UpstreamError::Timeout => f.write_str("timeout"),
            UpstreamError::TooLarge => f.write_str("response too large"),
            UpstreamError::BadStatus(code) => write!(f, "http status {code}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// Anything that can answer a raw DNS message.
///
/// The trait exists so the request pipeline can be tested against a scripted resolver without a
/// network, and so DoT/other transports can be added later without touching the pipeline.
pub trait Resolver: Send + Sync + std::fmt::Debug {
    /// Send one DNS message and return the reply body.
    fn query<'a>(
        &'a self,
        message: &'a [u8],
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, UpstreamError>> + Send + 'a>>;

    /// Short name used in logs and `statsJson`.
    fn label(&self) -> &str;
}

/// One configured upstream, with its retained DoH connection.
#[derive(Debug)]
pub struct Upstream {
    kind: UpstreamKind,
    label: String,
}

#[derive(Debug)]
enum UpstreamKind {
    Doh(DohUpstream),
    Udp { address: std::net::SocketAddr },
}

struct DohUpstream {
    endpoint: DohEndpoint,
    bootstrap: Vec<std::net::IpAddr>,
    connector: TlsConnector,
    /// Live HTTP/2 connection, created on first use.
    sender: Mutex<Option<hyper::client::conn::http2::SendRequest<Full<Bytes>>>>,
    /// Round-robin cursor over `bootstrap` so a dead address is not sticky forever.
    cursor: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for DohUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohUpstream")
            .field("endpoint", &self.endpoint)
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// Build a runtime upstream from configuration.
    pub fn new(cfg: &UpstreamConfig) -> Result<Self, UpstreamError> {
        match cfg {
            UpstreamConfig::Doh { url, bootstrap } => {
                let endpoint = DohEndpoint::parse(url)
                    .map_err(|e| UpstreamError::Io(format!("bad DoH URL: {e}")))?;
                let mut ips = Vec::with_capacity(bootstrap.len());
                for raw in bootstrap {
                    let ip = raw
                        .trim()
                        .parse::<std::net::IpAddr>()
                        .map_err(|_| UpstreamError::Io(format!("bad bootstrap IP: {raw}")))?;
                    ips.push(ip);
                }
                if ips.is_empty() {
                    return Err(UpstreamError::Io(
                        "DoH upstream requires a bootstrap address".to_string(),
                    ));
                }
                let connector = TlsConnector::from(Arc::new(tls_client_config()?));
                Ok(Self {
                    label: format!("doh:{url}"),
                    kind: UpstreamKind::Doh(DohUpstream {
                        endpoint,
                        bootstrap: ips,
                        connector,
                        sender: Mutex::new(None),
                        cursor: std::sync::atomic::AtomicUsize::new(0),
                    }),
                })
            }
            UpstreamConfig::Udp { address } => {
                let address = address
                    .trim()
                    .parse::<std::net::SocketAddr>()
                    .map_err(|_| UpstreamError::Io(format!("bad UDP upstream: {address}")))?;
                Ok(Self {
                    label: format!("udp:{address}"),
                    kind: UpstreamKind::Udp { address },
                })
            }
        }
    }

    /// The scheme name used in logs and `statsJson`.
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            UpstreamKind::Doh(_) => "doh",
            UpstreamKind::Udp { .. } => "udp",
        }
    }

    /// Send one DNS message and return the reply body.
    pub async fn query(&self, message: &[u8], timeout: Duration) -> Result<Vec<u8>, UpstreamError> {
        let fut = async {
            match &self.kind {
                UpstreamKind::Doh(doh) => doh.query(message).await,
                UpstreamKind::Udp { address } => udp_query(*address, message).await,
            }
        };
        match tokio::time::timeout(timeout, fut).await {
            Ok(result) => result,
            Err(_) => Err(UpstreamError::Timeout),
        }
    }
}

impl Resolver for Upstream {
    fn query<'a>(
        &'a self,
        message: &'a [u8],
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, UpstreamError>> + Send + 'a>> {
        Box::pin(Upstream::query(self, message, timeout))
    }

    fn label(&self) -> &str {
        &self.label
    }
}

/// A TLS client config that verifies against the platform trust store.
///
/// HTTP/2 is negotiated via ALPN (`h2`): the request pipeline speaks HTTP/2 exclusively, and a
/// server that is allowed to fall back to HTTP/1.1 would answer in a format hyper's h2 client
/// cannot parse (the connection would fail with an opaque "http2 error").
fn tls_client_config() -> Result<rustls::ClientConfig, UpstreamError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| UpstreamError::Tls(e.to_string()))?
        .with_platform_verifier()
        .map_err(|e| UpstreamError::Tls(e.to_string()))?
        // DoH servers do not ask for client certificates.
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

impl DohUpstream {
    async fn query(&self, message: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        // First attempt uses the retained connection; on any HTTP/2 level failure the connection
        // is dropped and the query retried once on a fresh one.
        match self.query_once(message).await {
            Ok(response) => Ok(response),
            Err(first) => {
                *self.sender.lock().await = None;
                self.query_once(message)
                    .await
                    .map_err(|second| UpstreamError::Http(format!("{first}; retry: {second}")))
            }
        }
    }

    async fn query_once(&self, message: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        let mut guard = self.sender.lock().await;
        if guard.is_none() {
            *guard = Some(self.connect().await?);
        }
        let sender = guard.as_mut().expect("sender present");

        sender
            .ready()
            .await
            .map_err(|e| UpstreamError::Http(format!("connection not ready: {e}")))?;

        let request = Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("https://{}{}", self.endpoint.authority, self.endpoint.path))
            .header(hyper::header::HOST, &self.endpoint.authority)
            .header(hyper::header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)
            .header(hyper::header::ACCEPT, DNS_MESSAGE_CONTENT_TYPE)
            .body(Full::new(Bytes::copy_from_slice(message)))
            .map_err(|e| UpstreamError::Http(e.to_string()))?;

        let response = sender
            .send_request(request)
            .await
            .map_err(|e| UpstreamError::Http(format!("request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(UpstreamError::BadStatus(response.status().as_u16()));
        }
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| UpstreamError::Http(format!("body failed: {e}")))?
            .to_bytes();
        if body.len() > MAX_DOH_RESPONSE {
            return Err(UpstreamError::TooLarge);
        }
        Ok(body.to_vec())
    }

    async fn connect(&self) -> Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>, UpstreamError> {
        let mut last_error = None;
        let count = self.bootstrap.len();
        let start = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % count;

        for offset in 0..count {
            let ip = self.bootstrap[(start + offset) % count];
            let addr = std::net::SocketAddr::new(ip, self.endpoint.port);
            match self.connect_to(addr).await {
                Ok(sender) => return Ok(sender),
                Err(err) => last_error = Some(format!("{addr}: {err}")),
            }
        }
        Err(UpstreamError::Io(format!(
            "no bootstrap address reachable ({})",
            last_error.unwrap_or_else(|| "none configured".to_string())
        )))
    }

    async fn connect_to(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>, UpstreamError> {
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| UpstreamError::Io(e.to_string()))?;
        stream
            .set_nodelay(true)
            .map_err(|e| UpstreamError::Io(e.to_string()))?;
        let server_name = rustls::pki_types::ServerName::try_from(self.endpoint.host.clone())
            .map_err(|e| UpstreamError::Tls(e.to_string()))?;
        let tls = self
            .connector
            .connect(server_name, stream)
            .await
            .map_err(|e| UpstreamError::Tls(e.to_string()))?;

        let (sender, connection) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            TokioIo::new(tls),
        )
        .await
        .map_err(|e| UpstreamError::Http(e.to_string()))?;

        // The connection future must be driven for the sender to make progress. It ends when the
        // sender is dropped (e.g. after a failure) which is exactly the lifetime we want.
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                crate::log_msg("debug", &format!("DoH connection closed: {err}"));
            }
        });

        Ok(sender)
    }
}

async fn udp_query(
    address: std::net::SocketAddr,
    message: &[u8],
) -> Result<Vec<u8>, UpstreamError> {
    let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| UpstreamError::Io(e.to_string()))?;
    socket
        .connect(address)
        .await
        .map_err(|e| UpstreamError::Io(e.to_string()))?;
    socket
        .send(message)
        .await
        .map_err(|e| UpstreamError::Io(e.to_string()))?;
    let mut buf = vec![0u8; MAX_UDP_RESPONSE];
    let len = socket
        .recv(&mut buf)
        .await
        .map_err(|e| UpstreamError::Io(e.to_string()))?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(url: &str) -> DohEndpoint {
        DohEndpoint::parse(url).expect("endpoint")
    }

    #[test]
    fn builds_a_verified_tls_client() {
        // Verifying against the platform store must never be replaced by an accept-all verifier.
        let cfg = tls_client_config().expect("client config");
        // Only HTTP/2 is offered: the pipeline uses hyper's h2 client and nothing else.
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn rejects_doh_without_bootstrap() {
        let cfg = UpstreamConfig::Doh {
            url: "https://dns.alidns.com/dns-query".to_string(),
            bootstrap: vec![],
        };
        assert!(Upstream::new(&cfg).is_err());
    }

    #[test]
    fn accepts_the_design_default_upstreams() {
        for cfg in crate::config::default_upstreams() {
            let upstream = Upstream::new(&cfg).expect("upstream");
            assert_eq!(upstream.kind_name(), "doh");
            assert!(upstream.label().starts_with("doh:"), "{}", upstream.label());
            assert!(upstream.label().ends_with("/dns-query"), "{}", upstream.label());
        }
    }

    #[test]
    fn parses_udp_upstream() {
        let cfg = UpstreamConfig::Udp {
            address: "1.1.1.1:53".to_string(),
        };
        let upstream = Upstream::new(&cfg).expect("upstream");
        assert_eq!(upstream.kind_name(), "udp");
        let bad = UpstreamConfig::Udp {
            address: "1.1.1.1".to_string(),
        };
        assert!(Upstream::new(&bad).is_err());
    }

    #[test]
    fn doh_request_target_uses_authority_and_path() {
        let ep = endpoint("https://dns.alidns.com/dns-query");
        assert_eq!(
            format!("https://{}{}", ep.authority, ep.path),
            "https://dns.alidns.com/dns-query"
        );
    }
}
