//! End-to-end tests of the HTTPS path: real TLS on both legs, no device and no network.
//!
//! The shape of every test is the same: a scripted origin server on a loopback port, the MITM relay
//! in the middle, and a client that speaks TLS to the relay exactly as a browser would. The only
//! thing that is not production code is the *upstream* trust decision: a test origin is signed by a
//! root the test controls, so the upstream verifier is given that root instead of the platform store
//! ([`crate::https::tls::client_config_with_roots`], compiled only for tests). Production has no way
//! to reach that function — the acceptance criterion for this milestone is that the upstream check is
//! never relaxed.
//!
//! What the tests pin down (task card §1 acceptance):
//!
//! - a decrypted HTTP/1.1 request is allowed or blocked on its full URL;
//! - several HTTP/2 streams on one connection are decided independently;
//! - an unacceptable upstream certificate makes the relay replay the ClientHello instead, so the
//!   client sees the origin's real certificate;
//! - a client that does not trust our leaf is auto-bypassed, and its next connection is passed
//!   through;
//! - ALPN (`h2`, `http/1.1`, none) decides the framing;
//! - the leaf is issued for the SNI with the fields the task card fixes;
//! - `$removeparam`, `$removeheader`, `$csp` and `$redirect` all reach the wire.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::http::decision::HttpFilter;
use crate::http::log::{RequestLog, RequestOutcome};
use crate::http::relay::{HttpContext, HttpStats};
use crate::https::ca::{self, Ca};
use crate::https::mitm::{self, HttpsContext, HttpsOutcome};
use crate::https::modifiers;
use crate::https::policy::AutoBypass;
use crate::https::stats::HttpsStats;
use crate::https::tls::{self, Alpn};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

/// A root CA for the *origin* side of a test, plus a leaf for one host.
struct TestPki {
    ca: ca::GeneratedCa,
    /// The loaded CA, so a test can issue the same leaf the origin served (leaf issuance is
    /// deterministic per host only because of this cache).
    loaded: Arc<Ca>,
    /// Server config that presents the leaf for `host`.
    server: Arc<rustls::ServerConfig>,
    /// Client config that trusts only this test root.
    roots: rustls::RootCertStore,
}

impl TestPki {
    fn new(host: &str) -> Self {
        let ca = ca::generate().expect("origin CA");
        let loaded = Arc::new(ca::load(&ca.cert_pem, &ca.key).expect("origin CA loads"));
        let leaf = loaded.leaf_for(host).expect("origin leaf");
        let chain: Vec<rustls_pki_types::CertificateDer<'static>> = leaf
            .chain_der
            .iter()
            .map(|der| rustls_pki_types::CertificateDer::from(der.clone()))
            .collect();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(leaf.key_pkcs8.clone()),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls_pki_types::CertificateDer::from(ca.cert_der.clone()))
            .expect("root");
        Self {
            ca,
            loaded,
            server: Arc::new(server),
            roots,
        }
    }

    fn with_alpn(mut self, alpn: &[&[u8]]) -> Self {
        let mut config = (*self.server).clone();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        self.server = Arc::new(config);
        self
    }
}

/// A scripted origin: for each accepted connection, run `handler` on the TLS stream.
struct Origin {
    port: u16,
    accepted: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Origin {
    async fn start(
        pki: Arc<TestPki>,
        handler: impl Fn(tokio_rustls::server::TlsStream<TcpStream>) -> tokio::task::JoinHandle<()>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = accepted.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(pki.server.clone());
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::Relaxed);
                let acceptor = acceptor.clone();
                let handler = handler.clone();
                tokio::spawn(async move {
                    match acceptor.accept(socket).await {
                        Ok(stream) => {
                            handler(stream);
                        }
                        Err(_) => {
                            // A client that walked away mid-handshake is normal in these tests.
                        }
                    }
                });
            }
        });
        Self {
            port,
            accepted,
            task,
        }
    }

    fn remote(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    fn connections(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The MITM side: its own root CA, engines and counters.
struct Relay {
    ctx: HttpsContext,
    ca: Arc<Ca>,
    stats: Arc<HttpsStats>,
    log: Arc<RequestLog>,
}

impl Relay {
    fn new(rules: &str, removeheader: &str) -> Self {
        let mut set = adblock::lists::FilterSet::new(true);
        set.add_filter_list(rules.to_string(), adblock::lists::ParseOptions::default());
        let filter = Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set)));
        let log = Arc::new(RequestLog::new());
        let http_stats = Arc::new(HttpStats::default());
        let generated = ca::generate().expect("relay CA");
        let ca = Arc::new(ca::load(&generated.cert_pem, &generated.key).expect("relay CA loads"));
        let removeheader = Arc::new(modifiers::collect_removeheader([removeheader]));
        let modifier_source = Arc::new(modifiers::HttpsModifiers::new(
            filter.clone(),
            removeheader.clone(),
            filter.extras_arc(),
        ));
        Self {
            ctx: HttpsContext {
                http: HttpContext {
                    cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
                    framing: crate::cosmetic::OutFraming::Chunked,
                    filter,
                    log: log.clone(),
                    stats: http_stats,
                    head_limit: 8 * 1024,
                    scheme: crate::http::head::Scheme::Https,
                    modifiers: Some(modifier_source),
                },
                removeheader,
                ca: ca.clone(),
                // Replaced per test with a config that trusts the test origin.
                // Replaced per test by `trust`; an empty root store trusts nothing.
                upstream: tls::client_config_with_roots(rustls::RootCertStore::empty(), Vec::new()),
                bypass: Arc::new(AutoBypass::default()),
                stats: Arc::new(HttpsStats::default()),
            },
            ca,
            stats: Arc::new(HttpsStats::default()),
            log,
        }
    }

    /// Point the upstream leg at a trust store that accepts `pki`, and its records.
    fn trust(mut self, pki: &TestPki) -> Self {
        self.ctx.upstream = tls::client_config_with_roots(pki.roots.clone(), Vec::new());
        self.ctx.stats = self.stats.clone();
        self
    }

}

/// Everything a test needs to drive one connection: the browser-side socket and the relay's outcome.
///
/// `browser` is an `Option` because the TLS client owns the socket once it is created (a `TlsStream`
/// wrapping a `&mut` would keep the session borrowed for the whole test, and the session also owns the
/// join handle the test has to await).
struct Session {
    browser: Option<tokio::io::DuplexStream>,
    outcome: Option<tokio::task::JoinHandle<HttpsOutcome>>,
    relay_ca_pem: String,
}

impl Session {
    /// Start the relay on `remote` with the client end left for the test to drive.
    ///
    /// The task first reads the client's ClientHello off the socket — exactly what the tunnel's sniff
    /// phase does — and then hands those bytes to `mitm::run`, so the ALPN and SNI the relay sees are
    /// the real ones and not a fixture.
    fn start(relay: &Relay, remote: std::net::SocketAddr, host: &str, uid: u32) -> Self {
        Self::start_with(relay, remote, host, uid, None, None)
    }

    /// Start the relay with an already-open outbound socket, as the tunnel does: it dials before the
    /// sniff so the connection is warm by the time the decision is made.
    fn start_reusing(
        relay: &Relay,
        remote: std::net::SocketAddr,
        host: &str,
        uid: u32,
        outbound: TcpStream,
    ) -> Self {
        Self::start_with(relay, remote, host, uid, None, Some(outbound))
    }

    fn start_with(
        relay: &Relay,
        remote: std::net::SocketAddr,
        host: &str,
        uid: u32,
        _unused: Option<()>,
        outbound: Option<TcpStream>,
    ) -> Self {
        let (mut relay_side, browser) = tokio::io::duplex(1 << 20);
        let ctx = relay.ctx.clone();
        let host = host.to_string();
        let outcome = tokio::spawn(async move {
            let mut head = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match crate::tun::inspect::client_hello_info(&head) {
                    Some(info) => {
                        head.truncate(info.hello_len);
                        break;
                    }
                    None => {
                        if head.len() > 16 * 1024 {
                            break;
                        }
                    }
                }
                match relay_side.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(n) => head.extend_from_slice(&buffer[..n]),
                    Err(_) => break,
                }
            }
            mitm::run(relay_side, head, remote, &host, uid, &ctx, outbound).await
        });
        Self {
            browser: Some(browser),
            outcome: Some(outcome),
            relay_ca_pem: relay.ca_pem(),
        }
    }

    /// Connect as a browser: TLS with the relay's root trusted and `alpn` offered.
    ///
    /// Takes the socket, so the returned stream is owned: the tests need to hand it to `h2` and to
    /// keep it alive across awaits without borrowing the session.
    async fn browser_tls(
        &mut self,
        host: &str,
        alpn: &[&[u8]],
    ) -> Result<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>, String> {
        let browser = self.browser.take().expect("the browser socket is taken once");
        let config = tls::client_config_with_roots(
            self.relay_roots(),
            alpn.iter().map(|p| p.to_vec()).collect(),
        );
        let connector = tokio_rustls::TlsConnector::from(config);
        let name = tls::server_name(host).expect("server name");
        connector
            .connect(name, browser)
            .await
            .map_err(|e| e.to_string())
    }

    /// Wait for the relay task and report how the connection ended.
    async fn finish(&mut self) -> HttpsOutcome {
        let outcome = self.outcome.take().expect("the outcome is read once");
        tokio::time::timeout(Duration::from_secs(10), outcome)
            .await
            .expect("the relay must finish")
            .expect("the relay task must not panic")
    }

    /// Abandon the connection the way a browser abandons a pre-connect: send a real ClientHello,
    /// wait until the relay has answered with its first flight (so our certificate is on the wire by
    /// then), and disappear without a word.
    ///
    /// This is the exact sequence behind MYS-2727: Chrome opens several TLS connections to one host,
    /// completes one of them, and closes the rest mid-handshake.
    async fn hang_up_after_server_flight(&mut self, host: &str) {
        let browser = self.browser.take().expect("the browser socket is taken once");
        let roots = self.relay_roots();
        let config = tls::client_config_with_roots(roots, vec![tls::ALPN_HTTP11.to_vec()]);
        let connector = tokio_rustls::TlsConnector::from(config);
        let name = tls::server_name(host).expect("server name");
        // The wrapper errors out as soon as the first byte of the server's flight arrives, which is
        // only possible after rustls resolved (and sent) the leaf for this handshake.
        let result = connector.connect(name, CutOnFirstData::new(browser)).await;
        assert!(
            result.is_err(),
            "the abandoning client must not complete a handshake"
        );
    }

    /// Abandon the connection before the ClientHello is even complete, i.e. before the relay could
    /// have selected a certificate.
    async fn hang_up_mid_client_hello(&mut self, host: &str) {
        let mut browser = self.browser.take().expect("the browser socket is taken once");
        let hello = client_hello(host, &[b"http/1.1"]);
        // Half a ClientHello record: a client that gives up mid-send and is cut off.
        let partial = &hello[..hello.len() / 2];
        browser.write_all(partial).await.expect("write");
        browser.flush().await.expect("flush");
        drop(browser);
    }

    fn relay_roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        let der = ca::pem_certificate(&self.relay_ca_pem).expect("relay root pem");
        roots
            .add(rustls_pki_types::CertificateDer::from(der))
            .expect("trust the relay root");
        roots
    }
}

/// A stream that refuses to deliver data: the peer's first byte is treated as the end.
///
/// Used to model a client that walks away the moment the server's certificate flight appears
/// ([`Session::hang_up_after_server_flight`]).
struct CutOnFirstData<C> {
    inner: C,
}

impl<C> CutOnFirstData<C> {
    fn new(inner: C) -> Self {
        Self { inner }
    }
}

impl<C: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CutOnFirstData<C> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        // Deliberately unused: the point of this wrapper is to notice that data arrived and then
        // throw it away, so it is read into a scratch buffer instead.
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut scratch = [0u8; 4096];
        let mut staged = tokio::io::ReadBuf::new(&mut scratch);
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut staged) {
            std::task::Poll::Ready(Ok(())) => {
                if staged.filled().is_empty() {
                    // EOF from the peer: pass it on as EOF.
                    return std::task::Poll::Ready(Ok(()));
                }
                // The certificate flight is here; the client gives up instead of reading it.
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the browser abandoned the handshake",
                )))
            }
            other => other,
        }
    }
}

impl<C: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CutOnFirstData<C> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Relay {
    fn ca_pem(&self) -> String {
        // `Ca` keeps only the DER; re-encode it as PEM for the client's trust store.
        pem_encode(self.ca.root_der())
    }
}

fn pem_encode(der: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        b64.push(TABLE[(n >> 18) as usize & 63] as char);
        b64.push(TABLE[(n >> 12) as usize & 63] as char);
        b64.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        b64.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("ascii"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Build a ClientHello byte string with `host` and `alpn`, so a test can hand the relay exactly what
/// the tunnel's sniff phase would have buffered.
fn client_hello(host: &str, alpn: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0x11; 32]);
    body.push(32);
    body.extend_from_slice(&[0x22; 32]);
    let ciphers: &[u8] = &[0x13, 0x01, 0x13, 0x02];
    body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    body.extend_from_slice(ciphers);
    body.push(1);
    body.push(0);

    let mut extensions = Vec::new();
    // server_name
    let mut sni = Vec::new();
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    let mut list = Vec::new();
    list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    list.extend_from_slice(&sni);
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&list);
    if !alpn.is_empty() {
        let mut protocols = Vec::new();
        for protocol in alpn {
            protocols.push(protocol.len() as u8);
            protocols.extend_from_slice(protocol);
        }
        extensions.extend_from_slice(&16u16.to_be_bytes());
        extensions.extend_from_slice(&((protocols.len() + 2) as u16).to_be_bytes());
        extensions.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&protocols);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    let len = body.len();
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_decrypted_http11_request_is_filtered_on_its_full_url() {
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buffer).await {
                let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                let body = if request.contains("/ads.js") {
                    "ads"
                } else {
                    "page"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
            // Hold the connection until the client closes it.
            let mut sink = [0u8; 64];
            while let Ok(n) = stream.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        })
    })
    .await;

    let relay = Relay::new("||www.example.com/ads.js\n", "").trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut tls = session
        .browser_tls("www.example.com", &[b"http/1.1"])
        .await
        .expect("handshake");

    // 1. An allowed request reaches the origin byte for byte.
    tls.write_all(b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\n\r\n")
        .await
        .expect("write");
    let mut response = vec![0u8; 1024];
    let n = tls.read(&mut response).await.expect("read");
    assert!(
        String::from_utf8_lossy(&response[..n]).contains("page"),
        "the allowed request must reach the origin"
    );

    // 2. A request whose *path* matches is blocked locally — the whole point of decrypting.
    tls.write_all(b"GET /ads.js HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
        .await
        .expect("write");
    let mut blocked = Vec::new();
    // A `204` for a subresource carries no body, so the response ends at the head.
    loop {
        let mut byte = [0u8; 1];
        match tls.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => {
                blocked.push(byte[0]);
                if blocked.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let blocked = String::from_utf8_lossy(&blocked).to_string();
    assert!(
        blocked.starts_with("HTTP/1.1 204"),
        "an ad script must be answered locally, got {blocked:?}"
    );

    drop(tls);
    let outcome = session.finish().await;
    assert!(
        matches!(outcome, HttpsOutcome::Clean | HttpsOutcome::Failed),
        "unexpected outcome {outcome:?}"
    );

    let entries = relay.log.snapshot();
    assert!(
        entries
            .iter()
            .any(|entry| entry.url.contains("/ads.js") && entry.outcome == RequestOutcome::Blocked),
        "the blocked request must be in the log: {entries:?}"
    );
    assert_eq!(relay.stats.snapshot().intercepted, 1);
}

#[tokio::test]
async fn a_document_request_gets_the_blocked_page() {
    let pki = Arc::new(TestPki::new("ads.example.com"));
    let origin = Origin::start(pki.clone(), |_stream| tokio::spawn(async {})).await;
    let relay = Relay::new("||ads.example.com^\n", "").trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "ads.example.com", 10001);
    let mut tls = session
        .browser_tls("ads.example.com", &[])
        .await
        .expect("handshake");
    // A navigation, identified the way a browser identifies it: `Sec-Fetch-Dest: document`. Without
    // the hint the request type is "other" and the answer would be the subresource `204`.
    tls.write_all(b"GET / HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: document\r\nAccept: text/html\r\n\r\n")
        .await
        .expect("write");
    let mut response = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if tls.read(&mut byte).await.unwrap_or(0) == 0 {
            break;
        }
        response.push(byte[0]);
        if response.ends_with(b"</html>\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(text.starts_with("HTTP/1.1 403"), "got {text:?}");
    assert!(text.contains("ZShield"), "the blocked page names the blocker");
    // The origin was never contacted: the decision happened before any request was forwarded.
    assert_eq!(origin.connections(), 1, "only the upstream TLS leg, no request");
    drop(tls);
    let _ = session.finish().await;
}

/// The host every h2 test origin expects in `:authority`, and the scheme it expects in `:scheme`.
///
/// A real origin (nginx, a CDN) rejects a request without `:authority` with `400`, which is exactly
/// the bug these assertions catch: `h2` does not synthesize `:authority` from a `host` header, and
/// `forward` removes `host` as connection-specific.
const H2_AUTHORITY: &str = "www.example.com";

/// An origin that speaks h2 and *checks the pseudo-headers a real server needs*.
///
/// `body_prefix` is prepended to every response body, so a test can tell forwarded responses apart.
fn h2_origin(
    body_of: impl Fn(&str, &str) -> String + Send + Sync + 'static,
) -> impl Fn(tokio_rustls::server::TlsStream<TcpStream>) -> tokio::task::JoinHandle<()>
       + Send
       + Sync
       + 'static {
    let body_of = Arc::new(body_of);
    move |stream| {
        let body_of = body_of.clone();
        tokio::spawn(async move {
            let mut connection = match h2::server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            while let Some(accepted) = connection.accept().await {
                let Ok((mut request, mut respond)) = accepted else {
                    return;
                };
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let authority = request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str().to_string())
                    .unwrap_or_default();
                let scheme = request
                    .uri()
                    .scheme_str()
                    .map(str::to_string)
                    .unwrap_or_default();
                let host = request
                    .headers()
                    .get(http::header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body_of = body_of.clone();
                tokio::spawn(async move {
                    // The two things every real origin requires. A path-only URI fails here with
                    // `400`, which is what nginx and every CDN do.
                    if scheme != "https" || authority != H2_AUTHORITY || !host.is_empty() {
                        let response = http::Response::builder()
                            .status(400)
                            .header("content-type", "text/plain")
                            .body(())
                            .expect("response");
                        if let Ok(mut stream) = respond.send_response(response, false) {
                            let _ = stream.send_data(
                                bytes::Bytes::from(format!(
                                    "bad authority: scheme={scheme:?} authority={authority:?} host={host:?}"
                                )),
                                true,
                            );
                        }
                        return;
                    }
                    let body = body_of(&path, &request_body(&mut request).await);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .body(())
                        .expect("response");
                    if let Ok(mut stream) = respond.send_response(response, false) {
                        let _ = stream.send_data(bytes::Bytes::from(body), true);
                    }
                });
            }
        })
    }
}

/// Like [`h2_origin`], but the callback also receives the request **method**.
///
/// A rewrite must preserve the verb: h2 rewrites `:path` per stream, and a rebuild that forgot
/// `:method` would deliver a `GET` where the client sent a `POST` — with the same 200 and, if the
/// body happened to be empty, the same body. Asserting on target and body alone cannot see that, so
/// the method-aware variant exists for the rewrite regressions. Keeping it separate leaves every
/// existing `h2_origin` caller untouched.
fn h2_origin_with_method(
    body_of: impl Fn(&str, &str, &str) -> String + Send + Sync + 'static,
) -> impl Fn(tokio_rustls::server::TlsStream<TcpStream>) -> tokio::task::JoinHandle<()>
       + Send
       + Sync
       + 'static {
    let body_of = Arc::new(body_of);
    move |stream| {
        let body_of = body_of.clone();
        tokio::spawn(async move {
            let mut connection = match h2::server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            while let Some(accepted) = connection.accept().await {
                let Ok((mut request, mut respond)) = accepted else {
                    return;
                };
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let authority = request
                    .uri()
                    .authority()
                    .map(|authority| authority.as_str().to_string())
                    .unwrap_or_default();
                let scheme = request
                    .uri()
                    .scheme_str()
                    .map(str::to_string)
                    .unwrap_or_default();
                let method = request.method().as_str().to_string();
                let body_of = body_of.clone();
                tokio::spawn(async move {
                    if scheme != "https" || authority != H2_AUTHORITY {
                        let response = http::Response::builder()
                            .status(400)
                            .header("content-type", "text/plain")
                            .body(())
                            .expect("response");
                        if let Ok(mut stream) = respond.send_response(response, false) {
                            let _ = stream.send_data(
                                bytes::Bytes::from(format!(
                                    "bad authority: scheme={scheme:?} authority={authority:?}"
                                )),
                                true,
                            );
                        }
                        return;
                    }
                    let body = body_of(&method, &path, &request_body(&mut request).await);
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/plain")
                        .body(())
                        .expect("response");
                    if let Ok(mut stream) = respond.send_response(response, false) {
                        let _ = stream.send_data(bytes::Bytes::from(body), true);
                    }
                });
            }
        })
    }
}

/// Read a whole h2 request body, releasing flow control, and return it as a lossy string.
async fn request_body(request: &mut http::Request<h2::RecvStream>) -> String {
    let mut collected = Vec::new();
    while let Some(chunk) = request.body_mut().data().await {
        let Ok(chunk) = chunk else { break };
        let _ = request.body_mut().flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    String::from_utf8_lossy(&collected).to_string()
}

#[tokio::test]
async fn an_h2_connection_is_decided_per_stream() {
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, _body| format!("origin:{path}")),
    )
    .await;

    let relay = Relay::new("||www.example.com/ads.js\n", "").trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let tls = session
        .browser_tls("www.example.com", &[b"h2"])
        .await
        .expect("handshake");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "the h2 leg must be negotiated"
    );

    let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 client");
    // The connection future is polled by hand (rather than spawned) because the TLS stream borrows
    // the session; `poll!` inside a yield loop is what a spawned task would otherwise do.
    let mut connection = Box::pin(connection);

    // Three streams: one blocked, two forwarded. They are opened together so the test also proves
    // the decisions do not serialise behind each other.
    let mut responses = Vec::new();
    for path in ["/index.html", "/ads.js", "/style.css"] {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://www.example.com{path}"))
            .header(
                "sec-fetch-dest",
                if path.ends_with(".js") { "script" } else { "document" },
            )
            .body(())
            .expect("request");
        let (response, _) = sender.send_request(request, true).expect("send");
        responses.push((path, response));
    }

    for (path, response) in responses {
        tokio::pin!(response);
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                biased;
                result = &mut connection => {
                    let _ = result;
                    panic!("the connection ended before {path} was answered");
                }
                response = &mut response => response,
            }
        })
        .await
        .expect("response in time")
        .expect("response");
        let status = response.status().as_u16();
        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("body chunk");
            let _ = body.flow_control().release_capacity(chunk.len());
            collected.extend_from_slice(&chunk);
        }
        if path == "/ads.js" {
            assert_eq!(status, 204, "the ad script must be answered locally");
            assert!(collected.is_empty(), "a 204 carries no body");
        } else {
            assert_eq!(status, 200, "{path} must reach the origin");
            assert_eq!(
                String::from_utf8_lossy(&collected),
                format!("origin:{path}"),
                "the forwarded stream must carry the origin's body"
            );
        }
    }

    // Closing the client's sender is what ends the connection: the relay's accept loop returns
    // `None` only once the client's side is gone, so the connection future has to be driven to
    // completion rather than dropped.
    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;

    let snapshot = relay.stats.snapshot();
    assert_eq!(snapshot.h2_streams, 3);
    assert_eq!(snapshot.h2_blocked, 1);
    // MYS-2742: an HTTP/2 block also writes a log entry, so it has to be counted in `httpBlocked`
    // too — that is the counter the home screen's "已拦截" sums, and a log line with no counter behind
    // it is exactly the disagreement this task fixes.
    let http = relay.ctx.http.stats.snapshot();
    assert_eq!(http.requests, 3, "every judged h2 stream is a request");
    assert_eq!(http.blocked, 1, "the blocked h2 stream must reach httpBlocked");
    let logged_blocked = relay
        .log
        .snapshot()
        .into_iter()
        .filter(|entry| entry.outcome == RequestOutcome::Blocked)
        .count();
    assert_eq!(
        logged_blocked as u64, http.blocked,
        "the h2 log's blocked entries must equal httpBlocked"
    );
    let _ = session.finish().await;
}

#[tokio::test]
async fn an_invalid_upstream_certificate_passes_the_client_through() {
    // The origin presents a certificate for a name the client dialled but signed by a root the relay
    // does not trust: the upstream verification fails, and the client must see the real certificate.
    let origin_pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(origin_pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            let _ = stream.read(&mut buffer).await;
            let _ = stream.write_all(b"real-origin").await;
            let _ = stream.flush().await;
        })
    })
    .await;

    // A relay that does *not* trust the origin's root.
    let unrelated = TestPki::new("www.example.com");
    let relay = Relay::new("||www.example.com/ads.js\n", "").trust(&unrelated);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);

    // The client trusts the *origin's* root, not the relay's: its handshake can only succeed if the
    // relay replayed the ClientHello and let the origin answer.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(
            origin_pki.ca.cert_der.clone(),
        ))
        .expect("origin root");
    let config = tls::client_config_with_roots(roots, Vec::new());
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = tls::server_name("www.example.com").expect("name");
    let browser = session.browser.take().expect("browser socket");
    let mut tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(name, browser),
    )
    .await
    .expect("handshake in time")
    .expect("the client must see the origin's real certificate");

    // The peer certificate is the origin's, not a ZShield leaf.
    let peer = tls.get_ref().1.peer_certificates().expect("peer certs");
    assert_eq!(
        peer[0].as_ref(),
        origin_pki
            .loaded
            .leaf_for("www.example.com")
            .expect("origin leaf")
            .chain_der[0]
            .as_slice(),
        "the certificate the client sees must be the origin's own leaf"
    );

    tls.write_all(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
        .await
        .expect("write");
    let mut buffer = [0u8; 64];
    let n = tls.read(&mut buffer).await.expect("read");
    assert_eq!(&buffer[..n], b"real-origin");

    let snapshot = relay.stats.snapshot();
    assert_eq!(snapshot.upstream_invalid, 1);
    assert_eq!(snapshot.intercepted, 0, "nothing was decrypted");
    drop(tls);
    let outcome = session.finish().await;
    assert!(
        matches!(outcome, HttpsOutcome::Passthrough | HttpsOutcome::Failed),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_client_that_rejects_our_leaf_is_auto_bypassed() {
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |_stream| tokio::spawn(async {})).await;
    let relay = Relay::new("||www.example.com/ads.js\n", "").trust(&pki);

    // First connection: the client trusts only the origin's root, so our leaf is rejected with
    // `UnknownCA` and the pair is remembered.
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(pki.ca.cert_der.clone()))
        .expect("origin root");
    let config = tls::client_config_with_roots(roots, Vec::new());
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = tls::server_name("www.example.com").expect("name");
    // This handshake must fail: the client does not trust the relay's root, and the relay's upstream
    // *does* trust the origin (so the relay really is presenting its own leaf).
    let browser = session.browser.take().expect("browser socket");
    let result = connector.connect(name, browser).await;
    assert!(
        result.is_err(),
        "a client that does not trust the relay root must reject the handshake"
    );
    let outcome = session.finish().await;
    assert_eq!(outcome, HttpsOutcome::ClientRejected);
    assert!(
        relay.ctx.bypass.is_bypassed(10001, "www.example.com"),
        "the pair must be auto-bypassed"
    );
    assert_eq!(relay.stats.snapshot().auto_bypassed, 1);

    // Second connection: passed through, so the client's own handshake with the origin succeeds.
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(pki.ca.cert_der.clone()))
        .expect("origin root");
    let config = tls::client_config_with_roots(roots, Vec::new());
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = tls::server_name("www.example.com").expect("name");
    let browser = session.browser.take().expect("browser socket");
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        connector.connect(name, browser),
    )
    .await
    .expect("handshake in time")
    .expect("the bypassed connection must let the client reach the origin");
    drop(tls);
    let _ = session.finish().await;
    assert!(
        relay.stats.snapshot().passthrough >= 1,
        "the second connection must be counted as a passthrough"
    );
}

#[tokio::test]
async fn a_client_offering_no_alpn_is_served_http11() {
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            if let Ok(n) = stream.read(&mut buffer).await {
                let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                let body = format!("alpn-less:{request}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        })
    })
    .await;

    let relay = Relay::new("", "").trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut tls = session
        .browser_tls("www.example.com", &[])
        .await
        .expect("handshake");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        None,
        "no ALPN must stay no ALPN"
    );
    tls.write_all(b"GET /a HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
        .await
        .expect("write");
    let mut response = vec![0u8; 512];
    let n = tls.read(&mut response).await.expect("read");
    assert!(
        String::from_utf8_lossy(&response[..n]).contains("HTTP/1.1 200"),
        "without ALPN the relay must speak HTTP/1.1"
    );
    drop(tls);
    let _ = session.finish().await;
}

#[tokio::test]
async fn the_leaf_is_issued_for_the_sni_it_was_asked_for() {
    let pki = Arc::new(TestPki::new("specific.example"));
    let origin = Origin::start(pki.clone(), |_stream| tokio::spawn(async {})).await;
    let relay = Relay::new("", "").trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "specific.example", 10001);
    let tls = session
        .browser_tls("specific.example", &[])
        .await
        .expect("handshake");
    let peer = tls.get_ref().1.peer_certificates().expect("peer certs").to_vec();
    drop(tls);
    let _ = session.finish().await;

    // The leaf's SAN is the SNI, and it is signed by the relay's root.
    let (_, parsed) = x509_parser::parse_x509_certificate(peer[0].as_ref()).expect("parse leaf");
    let sans = parsed
        .subject_alternative_name()
        .expect("san")
        .expect("present");
    match &sans.value.general_names[0] {
        x509_parser::extensions::GeneralName::DNSName(name) => {
            assert_eq!(*name, "specific.example")
        }
        other => panic!("unexpected SAN {other:?}"),
    }
    assert_eq!(peer.len(), 2, "the relay sends its leaf and its root");
    assert_eq!(peer[1].as_ref(), relay.ca.root_der());
    assert_eq!(relay.ca.cached_leaves(), 1, "the leaf is cached per host");
}

/// Start an origin that echoes the request head it received, so the test can assert on what the
/// **origin** got rather than on what the client believes about its own URL.
///
/// That distinction is the whole point of the `$removeparam` tests here: an in-place rewrite is
/// invisible to the client by design (`response.url` keeps the URL the script asked for; see
/// `docs/DESIGN.md` and `docs/EFFECTIVENESS.md` §13.1), so the origin's own record is the only honest
/// place to check that the parameter was stripped.
async fn echo_origin(pki: Arc<TestPki>) -> Origin {
    Origin::start(pki, |mut stream| {
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            if let Ok(n) = stream.read(&mut buffer).await {
                let request = String::from_utf8_lossy(&buffer[..n]).to_string();
                let body = request.clone();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        })
    })
    .await
}

/// Send one request over the decrypted connection and return what the client read back.
async fn round_trip(relay: &Relay, origin: &Origin, head: &str) -> String {
    let mut session = Session::start(relay, origin.remote(), "www.example.com", 10001);
    let mut tls = session
        .browser_tls("www.example.com", &[])
        .await
        .expect("handshake");
    tls.write_all(head.as_bytes()).await.expect("write");
    let mut response = Vec::new();
    let mut buffer = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buffer))
        .await
        .expect("response in time")
        .expect("read");
    response.extend_from_slice(&buffer[..n]);
    drop(tls);
    let _ = session.finish().await;
    String::from_utf8_lossy(&response).to_string()
}

#[tokio::test]
async fn a_rewritten_subresource_url_reaches_the_origin_in_place() {
    // The acceptance criterion for `$removeparam` on a non-navigation request is "the URL the origin
    // actually received", which is what this asserts. The client's `response.url` is deliberately left
    // alone: redirecting a subresource would change its observable shape for no filtering benefit, and
    // break `fetch(…, {redirect: 'error' | 'manual'})` (`docs/DESIGN.md`).
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = echo_origin(pki.clone()).await;
    let relay = Relay::new("||www.example.com/api$removeparam=utm_source,all\n", "").trust(&pki);

    let text = round_trip(
        &relay,
        &origin,
        "GET /api?utm_source=x&keep=1 HTTP/1.1\r\nHost: www.example.com\r\nSec-Fetch-Dest: empty\r\n\r\n",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 200 OK\r\n"),
        "a subresource is forwarded, not redirected: {text:?}"
    );
    assert!(
        text.contains("GET /api?keep=1 HTTP/1.1"),
        "the origin must receive the rewritten target: {text:?}"
    );
    assert!(
        !text.contains("utm_source"),
        "the removed parameter must not reach the origin: {text:?}"
    );
}

#[tokio::test]
async fn a_rewritten_subresource_post_keeps_its_method_and_body() {
    // A `$removeparam` rule applies to `POST` too (AdGuard's own page has a POST case), so the rewrite
    // must not turn it into a `GET` or drop the body — which is exactly what a redirect would risk.
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = echo_origin(pki.clone()).await;
    let relay = Relay::new("||www.example.com/api$removeparam=utm_source,all\n", "").trust(&pki);

    let text = round_trip(
        &relay,
        &origin,
        "POST /api?utm_source=x&keep=1 HTTP/1.1\r\nHost: www.example.com\r\n         Sec-Fetch-Dest: empty\r\nContent-Length: 7\r\n\r\nfield=1",
    )
    .await;
    assert!(
        text.contains("POST /api?keep=1 HTTP/1.1"),
        "the method and the rewritten target must both survive: {text:?}"
    );
    assert!(
        text.contains("Content-Length: 7"),
        "the body length must be untouched: {text:?}"
    );
    assert!(
        text.contains("field=1"),
        "the body itself must be forwarded: {text:?}"
    );
    assert!(!text.contains("utm_source"), "{text:?}");
}

#[tokio::test]
async fn a_rewritten_document_navigation_is_still_answered_with_a_redirect() {
    // The one case that does redirect, and the reason: the URL is in the address bar and in the page's
    // own relative links, so a silent rewrite would leave the browser believing it is somewhere else.
    // `docs/DESIGN.md` fixes this and the review kept it.
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = echo_origin(pki.clone()).await;
    let relay = Relay::new("||www.example.com/page$removeparam=utm_source,all\n", "").trust(&pki);

    let text = round_trip(
        &relay,
        &origin,
        "GET /page?utm_source=x&keep=1 HTTP/1.1\r\nHost: www.example.com\r\n\
         Sec-Fetch-Dest: document\r\n\r\n",
    )
    .await;
    assert!(
        text.starts_with("HTTP/1.1 302 Found\r\n"),
        "a navigation must still be redirected: {text:?}"
    );
    assert!(
        text.contains("Location: https://www.example.com/page?keep=1\r\n"),
        "the Location is the rewritten URL: {text:?}"
    );
    assert!(!text.contains("utm_source"), "{text:?}");
}

#[tokio::test]
async fn a_csp_and_removed_response_header_reach_the_client() {
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            if let Ok(n) = stream.read(&mut buffer).await {
                let _ = n;
                let body = "page";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Test: drop-me\r\n\
                     Content-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        })
    })
    .await;

    let relay = Relay::new(
        "||www.example.com^$csp=script-src 'none'\n",
        "||www.example.com^$removeheader=x-test\n",
    )
    .trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut tls = session
        .browser_tls("www.example.com", &[])
        .await
        .expect("handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: www.example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
        .await
        .expect("write");
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    for _ in 0..8 {
        let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buffer))
            .await
            .expect("response in time")
            .expect("read");
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..n]);
        // M3b: a document the cosmetic engine has rules for is chunked, so the body ends with the
        // terminal chunk rather than at the origin's `Content-Length`.
        if response.windows(5).any(|window| window == b"\r\n0\r\n") {
            break;
        }
        if response.ends_with(b"page") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.contains("Content-Security-Policy: script-src 'none'"),
        "the `$csp` directive must be added: {text:?}"
    );
    assert!(
        !text.to_ascii_lowercase().contains("x-test:"),
        "the `$removeheader` header must be gone: {text:?}"
    );
    drop(tls);
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_redirect_substitute_is_served_on_the_decrypted_connection() {
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |_stream| tokio::spawn(async {})).await;
    let relay = Relay::new(
        "||www.example.com/banner.js$script,redirect=noopjs\n",
        "",
    )
    .trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut tls = session
        .browser_tls("www.example.com", &[])
        .await
        .expect("handshake");
    tls.write_all(
        b"GET /banner.js HTTP/1.1\r\nHost: www.example.com\r\nSec-Fetch-Dest: script\r\n\r\n",
    )
    .await
    .expect("write");
    let mut response = Vec::new();
    let mut buffer = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buffer))
        .await
        .expect("response in time")
        .expect("read");
    response.extend_from_slice(&buffer[..n]);
    let text = String::from_utf8_lossy(&response).to_string();
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "a `$redirect` substitute is a 200 with a body, got {text:?}"
    );
    assert!(
        text.contains("application/javascript"),
        "the substitute's MIME type must be served: {text:?}"
    );
    drop(tls);
    let _ = session.finish().await;
    assert_eq!(relay.stats.snapshot().intercepted, 1);
}

#[tokio::test]
async fn an_origin_that_does_not_speak_h2_is_served_to_the_client_as_http11() {
    // The client offers h2 first (every browser does), the origin only speaks HTTP/1.1. Offering the
    // client `[h2, http/1.1]` and then refusing to splice made the connection fail, which is every
    // HTTPS site without h2 — so instead the client is only offered what the origin settled on and
    // independently lands on `http/1.1`, and the request succeeds.
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 1024];
            if let Ok(n) = stream.read(&mut buffer).await {
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nh11-or";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = n;
            }
            // `Connection: close` semantics: the origin ends the TLS session itself, which is what
            // the relay must report as a clean end rather than an unexpected EOF.
            let _ = stream.shutdown().await;
        })
    })
    .await;

    let relay = Relay::new("", "").trust(&pki);
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    // The client asks for h2 first, exactly like Chrome.
    let mut tls = session
        .browser_tls("www.example.com", &[b"h2", b"http/1.1"])
        .await
        .expect("the handshake must succeed for an HTTP/1.1-only origin");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice()),
        "the client must be steered onto the origin's protocol, not offered h2"
    );
    tls.write_all(b"GET /x HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
        .await
        .expect("write");
    let mut response = vec![0u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut response))
        .await
        .expect("response in time")
        .expect("read");
    assert!(
        String::from_utf8_lossy(&response[..n]).contains("h11-or"),
        "the request must reach the origin and come back"
    );
    // A real browser closes with `close_notify`; the relay reports that as a clean end. Dropping the
    // stream instead would be an unexpected EOF, which is a `Failed` outcome — the assertion below is
    // about the connection being correct, so the client closes properly.
    let _ = tls.shutdown().await;
    drop(tls);
    let outcome = session.finish().await;
    assert_eq!(outcome, HttpsOutcome::Clean);
}

#[tokio::test]
async fn an_unsupported_modifier_is_reported_rather_than_ignored() {
    // The delivery note has to name what is not implemented. `$removeheader` *is* implemented (by
    // `https::modifiers`); what the engine rejects is anything it does not know at all.
    let rules = modifiers::collect_removeheader(["||a.example^$removeheader=refresh\n"]);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules.header_names(), vec!["refresh"]);

    // A rule the engine cannot parse at all stays in the engine's own "unsupported" bucket; this
    // module only claims the `$removeheader` subset, and says so.
    let mut set = adblock::lists::FilterSet::new(false);
    set.add_filter_list(
        "||a.example^$removeheader=refresh\n".to_string(),
        adblock::lists::ParseOptions::default(),
    );
    let engine = adblock::Engine::new_with_filter_set(set);
    let request = adblock::request::Request::preparsed(
        "https://a.example/x",
        "a.example",
        "site.example",
        "document",
        true,
        "get",
    );
    assert!(
        engine.check_network_request(&request).filter.is_none(),
        "the engine alone does not match `$removeheader`, which is why this module exists"
    );
}

#[test]
fn the_alpn_of_a_hello_decides_the_relay() {
    // A cheap check of the handshake's ALPN contract, without a socket.
    let h2_hello = client_hello("a.example", &[b"h2", b"http/1.1"]);
    assert_eq!(
        tls::client_alpn(&h2_hello),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(
        tls::upstream_alpn(&tls::client_alpn(&h2_hello)),
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    );
    assert_eq!(
        Alpn::from_negotiated(Some(b"h2")),
        Alpn::H2,
        "the relay must pick the h2 path for an h2 client"
    );
    let plain_hello = client_hello("a.example", &[]);
    assert!(tls::client_alpn(&plain_hello).is_empty());
    assert_eq!(
        tls::upstream_alpn(&tls::client_alpn(&plain_hello)),
        vec![b"http/1.1".to_vec()],
        "no ALPN means HTTP/1.1 on both legs"
    );
}

/// Open an h2 client on the relay's leaf and return the connection pieces.
async fn h2_client(
    session: &mut Session,
    host: &str,
) -> (
    h2::client::SendRequest<bytes::Bytes>,
    h2::client::Connection<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>, bytes::Bytes>,
) {
    let tls = session
        .browser_tls(host, &[b"h2"])
        .await
        .expect("h2 handshake with the relay");
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "the h2 leg must be negotiated"
    );
    h2::client::handshake(tls).await.expect("h2 client")
}

#[tokio::test]
async fn a_blocked_h2_document_delivers_its_whole_body() {
    // The synthesized block page has a body. `send_response(.., true)` closed the stream before it,
    // so the client got `content-length: N` and no bytes: a blank page in the browser. The stream
    // must stay open until the body has been sent.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, _body| format!("origin:{path}")),
    )
    .await;
    let relay = Relay::new("||www.example.com^", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/index.html"))
        .header("sec-fetch-dest", "document")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => panic!("the connection ended before the page: {result:?}"),
            response = response => response.expect("response"),
        }
    })
    .await
    .expect("response in time");

    assert_eq!(response.status().as_u16(), 403, "a document block is a 403 page");
    let declared = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .expect("the block page declares a length");
    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(
        collected.len(),
        declared,
        "the whole block page must arrive, not just its headers"
    );
    assert!(
        String::from_utf8_lossy(&collected).contains("ZShield"),
        "the body must be the block page"
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_blocked_h2_redirect_resource_delivers_its_body() {
    // Same failure mode as the block page, for a `$redirect` substitute that actually carries bytes:
    // a `content-length` the client never receives is a broken resource, not a blocked ad. `noopjs`
    // is deliberately an empty document (uBO's behaviour), so the 1x1 GIF is used here — its body is
    // what proves the synthesized response opened the stream with END_STREAM off.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, _body| format!("origin:{path}")),
    )
    .await;
    let relay = Relay::new("||www.example.com/pixel.gif$image,redirect=1x1.gif", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/pixel.gif"))
        .header("sec-fetch-dest", "image")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => panic!("the connection ended before the substitute: {result:?}"),
            response = response => response.expect("response"),
        }
    })
    .await
    .expect("response in time");

    assert_eq!(response.status().as_u16(), 200);
    let declared = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .expect("the substitute declares a length");
    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(
        collected.len(),
        declared,
        "the whole substitute must arrive, not just its headers"
    );
    assert!(
        collected.starts_with(b"GIF89a") || collected.starts_with(b"\x89PNG"),
        "the body must be the substituted image"
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_blocked_h2_post_with_a_large_body_does_not_stall_the_connection() {
    // The blocked upload's DATA frames still occupy the connection's receive window. If the relay
    // stops reading without releasing it, the client keeps sending until the window is gone and the
    // whole connection — every other stream on it — stops. A 100 KiB POST followed by a normal
    // request on the same connection is what proves the window is released.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, body| {
            format!("origin:{path}:{}", body.len())
        }),
    )
    .await;
    let relay = Relay::new("||www.example.com/upload", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    // The connection has to be driven for flow-control capacity to be granted, and the test also
    // awaits capacity — so it gets its own task rather than being polled by hand. Its end is an
    // error here: a stall is exactly what this test is looking for.
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });

    // 1. A blocked POST with 100 KiB of body.
    let upload = bytes::Bytes::from(vec![b'x'; 100 * 1024]);
    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{H2_AUTHORITY}/upload"))
        .header("sec-fetch-dest", "empty")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (response, mut upload_body) = sender.send_request(request, false).expect("send");
    // Send in chunks so the flow-control window is genuinely exercised rather than one giant frame.
    let mut remaining = upload.clone();
    while !remaining.is_empty() {
        let take = remaining.len().min(16 * 1024);
        let mut chunk = remaining.split_to(take);
        upload_body.reserve_capacity(chunk.len());
        let capacity = std::future::poll_fn(|cx| upload_body.poll_capacity(cx))
            .await
            .expect("capacity")
            .expect("window");
        let _ = capacity;
        let end = remaining.is_empty();
        upload_body
            .send_data(std::mem::take(&mut chunk), end)
            .expect("send body chunk");
    }
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("the blocked upload must be answered")
        .expect("response");
    assert!(
        response.status().as_u16() == 204 || response.status().as_u16() == 403,
        "the upload must be blocked locally, got {}",
        response.status()
    );

    // 2. A normal request on the *same* connection must still work.
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/after.html"))
        .header("sec-fetch-dest", "document")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (after, _) = sender.send_request(request, true).expect("send");
    let after = tokio::time::timeout(Duration::from_secs(10), after)
        .await
        .expect("the connection must still carry requests after a blocked upload")
        .expect("response");
    assert_eq!(after.status().as_u16(), 200);
    let mut body = after.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(String::from_utf8_lossy(&collected), "origin:/after.html:0");

    // Every stream handle has to go before the client connection can close: the blocked upload's
    // body was never read, and holding it keeps the client's h2 connection alive. The relay task ends
    // when the client's connection does, so this ordering is what lets `finish` return.
    drop(body);
    drop(upload_body);
    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    // The relay's outcome is not the subject here; the two responses above are.
    let _ = session.outcome.take();
}

#[tokio::test]
async fn an_h2_request_carries_the_authority_and_scheme_the_origin_needs() {
    // A path-only upstream URI reaches a real origin with no `:authority` and comes back `400`. The
    // test origin answers 400 for exactly that, so a regression here is a failed assertion and not a
    // silently broken page.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, _body| format!("ok:{path}")),
    )
    .await;
    let relay = Relay::new("", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/plain.html"))
        .header("sec-fetch-dest", "document")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => panic!("the connection ended: {result:?}"),
            response = response => response.expect("response"),
        }
    })
    .await
    .expect("response in time");

    let status = response.status().as_u16();
    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(
        status,
        200,
        "the origin must see :scheme and :authority: {}",
        String::from_utf8_lossy(&collected)
    );
    assert_eq!(String::from_utf8_lossy(&collected), "ok:/plain.html");

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_removeparam_rewrite_keeps_the_authority_on_h2() {
    // A non-navigation rewrite is forwarded **in place** on h2 too, and the rewritten URL must stay
    // absolute in the `:path` it sends: replacing it with a bare path would drop `:authority` and turn a
    // `$removeparam` match into a `400` from the origin. Both protocols have to agree, so this asserts
    // the same thing `a_rewritten_subresource_url_reaches_the_origin_in_place` does on HTTP/1.1: what
    // the origin saw, not what the client believes about its own URL.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, _body| format!("seen:{path}")),
    )
    .await;
    let relay = Relay::new("||www.example.com/api$removeparam=utm_source,all", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/api?utm_source=x&keep=1"))
        .header("sec-fetch-dest", "empty")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => panic!("the connection ended: {result:?}"),
            response = response => response.expect("response"),
        }
    })
    .await
    .expect("response in time");
    assert_eq!(
        response.status().as_u16(),
        200,
        "a rewritten subresource is forwarded, not redirected"
    );
    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(
        String::from_utf8_lossy(&collected),
        "seen:/api?keep=1",
        "the origin must receive the rewritten path and the authority must be preserved"
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_removeparam_rewrite_on_h2_post_keeps_the_method_and_body() {
    // The H2 counterpart of `a_rewritten_subresource_post_keeps_its_method_and_body`. The h2 path
    // rewrites `:path` per stream, and the body arrives as DATA frames the relay forwards; a rewrite
    // that reset the stream, or that rebuilt the request without `:method`, would arrive at the
    // origin as a `GET` with no body and still answer 200 — so the assertion has to be on what the
    // origin received, not on the status.
    //
    // AdGuard's own `removeparam` page has a POST case (`case 13`), which is why this is a required
    // regression and not a hypothetical.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    // Report the **method**, the path and the body the origin was handed. The method matters here:
    // without it this test cannot tell a correct rewrite from one that rebuilt the request as a GET,
    // because both answer 200 — only the verb at the origin differs.
    let origin = Origin::start(
        pki.clone(),
        h2_origin_with_method(|method, path, body| format!("seen:{method} {path}|{body}")),
    )
    .await;
    let relay = Relay::new("||www.example.com/api$removeparam=utm_source,all", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    let request = http::Request::builder()
        .method("POST")
        .uri(format!("https://{H2_AUTHORITY}/api?utm_source=x&keep=1"))
        .header("sec-fetch-dest", "empty")
        .header("content-type", "application/x-www-form-urlencoded")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (response, mut send_stream) = sender.send_request(request, false).expect("send");
    send_stream
        .send_data(bytes::Bytes::from_static(b"field=1&other=2"), true)
        .expect("body");

    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => panic!("the connection ended: {result:?}"),
            response = response => response.expect("response"),
        }
    })
    .await
    .expect("response in time");
    assert_eq!(
        response.status().as_u16(),
        200,
        "a rewritten POST subresource is forwarded, not redirected"
    );

    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(
        String::from_utf8_lossy(&collected),
        "seen:POST /api?keep=1|field=1&other=2",
        "the origin must get the verb, the rewritten path and the whole body; a request rebuilt as a \
         GET, a lost body or a dropped parameter all show up here"
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_removeparam_rewrite_on_h2_leaves_a_concurrent_stream_alone() {
    // Two streams on one h2 connection, one rewritten and one not. The relay decides and rewrites
    // per stream; a shared mutable "current request" would leak the first stream's rewrite into the
    // second, which is the concurrency bug a single-stream test cannot see — and the tunnel serves
    // both streams of a page at once, so it would corrupt real traffic.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(
        pki.clone(),
        h2_origin(|path, body| format!("seen:{path}|{body}")),
    )
    .await;
    let relay = Relay::new("||www.example.com/api$removeparam=utm_source,all", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    // The tracked stream: `/api` with the parameter the rule names.
    let tracked = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/api?utm_source=x&keep=1"))
        .header("sec-fetch-dest", "empty")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (tracked_response, _) = sender.send_request(tracked, true).expect("send tracked");

    // The untouched stream: a *different* path carrying the same parameter name, which the rule does
    // not name. It must reach the origin with `utm_source` intact.
    let untouched = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/other?utm_source=x&keep=1"))
        .header("sec-fetch-dest", "empty")
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (untouched_response, _) = sender.send_request(untouched, true).expect("send untouched");

    async fn collect<S>(
        response: impl std::future::Future<Output = Result<http::Response<h2::RecvStream>, h2::Error>>,
        connection: &mut std::pin::Pin<Box<S>>,
    ) -> String
    where
        S: std::future::Future<Output = Result<(), h2::Error>> + Unpin,
    {
        let response = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                biased;
                result = connection.as_mut() => panic!("the connection ended: {result:?}"),
                response = response => response.expect("response"),
            }
        })
        .await
        .expect("response in time");
        assert_eq!(response.status().as_u16(), 200);
        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("body chunk");
            let _ = body.flow_control().release_capacity(chunk.len());
            collected.extend_from_slice(&chunk);
        }
        String::from_utf8_lossy(&collected).to_string()
    }

    let tracked_body = collect(tracked_response, &mut connection).await;
    let untouched_body = collect(untouched_response, &mut connection).await;
    assert_eq!(
        tracked_body, "seen:/api?keep=1|",
        "the ruled path loses the parameter"
    );
    assert_eq!(
        untouched_body, "seen:/other?utm_source=x&keep=1|",
        "an unruled path on the same connection keeps its parameter — a shared rewrite state would \
         strip it here"
    );

    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn an_h2_origin_that_goes_away_is_reported_to_the_client() {
    // An origin closes an idle h2 connection, or ends one at its request limit. Without a GOAWAY the
    // client only finds out one cancelled stream at a time, and Chrome does not retry a stream it saw
    // cancelled — the page just breaks. The client must instead see the connection end in a way it
    // can reconnect from.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    // Lets the test release the origin once the client has the first response, so the two events are
    // ordered instead of racing.
    let closed = Arc::new(tokio::sync::Notify::new());
    let released = closed.clone();
    let origin = Origin::start(pki.clone(), move |stream| {
        let closed = released.clone();
        tokio::spawn(async move {
            let mut connection = match h2::server::handshake(stream).await {
                Ok(connection) => connection,
                Err(_) => return,
            };
            // The accept loop keeps the connection future driven, which is what actually writes the
            // response frames; the release signal ends it, which is the origin going away.
            loop {
                tokio::select! {
                    _ = closed.notified() => return,
                    accepted = connection.accept() => {
                        let Some(Ok((_request, mut respond))) = accepted else { return };
                        let response = http::Response::builder()
                            .status(200)
                            .body(())
                            .expect("response");
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(bytes::Bytes::from_static(b"first"), true);
                        }
                    }
                }
            }
        })
    })
    .await;
    let relay = Relay::new("", "").trust(&pki);

    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let mut connection = Box::pin(connection);

    // The first request is answered, which is what makes the origin end the connection afterwards.
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/first"))
        .version(http::Version::HTTP_2)
        .body(())
        .expect("request");
    let (first, _) = sender.send_request(request, true).expect("send");
    let first = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => panic!("the connection ended before the first answer: {result:?}"),
            response = first => response.expect("response"),
        }
    })
    .await
    .expect("first response in time");
    let mut body = first.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    assert_eq!(String::from_utf8_lossy(&collected), "first");
    // The client has the body; the origin may now end its connection.
    closed.notify_one();

    // The origin is gone. The relay must tell the client with a GOAWAY rather than leaving it to
    // discover the loss one cancelled stream at a time — Chrome does not retry a cancelled stream, so
    // that shows up as a broken page. What the client observes is that its connection future
    // completes and the next request is refused locally instead of hanging or silently vanishing.
    // The relay sent the client a GOAWAY (the log line above proves the decision was taken). What the
    // client observes is that the connection is *finished*: `ready()` fails or the connection future
    // resolves. A silent cancel of later streams — which Chrome does not retry — is the failure this
    // guards against, and it looks like neither of those happening.
    let ended = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let next = sender.clone();
            tokio::select! {
                biased;
                // The GOAWAY can only be read while the connection future is being polled.
                _ = &mut connection => return true,
                ready = next.ready() => {
                    match ready {
                        // The connection is gone: h2 refuses new streams.
                        Err(_) => return true,
                        Ok(mut ready) => {
                            let request = http::Request::builder()
                                .method("GET")
                                .uri(format!("https://{H2_AUTHORITY}/later"))
                                .version(http::Version::HTTP_2)
                                .body(())
                                .expect("request");
                            if ready.send_request(request, true).is_err() {
                                return true;
                            }
                        }
                    }
                }
            }
            // Give the connection a moment to process the GOAWAY frame before trying again.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await.unwrap_or(false);
    assert!(
        ended,
        "after the origin went away the client must see the connection finish, not be left hanging"
    );
    drop(sender);
    let _ = tokio::time::timeout(Duration::from_secs(5), &mut connection).await;
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_socket_opened_before_the_sniff_is_reused_instead_of_redialled() {
    // The tunnel dials the origin before it sniffs, so that a connection it does not decrypt is not
    // delayed by a second handshake. When it does decrypt, that socket carries nothing yet — the
    // ClientHello was held back — so the MITM layer must finish its TLS on it rather than dial again.
    // One origin connection for the whole relay proves the socket was reused.
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 1024];
            if let Ok(n) = stream.read(&mut buffer).await {
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npage";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = n;
            }
            let _ = stream.shutdown().await;
        })
    })
    .await;

    let relay = Relay::new("", "").trust(&pki);
    // The tunnel's pre-sniff dial.
    let warm = TcpStream::connect(origin.remote())
        .await
        .expect("pre-sniff outbound connect");
    let mut session = Session::start_reusing(&relay, origin.remote(), "www.example.com", 10001, warm);
    let mut tls = session
        .browser_tls("www.example.com", &[])
        .await
        .expect("handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n")
        .await
        .expect("write");
    let mut response = vec![0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut response))
        .await
        .expect("response in time")
        .expect("read");
    assert!(
        String::from_utf8_lossy(&response[..n]).contains("page"),
        "the reused socket must carry the request"
    );
    let _ = tls.shutdown().await;
    drop(tls);
    let _ = session.finish().await;

    assert_eq!(
        origin.connections(),
        1,
        "the pre-sniff socket must be reused, not replaced by a second dial"
    );
}

// ---------------------------------------------------------------------------------------------
// M3b: cosmetic injection on a decrypted connection
// ---------------------------------------------------------------------------------------------

/// The `Accept-Encoding` the last [`h2_html_origin`] request carried, for the narrowing test.
///
/// One static because the origin's handler is a plain closure; the two tests that read it therefore
/// take [`H2_ENCODING_LOCK`] so they cannot observe each other's request.
static H2_SEEN_ACCEPT_ENCODING: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Serialises the two tests that assert on [`H2_SEEN_ACCEPT_ENCODING`].
///
/// A `tokio::sync::Mutex` and not a `std` one: the guard has to live across the awaits of a whole test,
/// which a `std` guard may not.
static H2_ENCODING_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// An h2 origin that answers every stream with an HTML document, so injection has something to do.
fn h2_html_origin(
    content_type: &'static str,
) -> impl Fn(tokio_rustls::server::TlsStream<TcpStream>) -> tokio::task::JoinHandle<()>
       + Send
       + Sync
       + 'static {
    move |stream| {
        tokio::spawn(async move {
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            while let Some(accepted) = connection.accept().await {
                let Ok((request, mut respond)) = accepted else {
                    return;
                };
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                *H2_SEEN_ACCEPT_ENCODING.lock().unwrap_or_else(|e| e.into_inner()) = request
                    .headers()
                    .get(http::header::ACCEPT_ENCODING)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                tokio::spawn(async move {
                    let body = format!(
                        "<!doctype html><html><head><title>{path}</title></head>\
                         <body><div class=\"ad-slot\">ad</div><p>content</p></body></html>"
                    );
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", content_type)
                        .header("content-length", body.len())
                        .body(())
                        .expect("response");
                    if let Ok(mut stream) = respond.send_response(response, false) {
                        let _ = stream.send_data(bytes::Bytes::from(body), true);
                    }
                });
            }
        })
    }
}

/// Drive one h2 request on a fresh client connection and return `(status, headers, body)`.
async fn h2_get(
    relay: &Relay,
    pki: &Arc<TestPki>,
    origin: &Origin,
    path: &str,
) -> (u16, http::HeaderMap, String) {
    let _ = pki;
    let mut session = Session::start(relay, origin.remote(), H2_AUTHORITY, 10001);
    let tls = session
        .browser_tls(H2_AUTHORITY, &[b"h2"])
        .await
        .expect("handshake");
    let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 client");
    let connection = Box::pin(connection);
    tokio::pin!(connection);
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}{path}"))
        .header("sec-fetch-dest", "document")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    tokio::pin!(response);
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => {
                let _ = result;
                panic!("the connection ended before the response");
            }
            response = &mut response => response,
        }
    })
    .await
    .expect("response in time")
    .expect("response");
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        collected.extend_from_slice(&chunk);
    }
    (status, headers, String::from_utf8_lossy(&collected).to_string())
}

#[tokio::test]
async fn an_h2_document_is_injected_without_a_content_length() {
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_html_origin("text/html; charset=utf-8")).await;
    let relay = Relay::new("www.example.com##.ad-slot\n", "").trust(&pki);

    let (status, headers, body) = h2_get(&relay, &pki, &origin, "/page.html").await;
    assert_eq!(status, 200);
    assert!(
        headers.get("content-length").is_none(),
        "a rewritten body has no length to declare: {headers:?}"
    );
    assert!(
        body.contains("<style data-zshield=\"specific\">"),
        "the hide rule must be injected: {body}"
    );
    assert!(body.contains(".ad-slot"), "{body}");
    assert!(
        body.contains("<div class=\"ad-slot\">ad</div>"),
        "the page's own bytes must survive: {body}"
    );
    assert!(body.ends_with("</body></html>"), "{body}");
}

#[tokio::test]
async fn an_h2_document_no_rule_matches_keeps_its_bytes() {
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_html_origin("text/html; charset=utf-8")).await;
    // A rule for a different hostname, and no generic rule that this page's classes hit: nothing is
    // inserted. The body is still rewritten (the generic query can only run once `</body>` is in
    // sight, so the length cannot be declared up front), but not one byte of the document changes.
    let relay = Relay::new("other.example##.ad-slot\n##.never-present\n", "").trust(&pki);
    let (status, _headers, body) = h2_get(&relay, &pki, &origin, "/page.html").await;
    assert_eq!(status, 200);
    assert!(!body.contains("<style"), "nothing may be inserted: {body}");
    assert_eq!(
        body,
        "<!doctype html><html><head><title>/page.html</title></head>\
         <body><div class=\"ad-slot\">ad</div><p>content</p></body></html>",
        "the document's own bytes must be unchanged"
    );
}

#[tokio::test]
async fn an_h2_document_request_offers_only_the_codings_the_core_decodes() {
    let _guard = H2_ENCODING_LOCK.lock().await;
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_html_origin("text/html; charset=utf-8")).await;
    let relay = Relay::new("www.example.com##.ad-slot\n", "").trust(&pki);
    *H2_SEEN_ACCEPT_ENCODING.lock().unwrap_or_else(|e| e.into_inner()) = None;
    let _ = h2_get(&relay, &pki, &origin, "/page.html").await;
    let seen = H2_SEEN_ACCEPT_ENCODING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen.as_deref(),
        Some(crate::http::rewrite::DOCUMENT_ACCEPT_ENCODING),
        "a document whose response will be rewritten must offer only decodable codings"
    );
}

#[tokio::test]
async fn an_h2_subresource_keeps_the_clients_accept_encoding() {
    let _guard = H2_ENCODING_LOCK.lock().await;
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_html_origin("application/javascript")).await;
    let relay = Relay::new("www.example.com##.ad-slot\n", "").trust(&pki);
    *H2_SEEN_ACCEPT_ENCODING.lock().unwrap_or_else(|e| e.into_inner()) = None;
    // A script request: no injection, so the client's own header must survive untouched.
    let mut session = Session::start(&relay, origin.remote(), H2_AUTHORITY, 10001);
    let tls = session
        .browser_tls(H2_AUTHORITY, &[b"h2"])
        .await
        .expect("handshake");
    let (mut sender, connection) = h2::client::handshake(tls).await.expect("h2 client");
    let connection = Box::pin(connection);
    tokio::pin!(connection);
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/a.js"))
        .header("sec-fetch-dest", "script")
        .header("accept-encoding", "br, zstd")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    tokio::pin!(response);
    let _ = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            biased;
            result = &mut connection => { let _ = result; }
            response = &mut response => { let _ = response; }
        }
    })
    .await;
    let seen = H2_SEEN_ACCEPT_ENCODING
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    assert_eq!(
        seen.as_deref(),
        Some("br, zstd"),
        "a subresource keeps the client's Accept-Encoding"
    );
}

#[tokio::test]
async fn an_h2_document_gets_a_generic_rule_for_a_class_it_carries() {
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_html_origin("text/html; charset=utf-8")).await;
    // A generic rule (no hostname): it applies because the page has an `.ad-slot` element, and the
    // engine is asked about the class/id values the document actually contains.
    let relay = Relay::new("##.ad-slot\n", "").trust(&pki);
    let (status, _headers, body) = h2_get(&relay, &pki, &origin, "/page.html").await;
    assert_eq!(status, 200);
    let generic_at = body
        .find("data-zshield=\"generic\"")
        .unwrap_or_else(|| panic!("the generic rule must be injected: {body}"));
    // The generic `<style>` is appended at the end of the document: `</body` also occurs inside inline
    // scripts, and inserting there would splice markup into a JavaScript string (review item 7).
    let close = body.find("</body>").expect("the body's end");
    assert!(
        generic_at > close,
        "the generic style is appended after the document body: {body}"
    );
    assert!(body[generic_at..].contains(".ad-slot"), "{body}");
}

#[tokio::test]
async fn an_h2_non_html_response_is_not_injected() {
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_html_origin("application/json")).await;
    // The rule matches the hostname, so a cosmetic plan exists — but the response is not HTML.
    let relay = Relay::new("www.example.com##.ad-slot\n", "").trust(&pki);
    let (status, headers, body) = h2_get(&relay, &pki, &origin, "/api").await;
    assert_eq!(status, 200);
    assert!(
        headers.get("content-length").is_some(),
        "a non-document keeps its framing: {headers:?}"
    );
    assert!(!body.contains("<style"), "{body}");
}

// ---------------------------------------------------------------------------------------------
// Rework regressions (review items 2, 11)
// ---------------------------------------------------------------------------------------------

/// An h2 origin that answers every stream with an HTML document and records the `Accept-Encoding`.
fn h2_csp_origin(
    csp: &'static str,
) -> impl Fn(tokio_rustls::server::TlsStream<TcpStream>) -> tokio::task::JoinHandle<()>
       + Send
       + Sync
       + 'static {
    move |stream| {
        tokio::spawn(async move {
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            while let Some(accepted) = connection.accept().await {
                let Ok((_request, mut respond)) = accepted else {
                    return;
                };
                tokio::spawn(async move {
                    let body = "<!doctype html><html><head></head><body>\
                                <div class=\"ad-slot\">ad</div></body></html>";
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/html; charset=utf-8")
                        .header("content-security-policy", csp)
                        .body(())
                        .expect("response");
                    if let Ok(mut stream) = respond.send_response(response, false) {
                        let _ = stream.send_data(bytes::Bytes::from(body), true);
                    }
                });
            }
        })
    }
}

#[tokio::test]
async fn an_h2_csp_directive_from_a_rule_is_added_exactly_once() {
    // Review item 11: the `$csp` directive used to be appended by the header builder *and* again by the
    // injector, so the client saw it twice.
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    let origin = Origin::start(pki.clone(), h2_csp_origin("default-src 'self'")).await;
    let relay = Relay::new(
        "www.example.com##.ad-slot\n||www.example.com^$csp=script-src 'none'\n",
        "",
    )
    .trust(&pki);
    let (status, headers, body) = h2_get(&relay, &pki, &origin, "/page.html").await;
    assert_eq!(status, 200);
    let values: Vec<&str> = headers
        .get_all("content-security-policy")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let matching: Vec<&&str> = values
        .iter()
        .filter(|value| value.contains("script-src 'none'"))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "the `$csp` directive must appear exactly once: {values:?}"
    );
    assert!(
        values.iter().any(|value| value.contains("default-src 'self'")),
        "the site's own policy must survive: {values:?}"
    );
    assert!(body.contains("<style"), "the hide rule is still injected: {body}");
}

// ---------------------------------------------------------------------------------------------
// M3b rework round 2: a large document through a *slow* client
// ---------------------------------------------------------------------------------------------

/// Start a session whose browser↔relay pipe holds only `pipe` bytes.
///
/// A real phone reads a decrypted document at whatever pace its renderer manages, so the relay's
/// writes block. A 1 MiB in-memory pipe never blocks and therefore cannot reproduce that.
fn start_with_pipe(
    relay: &Relay,
    remote: std::net::SocketAddr,
    host: &str,
    uid: u32,
    pipe: usize,
) -> Session {
    let (mut relay_side, browser) = tokio::io::duplex(pipe);
    let ctx = relay.ctx.clone();
    let host = host.to_string();
    let outcome = tokio::spawn(async move {
        let mut head = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match crate::tun::inspect::client_hello_info(&head) {
                Some(info) => {
                    head.truncate(info.hello_len);
                    break;
                }
                None => {
                    if head.len() > 16 * 1024 {
                        break;
                    }
                }
            }
            match relay_side.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => head.extend_from_slice(&buffer[..n]),
                Err(_) => break,
            }
        }
        mitm::run(relay_side, head, remote, &host, uid, &ctx, None).await
    });
    Session {
        browser: Some(browser),
        outcome: Some(outcome),
        relay_ca_pem: relay.ca_pem(),
    }
}

/// A gzip document of `size` bytes: `(plain, gzip compressed, chunk-framed)`.
fn large_gzip_document(size: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut plain = b"<!doctype html><html><head><title>t</title></head><body>".to_vec();
    while plain.len() < size {
        plain.extend_from_slice(b"<div class=\"row\">payload payload payload</div>\n");
    }
    plain.extend_from_slice(b"</body></html>");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &plain).expect("compress");
    let compressed = encoder.finish().expect("finish");
    let mut framed = Vec::new();
    let mut offset = 0usize;
    let mut size = 1000usize;
    while offset < compressed.len() {
        let end = (offset + size).min(compressed.len());
        let piece = &compressed[offset..end];
        framed.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        framed.extend_from_slice(piece);
        framed.extend_from_slice(b"\r\n");
        offset = end;
        size = 700 + (size * 7 % 5000);
    }
    framed.extend_from_slice(b"0\r\n\r\n");
    (plain, compressed, framed)
}

/// Remove the HTTP/1.1 chunk framing from a rewritten body, panicking on broken framing.
fn strip_chunk_framing(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = body.windows(2).position(|window| window == b"\r\n") else {
            panic!("no chunk size line in {:?}", String::from_utf8_lossy(body));
        };
        let text = std::str::from_utf8(&body[..line_end]).expect("ascii size");
        let size = usize::from_str_radix(text.trim(), 16)
            .unwrap_or_else(|_| panic!("bad chunk size {text:?}"));
        body = &body[line_end + 2..];
        if size == 0 {
            return out;
        }
        assert!(body.len() >= size + 2, "chunk of {size} runs past the body");
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Read everything the client is sent, returning `Some(elapsed)` when the stream went quiet.
async fn read_slowly(
    tls: &mut tokio_rustls::client::TlsStream<tokio::io::DuplexStream>,
) -> (Vec<u8>, Option<Duration>) {
    let started = std::time::Instant::now();
    let mut got = Vec::new();
    loop {
        let mut chunk = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk)).await {
            Ok(Ok(0)) => return (got, None),
            Ok(Ok(n)) => {
                got.extend_from_slice(&chunk[..n]);
                // A phone's renderer reads in bursts, not at line rate: without this pause the client
                // drains the relay faster than the origin supplies it and the writer never blocks.
                tokio::time::sleep(Duration::from_millis(2)).await;
                // The origin keeps the connection open (keep-alive), so the end of the *document* is
                // the terminal chunk, not EOF. Without this the reader would sit on a complete body
                // until its own timeout and report a stall that is really "nothing more is coming".
                if got.ends_with(b"0\r\n\r\n") {
                    return (got, None);
                }
            }
            Ok(Err(_)) => return (got, None),
            Err(_) => return (got, Some(started.elapsed())),
        }
    }
}

type SlowRun = (usize, usize, Option<Duration>, Option<Vec<u8>>);

async fn large_document_slow_client(rules: &str) -> SlowRun {
    large_document_slow_client_with(rules, "text/html").await
}

async fn large_document_slow_client_with(rules: &str, content_type: &'static str) -> SlowRun {
    let pki = Arc::new(TestPki::new("www.example.com"));
    let (plain, _compressed, framed) = large_gzip_document(1_200_000);
    let mut response = Vec::new();
    response.extend_from_slice(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Encoding: gzip\r\n\
             Transfer-Encoding: chunked\r\n\r\n"
        )
        .as_bytes(),
    );
    response.extend_from_slice(&framed);
    let response: &'static [u8] = Box::leak(response.into_boxed_slice());
    let origin = Origin::start(pki.clone(), move |mut stream| {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            loop {
                let Ok(n) = stream.read(&mut buffer).await else { return };
                if n == 0 || buffer[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            for piece in response.chunks(1400) {
                if stream.write_all(piece).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
                tokio::task::yield_now().await;
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
    })
    .await;

    let relay = Relay::new(rules, "").trust(&pki);
    // 16 KiB each way: four times smaller than one decoded round, so the relay's writes must block.
    let mut session = start_with_pipe(&relay, origin.remote(), "www.example.com", 10001, 16 * 1024);
    let mut tls = session
        .browser_tls("www.example.com", &[b"http/1.1"])
        .await
        .expect("handshake");
    tls.write_all(b"GET / HTTP/1.1\r\nHost: www.example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
        .await
        .expect("request");

    let (got, stalled) = read_slowly(&mut tls).await;
    // A keep-alive origin leaves the socket open, so the end of the *body* is the terminal chunk.
    let complete = got.ends_with(b"0\r\n\r\n");
    let body = complete.then(|| {
        let head_end = got
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a response head")
            + 4;
        strip_chunk_framing(&got[head_end..])
    });
    (got.len(), plain.len(), stalled.filter(|_| !complete), body)
}

#[tokio::test]
async fn a_large_document_survives_a_slow_http11_client() {
    let (received, expected, stalled, body) =
        large_document_slow_client("www.example.com##.row").await;
    assert!(
        stalled.is_none(),
        "the document stopped arriving after {received} bytes of ~{expected} (stalled {stalled:?})"
    );
    let body = body.expect("the body must be framed to its end");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("data-zshield=\"specific\""), "the rule must be injected");
    assert!(
        text.ends_with("</body></html>"),
        "the document must arrive whole, not merely end with a terminal chunk"
    );
}

#[tokio::test]
async fn a_large_non_document_survives_a_slow_http11_client() {
    // Nothing rewrites this response at all: it exercises the plain copy path only.
    let (received, expected, stalled, _body) =
        large_document_slow_client_with("", "application/octet-stream").await;
    assert!(
        stalled.is_none(),
        "the body stopped arriving after {received} bytes of ~{expected} (stalled {stalled:?})"
    );
}

#[tokio::test]
async fn a_large_document_survives_a_slow_http11_client_without_cosmetic_rules() {
    let (received, expected, stalled, body) = large_document_slow_client("").await;
    assert!(
        stalled.is_none(),
        "the document stopped arriving after {received} bytes of ~{expected} (stalled {stalled:?})"
    );
    let body = body.expect("the body must be framed to its end");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.ends_with("</body></html>"),
        "the document must arrive whole, not merely end with a terminal chunk"
    );
}

/// An h2 origin that streams a large gzip document in many small DATA frames.
fn h2_large_document_origin(
    framed: Vec<u8>,
) -> impl Fn(tokio_rustls::server::TlsStream<TcpStream>) -> tokio::task::JoinHandle<()>
       + Send
       + Sync
       + 'static {
    move |stream| {
        let framed = framed.clone();
        tokio::spawn(async move {
            let Ok(mut connection) = h2::server::handshake(stream).await else {
                return;
            };
            while let Some(accepted) = connection.accept().await {
                let Ok((_request, mut respond)) = accepted else {
                    return;
                };
                let framed = framed.clone();
                tokio::spawn(async move {
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "text/html; charset=utf-8")
                        .header("content-encoding", "gzip")
                        .body(())
                        .expect("response");
                    let Ok(mut send) = respond.send_response(response, false) else {
                        return;
                    };
                    // `send_data` without a reservation buffers and requests capacity itself; the
                    // unbounded buffering the docs warn about is exactly what a fixture wants here —
                    // the point under test is the relay, not this origin's back-pressure.
                    for piece in framed.chunks(1400) {
                        if send.send_data(bytes::Bytes::copy_from_slice(piece), false).is_err() {
                            return;
                        }
                        tokio::task::yield_now().await;
                    }
                    let _ = send.send_data(bytes::Bytes::new(), true);
                });
            }
        })
    }
}

#[tokio::test]
async fn a_large_h2_document_survives_a_slow_client() {
    let pki = Arc::new(TestPki::new(H2_AUTHORITY).with_alpn(&[b"h2"]));
    // HTTP/2 has no chunk coding: the stream's DATA frames are the framing.
    let (plain, compressed, _framed) = large_gzip_document(1_200_000);
    let origin = Origin::start(pki.clone(), h2_large_document_origin(compressed)).await;
    let relay = Relay::new("www.example.com##.row", "").trust(&pki);

    // A 16 KiB browser pipe: the relay's h2 writes meet a client that is behind.
    let mut session = start_with_pipe(&relay, origin.remote(), H2_AUTHORITY, 10001, 16 * 1024);
    let (mut sender, connection) = h2_client(&mut session, H2_AUTHORITY).await;
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{H2_AUTHORITY}/"))
        .header("sec-fetch-dest", "document")
        .body(())
        .expect("request");
    let (response, _) = sender.send_request(request, true).expect("send");
    // The connection future is what actually moves DATA frames: it must be driven for the whole
    // read, not just while waiting for the response head.
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = tokio::time::timeout(Duration::from_secs(30), response)
        .await
        .expect("a response head")
        .expect("response");
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let mut received = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), body.data()).await {
                Ok(Some(Ok(chunk))) => {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    received.extend_from_slice(&chunk);
                }
                Ok(Some(Err(err))) => panic!("body error after {} bytes: {err}", received.len()),
                Ok(None) => return,
                Err(_) => panic!("body went quiet after {} bytes", received.len()),
            }
        }
    })
    .await;
    driver.abort();
    assert!(
        read.is_ok(),
        "the h2 body stopped arriving after {} of ~{} bytes",
        received.len(),
        plain.len()
    );
    let text = String::from_utf8_lossy(&received);
    assert!(text.contains("data-zshield=\"specific\""), "the rule must be injected");
    assert!(text.ends_with("</body></html>"), "the document must be complete");
}

// ---------------------------------------------------------------------------------------------
// MYS-2727: a browser's parallel pre-connections must not bypass a host it just decrypted
// ---------------------------------------------------------------------------------------------

/// An origin for one plain HTTP/1.1 exchange, so a test can drive a connection all the way to a
/// completed, decrypted request instead of stopping at the handshake.
async fn responding_origin() -> (Arc<TestPki>, Origin) {
    let pki = Arc::new(TestPki::new("cdn.example.com"));
    let origin = Origin::start(pki.clone(), |mut stream| {
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npage")
                .await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        })
    })
    .await;
    (pki, origin)
}

/// Drive one complete decrypted exchange for `(uid, host)`, which is what records the pair as
/// trusting our leaf.
async fn complete_one_connection(relay: &Relay, origin: &Origin, host: &str, uid: u32) {
    let mut session = Session::start(relay, origin.remote(), host, uid);
    let mut tls = session
        .browser_tls(host, &[b"http/1.1"])
        .await
        .expect("the connection must be decrypted");
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .expect("write");
    let mut buffer = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read(&mut buffer)).await;
    drop(tls);
    let _ = session.finish().await;
}

#[tokio::test]
async fn a_parallel_preconnect_after_a_successful_handshake_does_not_bypass_the_host() {
    // The reported failure (MYS-2727): Chrome opens several TLS connections to one host, one wins,
    // and it closes the rest mid-handshake. Five of those used to put the host on the 24 h bypass
    // list — a host that had just been decrypted. It must stay decrypted.
    let (pki, origin) = responding_origin().await;
    let relay = Relay::new("", "").trust(&pki);

    // 1. One connection completes: the pair has proved it accepts our leaf.
    complete_one_connection(&relay, &origin, "cdn.example.com", 10001).await;
    assert_eq!(relay.stats.snapshot().intercepted, 1);

    // 2. Five racing connections are abandoned after our certificate went out.
    let mut rejected = 0u64;
    for attempt in 0..5 {
        let mut session = Session::start(&relay, origin.remote(), "cdn.example.com", 10001);
        session.hang_up_after_server_flight("cdn.example.com").await;
        let outcome = session.finish().await;
        assert!(
            matches!(outcome, HttpsOutcome::ClientRejected | HttpsOutcome::Failed),
            "abandoned connection #{attempt} must not succeed, got {outcome:?}"
        );
        if outcome == HttpsOutcome::ClientRejected {
            rejected += 1;
        }
        assert!(
            !relay.ctx.bypass.is_bypassed(10001, "cdn.example.com"),
            "abandoned connection #{attempt} must not bypass the host"
        );
    }
    assert_eq!(rejected, 5, "every abandoned connection must be a client failure");

    let snapshot = relay.stats.snapshot();
    assert_eq!(
        snapshot.auto_bypassed, 0,
        "no connection may have entered the bypass table"
    );
    // Every client failure above is a disconnect, so all of them must be in the ignored counter —
    // and `httpsHandshakeFailures` counts the same five, i.e. nothing was silently dropped.
    assert_eq!(
        snapshot.disconnects_ignored, rejected,
        "every disconnect must be counted as ignored"
    );
    assert_eq!(snapshot.handshake_failures, rejected);
    assert!(relay.ctx.bypass.is_empty());

    // 3. A later connection is still decrypted — the whole point of the fix.
    complete_one_connection(&relay, &origin, "cdn.example.com", 10001).await;
    assert_eq!(relay.stats.snapshot().intercepted, 2);
}

#[tokio::test]
async fn a_client_that_never_trusted_us_still_bypasses_on_the_second_disconnect() {
    // The behaviour M3a introduced and this fix must keep: a client that never completes a handshake
    // and keeps dropping the connection after being shown the certificate is bypassed on the second
    // sighting. Nothing here ever succeeded, so `disconnectsIgnored` stays at zero.
    let (pki, origin) = responding_origin().await;
    let relay = Relay::new("", "").trust(&pki);

    for attempt in 0..2 {
        let mut session = Session::start(&relay, origin.remote(), "cdn.example.com", 10001);
        session.hang_up_after_server_flight("cdn.example.com").await;
        let outcome = session.finish().await;
        assert_eq!(outcome, HttpsOutcome::ClientRejected);
        let bypassed = relay.ctx.bypass.is_bypassed(10001, "cdn.example.com");
        assert_eq!(
            bypassed,
            attempt == 1,
            "the second disconnect must be the one that bypasses (attempt {attempt})"
        );
    }

    let snapshot = relay.stats.snapshot();
    assert_eq!(snapshot.auto_bypassed, 1);
    assert_eq!(
        snapshot.disconnects_ignored, 0,
        "neither disconnect may be ignored: the pair never completed a handshake"
    );
    assert_eq!(relay.ctx.bypass.snapshot(0).len(), 1);
    assert_eq!(relay.ctx.bypass.snapshot(0)[0].reason, "client_disconnect");
}

#[tokio::test]
async fn a_disconnect_before_our_certificate_is_never_counted() {
    // A client that gives up while still sending its ClientHello never saw our leaf, so its
    // departure says nothing: an answer that is slow and a give-up look identical on the wire.
    let (pki, origin) = responding_origin().await;
    let relay = Relay::new("", "").trust(&pki);

    for _ in 0..3 {
        let mut session = Session::start(&relay, origin.remote(), "cdn.example.com", 10001);
        session.hang_up_mid_client_hello("cdn.example.com").await;
        // The relay cannot even parse a partial ClientHello, so it has no SNI to bypass; what matters
        // is that the pair is untouched.
        let _ = tokio::time::timeout(Duration::from_secs(5), session.finish()).await;
        assert!(
            !relay.ctx.bypass.is_bypassed(10001, "cdn.example.com"),
            "an unfinished ClientHello must never bypass anything"
        );
    }
    assert!(relay.ctx.bypass.is_empty());
}

#[tokio::test]
async fn an_explicit_certificate_alert_still_bypasses_at_once_over_the_wire() {
    // Regression for rule 4 of the task card, end to end: a client that states `unknown_ca` is
    // bypassed on the first connection, regardless of any recent success for the pair.
    let pki = Arc::new(TestPki::new("www.example.com"));
    let origin = Origin::start(pki.clone(), |_stream| tokio::spawn(async {})).await;
    let relay = Relay::new("", "").trust(&pki);

    // Let the pair complete one handshake first, so the recent-success rule is armed.
    complete_one_connection(&relay, &origin, "www.example.com", 10001).await;
    assert_eq!(relay.stats.snapshot().intercepted, 1);

    // A client that trusts only the origin's root states `unknown_ca` for our leaf.
    let mut session = Session::start(&relay, origin.remote(), "www.example.com", 10001);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(pki.ca.cert_der.clone()))
        .expect("origin root");
    let config = tls::client_config_with_roots(roots, Vec::new());
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = tls::server_name("www.example.com").expect("name");
    let browser = session.browser.take().expect("browser socket");
    assert!(
        connector.connect(name, browser).await.is_err(),
        "the client must reject our leaf"
    );
    assert_eq!(session.finish().await, HttpsOutcome::ClientRejected);

    assert!(
        relay.ctx.bypass.is_bypassed(10001, "www.example.com"),
        "an explicit alert must bypass even though the pair succeeded a moment ago"
    );
    let snapshot = relay.stats.snapshot();
    assert_eq!(snapshot.auto_bypassed, 1);
    assert_eq!(
        snapshot.disconnects_ignored, 0,
        "an explicit alert is not an ignored disconnect"
    );
    assert_ne!(
        relay.ctx.bypass.snapshot(0)[0].reason, "client_disconnect",
        "the reason must name the alert, not a disconnect"
    );
}
