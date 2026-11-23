//! The per-connection MITM state machine: client TLS ⇄ decision ⇄ origin TLS.
//!
//! One tunnelled 443 connection goes through these steps, and each step has exactly one failure
//! behaviour — there is no path that leaves a connection hanging (task card §3/§4):
//!
//! ```text
//! 1. sniff       the ClientHello is already buffered by the tunnel (SNI + ALPN)
//! 2. decide      policy::decide → decrypt or skip
//! 3. upstream    TCP + TLS to the origin with the client's SNI and ALPN, verified normally
//!      ├─ verify fails, name mismatch, any TLS error ─▶ 4
//! 4. passthrough  replay the buffered ClientHello on a *fresh* TCP connection, copy both ways
//! 5. downstream  TLS to the client, leaf for that SNI
//!      ├─ handshake fails (unknown_ca / bad_certificate / reset) ─▶ record auto-bypass, close
//! 6. relay       h2 or h1.1, filtered per request
//! ```
//!
//! # Why the passthrough replays on a new socket
//!
//! The origin's TLS was already started with a ClientHello of ours, so the client's own bytes can no
//! longer be sent on that socket. A fresh TCP connection plus the buffered ClientHello is the only
//! way to let the client see and judge the real certificate itself, which is the whole point of
//! "上游校验失败 → 直通": a client that trusts a pinned certificate keeps working, and one that does
//! not reports the error it would have reported without us.
//!
//! # Why a client handshake failure is a bypass, not an error
//!
//! A browser that does not trust user CAs (or an app with a pinned certificate) answers our leaf with
//! `unknown_ca`. Retrying the decryption on its next connection would break it permanently, so the
//! pair is remembered for 24 h ([`crate::https::policy::AutoBypass`]) and passed through instead.
//!
//! # Why a bare disconnect usually is not
//!
//! A browser opens several TLS connections to one host at once and abandons the losers as soon as one
//! handshake wins, which on the wire looks exactly like a pinned app rejecting our certificate. What
//! separates them is evidence, and [`crate::https::policy::AutoBypass::observe`] demands two pieces:
//! the pair did not complete a handshake recently, and our certificate had already been sent. The
//! second is answered by [`tls::CertificateSent`], set from the resolver rustls calls when it builds
//! the Certificate message — so a connection that gave up before that point never counts.
//!
//! # Why `run` owns the client stream
//!
//! The HTTP/2 relay drives the client connection and every stream on it concurrently, which needs
//! `Send + 'static` futures. Owning the stream from the start is what makes that possible without a
//! second, borrowing clone of the same socket.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::http::relay::{self as http_relay, HttpContext};
use crate::https::h2;
use crate::https::modifiers::RemoveHeaderRules;
use crate::https::policy::{AutoBypass, HandshakePhase, Verdict};
use crate::https::stats::HttpsStats;
use crate::https::tls::{self, Alpn};

/// How long the origin has to accept the TCP connection and complete its TLS handshake.
///
/// One value for both steps: a host that is unreachable and a host that accepts TCP and then never
/// answers are the same problem from the user's side, and 10 s is long enough for a slow mobile link
/// and short enough that a page load does not appear frozen.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the client has to complete its TLS handshake after we start ours.
///
/// Longer than the upstream budget because it is bounded by the client's own timeouts, and a client
/// that abandons the handshake closes the connection (which ends the wait anyway).
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(20);

/// Everything a decrypted connection needs, shared by every HTTPS relay task of one engine.
#[derive(Clone)]
pub struct HttpsContext {
    /// The HTTP pipeline for the decrypted leg: rules, request log, `$redirect` resources, and the
    /// modifier source (`$removeparam`, `$removeheader`, `$csp`).
    pub http: HttpContext,
    /// `$removeheader` rules, kept alongside for the delivery note and the log.
    pub removeheader: Arc<RemoveHeaderRules>,
    /// The root CA in force.
    pub ca: Arc<crate::https::ca::Ca>,
    /// The upstream TLS configuration (platform-verified in production).
    pub upstream: Arc<rustls::ClientConfig>,
    /// `(uid, host)` pairs that must be passed through.
    pub bypass: Arc<AutoBypass>,
    pub stats: Arc<HttpsStats>,
}

impl HttpsContext {
    /// Downstream ALPN: exactly the protocol (or protocols) the origin settled on.
    ///
    /// This used to be a fixed `[h2, http/1.1]`, which broke every HTTPS site that does not speak
    /// h2: the client negotiated h2 with us and `http/1.1` with the origin, and the two legs cannot be
    /// spliced — so the connection failed instead of downgrading. Offering only what the origin chose
    /// means the client independently lands on the same protocol, and a client that asked for h2
    /// against an HTTP/1.1-only origin correctly gets `http/1.1` (which is what it would have got
    /// without us).
    ///
    /// `None` — the origin offered no ALPN at all — becomes `http/1.1` alone, the protocol RFC 9113
    /// §3.2 says to assume. It is offered explicitly rather than advertised as "no ALPN" so a browser
    /// has nothing to guess about.
    pub fn downstream_alpn(upstream: Alpn) -> Vec<Vec<u8>> {
        vec![match upstream {
            Alpn::H2 => tls::ALPN_H2.to_vec(),
            Alpn::Http11 => tls::ALPN_HTTP11.to_vec(),
        }]
    }
}

impl std::fmt::Debug for HttpsContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsContext")
            .field("removeheader_rules", &self.removeheader.len())
            .field("ca", &self.ca.info().fingerprint_sha256)
            .finish_non_exhaustive()
    }
}

/// How one decrypted connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsOutcome {
    /// The client and the origin talked through us; both directions drained.
    Clean,
    /// The connection was passed through verbatim (not selected, excluded, or upstream invalid).
    Passthrough,
    /// The client would not accept our certificate. The pair is now auto-bypassed.
    ClientRejected,
    /// Something failed; the connection is not usable.
    Failed,
}

impl HttpsOutcome {
    /// True when the tunnel may close the connection with a FIN instead of a RST.
    pub fn is_clean(self) -> bool {
        matches!(self, HttpsOutcome::Clean | HttpsOutcome::Passthrough)
    }
}

/// What the upstream handshake produced, or why it did not.
///
/// Boxed because a `TlsStream` is over a kilobyte of session state and the error variant is a short
/// string: without the box every `Result` on this path would be sized for the large variant.
enum Upstream {
    /// A TLS session to the origin, with the ALPN it settled on.
    Ready(Box<tokio_rustls::client::TlsStream<TcpStream>>, Alpn),
    /// The certificate (or the connection) was not acceptable: pass through instead.
    Invalid(String),
}

/// Run the MITM path for one connection.
///
/// The caller has already decided that this connection is a candidate (port 443, TLS, owner
/// selected); the SNI-level parts of the decision are repeated here so the auto-bypass state is
/// consulted with the real hostname.
///
/// `initial` holds the bytes the tunnel already read (the ClientHello). `client` is the tunnelled
/// stream, taken by value so the HTTP/2 leg can move it between tasks.
pub async fn run<C>(
    client: C,
    initial: Vec<u8>,
    remote: std::net::SocketAddr,
    host: &str,
    uid: u32,
    ctx: &HttpsContext,
    outbound: Option<TcpStream>,
) -> HttpsOutcome
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if ctx.bypass.is_bypassed(uid, host) {
        return passthrough(client, &initial, remote, ctx, None).await;
    }

    let client_alpn = tls::client_alpn(&initial);
    let upstream_alpn = tls::upstream_alpn(&client_alpn);

    // ---- 3. upstream TLS, with the client's SNI and the intersected ALPN ---------------------
    // The tunnel already opened this socket before it started sniffing, so reusing it saves a TCP
    // handshake (and a socket) per decrypted connection. It carries nothing yet: the ClientHello was
    // held back for the decision.
    let (upstream_stream, upstream_alpn_negotiated) =
        match connect_upstream(remote, host, &upstream_alpn, ctx, outbound).await {
            Upstream::Ready(stream, alpn) => (stream, alpn),
            Upstream::Invalid(reason) => {
                // Certificate invalid, name mismatch, connection refused, timeout: all of them have
                // the same correct answer — let the client judge the origin itself.
                ctx.stats.count_upstream_invalid();
                crate::log_msg(
                    "info",
                    &format!("https upstream for {host} not decryptable ({reason}): passing through"),
                );
                return passthrough(client, &initial, remote, ctx, None).await;
            }
        };

    // ---- 5. client TLS with a leaf for that SNI ---------------------------------------------
    //
    // The downstream ALPN is the upstream's, not a preference: whatever the origin agreed to is the
    // only protocol both legs can frame, so that is the only one offered.
    let downstream_alpn = HttpsContext::downstream_alpn(upstream_alpn_negotiated);
    // The acceptor also reports whether our leaf was ever selected for this handshake, which is what
    // tells a client that judged our certificate apart from one that left before seeing it.
    let (acceptor, certificate_sent) =
        match tls::acceptor_watching_certificate(Arc::clone(&ctx.ca), downstream_alpn, host) {
            Ok(pair) => pair,
            Err(err) => {
                // Our own failure, not the client's: it is counted but never bypassed, because
                // bypassing would stop filtering this host for a day and hide the bug.
                crate::log_msg("error", &format!("cannot build the TLS acceptor: {err}"));
                ctx.stats.count_handshake_failure();
                return HttpsOutcome::Failed;
            }
        };

    // `initial` is the buffer the tunnel sniffed; everything after it is still in the stream, so the
    // handshake reads the two halves in order through `PrefixedStream`.
    let prefixed = PrefixedStream::new(initial, client);
    let client_tls = match tokio::time::timeout(CLIENT_TIMEOUT, acceptor.accept(prefixed)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            ctx.stats.count_handshake_failure();
            let failure = classify_client_failure(&err);
            let phase = if certificate_sent.is_sent() {
                HandshakePhase::AfterCertificate
            } else {
                HandshakePhase::BeforeCertificate
            };
            let verdict = ctx.bypass.observe(uid, host, failure, phase);
            if verdict.is_bypassed() {
                ctx.stats.count_auto_bypassed();
            }
            if verdict == Verdict::DisconnectIgnored {
                // Counted, but explicitly not as evidence: this is the counter that shows the
                // racing-connection rule working (MYS-2727).
                ctx.stats.count_disconnect_ignored();
            }
            let ignored_total = ctx.stats.snapshot().disconnects_ignored;
            crate::log_msg(
                "info",
                &format!(
                    "https client for {host} (uid {uid}) failed the handshake ({}): {} \
                     [httpsDisconnectsIgnored={ignored_total}]",
                    failure.reason(),
                    disposition(failure, phase, verdict)
                ),
            );
            return HttpsOutcome::ClientRejected;
        }
        Err(_) => {
            // Our timeout, not the client's verdict.
            ctx.stats.count_handshake_failure();
            crate::log_msg("debug", &format!("https client handshake for {host} timed out"));
            return HttpsOutcome::Failed;
        }
    };

    // The downstream handshake succeeded, so this connection really is decrypted and filtered. The
    // counter is recorded here rather than before the handshake (where it used to be): a client that
    // rejected our leaf was being counted as intercepted even though nothing was filtered.
    ctx.stats.count_intercepted();
    // …and the pair has just proved that it accepts our leaf. Every disconnect it causes from now
    // until that record expires is a connection that lost a race, not a certificate verdict, so it
    // must not be allowed to switch filtering off for this host (MYS-2727).
    ctx.bypass.record_success(uid, host);

    // The downstream session's ALPN must equal the upstream's: it was the only one offered.
    let negotiated = client_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|protocol| Alpn::from_negotiated(Some(protocol)))
        .unwrap_or(Alpn::Http11);
    debug_assert_eq!(
        negotiated, upstream_alpn_negotiated,
        "the client can only pick the protocol the origin chose"
    );

    // ---- 6. relay ---------------------------------------------------------------------------
    //
    // Which protocol the connection ended up on is the one fact needed to explain a counter that
    // stays at zero (`h2Streams` with a browser that offered h2 but reached an HTTP/1.1 origin).
    crate::log_msg(
        "debug",
        &format!(
            "https decrypt {host} (uid {uid}) negotiated {}",
            upstream_alpn_negotiated.as_str()
        ),
    );
    match upstream_alpn_negotiated {
        Alpn::H2 => {
            match h2::run(client_tls, upstream_stream, Arc::new(ctx.clone()), host.to_string()).await {
                Ok(()) => HttpsOutcome::Clean,
                Err(err) => {
                    crate::log_msg("debug", &format!("h2 relay for {host} ended: {err}"));
                    HttpsOutcome::Failed
                }
            }
        }
        Alpn::Http11 => {
            let mut upstream_stream = upstream_stream;
            let mut client_stream = client_tls;
            let outcome = http_relay::run(
                &mut client_stream,
                &mut upstream_stream,
                &ctx.http,
                Vec::new(),
            )
            .await;
            if outcome.clean {
                HttpsOutcome::Clean
            } else {
                HttpsOutcome::Failed
            }
        }
    }
}

/// One sentence for the log, matching what [`crate::https::policy::AutoBypass::observe`] decided.
fn disposition(
    failure: crate::https::policy::ClientFailure,
    phase: crate::https::policy::HandshakePhase,
    verdict: crate::https::policy::Verdict,
) -> &'static str {
    use crate::https::policy::{ClientFailure, HandshakePhase, Verdict};
    match (failure, verdict) {
        (ClientFailure::CertificateRejected(_), _) => "auto-bypassed for 24 h",
        (ClientFailure::Disconnect(_), Verdict::Bypassed) => {
            "second recent disconnect after our certificate: auto-bypassed for 24 h"
        }
        (ClientFailure::Disconnect(_), Verdict::Recorded) => {
            "first disconnect after our certificate: recorded, a second within 10 min bypasses"
        }
        (ClientFailure::Disconnect(_), _) if phase == HandshakePhase::BeforeCertificate => {
            "ignored: the client left before our certificate was sent"
        }
        (ClientFailure::Disconnect(_), _) => {
            "ignored: this pair completed a handshake recently, so the client accepts our leaf \
             (a racing connection, not a verdict)"
        }
        (ClientFailure::Local(_), _) => "not bypassed (local failure)",
    }
}

/// Run the upstream handshake, or say why it cannot be used.
async fn connect_upstream(
    remote: std::net::SocketAddr,
    host: &str,
    alpn: &[Vec<u8>],
    ctx: &HttpsContext,
    outbound: Option<TcpStream>,
) -> Upstream {
    let socket = match outbound {
        // Reused: the tunnel opened it before the sniff and never wrote to it.
        Some(socket) => socket,
        None => match tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(remote)).await {
            Ok(Ok(socket)) => {
                if let Err(err) = socket.set_nodelay(true) {
                    return Upstream::Invalid(format!("nodelay: {err}"));
                }
                socket
            }
            Ok(Err(err)) => return Upstream::Invalid(format!("connect: {err}")),
            Err(_) => return Upstream::Invalid("connect timed out".to_string()),
        },
    };
    let server_name = match tls::server_name(host) {
        Ok(name) => name,
        Err(err) => return Upstream::Invalid(err),
    };
    let connector = tls::connector(Arc::clone(&ctx.upstream), alpn);
    match tokio::time::timeout(UPSTREAM_TIMEOUT, connector.connect(server_name, socket)).await {
        Ok(Ok(stream)) => {
            let negotiated = stream
                .get_ref()
                .1
                .alpn_protocol()
                .map(|protocol| Alpn::from_negotiated(Some(protocol)))
                .unwrap_or(Alpn::Http11);
            Upstream::Ready(Box::new(stream), negotiated)
        }
        Ok(Err(err)) => Upstream::Invalid(format!("tls: {err}")),
        Err(_) => Upstream::Invalid("tls handshake timed out".to_string()),
    }
}

/// Replay the buffered bytes on a fresh connection and copy both ways.
async fn passthrough<C>(
    mut client: C,
    initial: &[u8],
    remote: std::net::SocketAddr,
    ctx: &HttpsContext,
    outbound: Option<TcpStream>,
) -> HttpsOutcome
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ctx.stats.count_passthrough();
    // A caller that still has the unused outbound socket hands it over; a caller that already
    // started a TLS session on one (an upstream that failed verification) does not, because those
    // bytes can no longer be replayed as the client's own ClientHello.
    let mut socket = match outbound {
        Some(socket) => socket,
        None => match tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect(remote)).await {
            Ok(Ok(socket)) => socket,
            Ok(Err(err)) => {
                crate::log_msg("debug", &format!("passthrough connect {remote} failed: {err}"));
                return HttpsOutcome::Failed;
            }
            Err(_) => {
                crate::log_msg("debug", &format!("passthrough connect {remote} timed out"));
                return HttpsOutcome::Failed;
            }
        },
    };
    let _ = socket.set_nodelay(true);
    if !initial.is_empty() && socket.write_all(initial).await.is_err() {
        return HttpsOutcome::Failed;
    }
    // `copy_bidirectional` handles half-close in both directions; a TLS connection that either side
    // closes cleanly ends here, and anything else is reported as a failure so the tunnel RSTs.
    match tokio::io::copy_bidirectional(&mut client, &mut socket).await {
        Ok(_) => HttpsOutcome::Passthrough,
        Err(err) => {
            crate::log_msg("debug", &format!("passthrough for {remote} ended: {err}"));
            HttpsOutcome::Failed
        }
    }
}

/// Turn a rustls handshake error into the typed failure the bypass table understands.
///
/// The strings are stable because `httpsBypassJson` exposes them and the UI shows them: a user
/// looking at "why is this app not filtered" must get an answer that is not a debug rendering.
///
/// The *kind* matters as much as the name. Only an explicit alert says the client judged our
/// certificate; an EOF says the client left, which is also what closing a tab looks like, so it needs
/// a second sighting before it may turn filtering off for a day.
fn classify_client_failure(error: &std::io::Error) -> crate::https::policy::ClientFailure {
    use crate::https::policy::ClientFailure;
    let text = error.to_string();
    if text.contains("UnknownCA") || text.contains("unknown ca") {
        ClientFailure::CertificateRejected("client_unknown_ca")
    } else if text.contains("BadCertificate") || text.contains("bad certificate") {
        ClientFailure::CertificateRejected("client_bad_certificate")
    } else if text.contains("CertificateUnknown") || text.contains("certificate unknown") {
        ClientFailure::CertificateRejected("client_certificate_unknown")
    } else if text.contains("CertificateRequired") || text.contains("certificate required") {
        ClientFailure::CertificateRejected("client_certificate_required")
    } else if error.kind() == std::io::ErrorKind::UnexpectedEof
        || error.kind() == std::io::ErrorKind::ConnectionReset
        || error.kind() == std::io::ErrorKind::BrokenPipe
    {
        // The client closed during the handshake. From a pinned app's side that is how rejecting a
        // certificate looks — but so is a user closing a tab, hence the second-strike rule.
        ClientFailure::Disconnect("client_disconnect")
    } else {
        ClientFailure::Local("client_handshake_failed")
    }
}

/// A stream that yields `prefix` first and then reads from `inner`.
///
/// The tunnel's sniff phase has already consumed the client's ClientHello from the socket, so a TLS
/// acceptor handed the raw stream would see a handshake starting mid-record. This puts the consumed
/// bytes back in front without copying the two halves into one buffer.
struct PrefixedStream<C> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: C,
}

impl<C> PrefixedStream<C> {
    fn new(prefix: Vec<u8>, inner: C) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for PrefixedStream<C> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let position = this.prefix.position() as usize;
        let data = this.prefix.get_ref();
        if position < data.len() {
            let take = (data.len() - position).min(buf.remaining());
            buf.put_slice(&data[position..position + take]);
            this.prefix.set_position((position + take) as u64);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<C> {
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

/// Read the ClientHello out of `initial` and return its SNI.
pub fn hello_host(initial: &[u8]) -> Option<String> {
    crate::tun::inspect::client_hello_info(initial).and_then(|info| info.server_name)
}

#[cfg(test)]
#[path = "https_e2e.rs"]
mod e2e_tests;
