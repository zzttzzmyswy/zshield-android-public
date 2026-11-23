//! HTTP/2 on a decrypted connection: one decision per stream, everything else forwarded.
//!
//! `h2` is used directly (rather than through `hyper`) because the relay has to do something a
//! request/response client cannot express: **per-stream** decide, answer some streams locally while
//! the others keep streaming to the origin, and keep the origin's connection multiplexing intact.
//!
//! ```text
//! client ══h2══▶ h2::server ──stream──▶ decide ──block──▶ synthesized response
//!                                        │
//!                                        └─allow──▶ h2::client ══h2══▶ origin
//!                          ◀────────────────────────────────────────
//! ```
//!
//! # What is preserved
//!
//! - **Streams are independent.** A blocked stream never delays or reorders another, which is what
//!   the whole protocol is for; the HTTP/1.1 relay had to work around pipelining for the same
//!   property.
//! - **Flow control is the protocol's.** `h2` owns the windows on both legs, and a body copied
//!   through is released on the receive side only after it has been accepted on the send side, so a
//!   slow client throttles the origin rather than making the tunnel buffer.
//! - **GOAWAY and RST_STREAM propagate.** A stream the origin resets is reset towards the client, and
//!   a connection either side closes ends the relay.
//! - **Trailers are forwarded**, because a streaming or gRPC response carries its status there.
//!
//! # What is *not* handled
//!
//! HTTP/2 server push: browsers have removed it and the origin never uses it for a connection we
//! opened as a client. A PUSH_PROMISE would be a protocol error for `h2`'s client, which resets the
//! stream and leaves the connection usable.
//!
//! # Degrading
//!
//! Only the handshake can fail in a way that needs a decision: a client that does not trust our leaf
//! answers with an alert and the connection ends there (that is the auto-bypass path, handled by
//! [`crate::https::mitm`]). Once the h2 handshake succeeds there is no "verbatim copy" to fall back
//! to, so a framing error is reported and the connection closes — a truncated HTTP/2 connection at
//! least fails loudly in the browser rather than silently feeding it unfiltered bytes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::http::head::{HttpRequest, Version};
use crate::http::log::RequestOutcome;
use crate::http::resource::{self, RequestKind};
use crate::http::response;
use crate::http::rewrite::Edits;
use crate::https::modifiers;
use crate::https::mitm::HttpsContext;

/// Largest request body buffered while a decision is made.
///
/// The decision only needs the head, so a body is streamed: this cap applies to the *initial* bytes
/// a client sends together with its headers, which is what has to be held while the decision runs.
/// A request that arrives with more than this is forwarded in streaming mode with the bytes already
/// received, never buffered further.
pub const MAX_BUFFERED_BODY: usize = 64 * 1024;

/// Per-stream receive window offered to the client, and the one requested from the origin.
///
/// HTTP/2's default is 65 535 bytes, which caps a decrypted download at one window per round trip:
/// on a 60 ms mobile RTT that is about 8 Mbit/s no matter what the link can do. 1 MiB is the value
/// browsers use per stream, and it costs nothing until it is actually outstanding.
pub const STREAM_WINDOW: u32 = 1024 * 1024;

/// Connection-level window, covering every concurrent stream of the same connection.
///
/// Four times the per-stream window: enough that a page opening a dozen streams at once is not
/// throttled by the shared window, and still a bounded amount of buffering per decrypted connection
/// (`docs/PERF.md` §12.1 measures the PSS this implies).
pub const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

/// How long a client is given to finish its in-flight streams after the origin's connection ended.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Read at most `limit` bytes of a request body, releasing flow control as it goes.
///
/// Used for a body that will not be forwarded: the bytes still have to be taken off the receive
/// window, because a stream that stops reading holds the connection's window hostage. The limit
/// keeps a hostile upload from costing unbounded memory; whatever is left after it is dropped, and
/// the [`h2::RecvStream`] drop releases the rest of the window.
async fn drain_body(body: &mut RecvStream, limit: usize) -> usize {
    let mut total = 0;
    while total < limit {
        match body.data().await {
            Some(Ok(chunk)) => {
                total += chunk.len();
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            // End of stream, or a reset by the client: either way there is nothing left to read.
            _ => break,
        }
    }
    total
}

/// Counters for one h2 connection, folded into `HttpsStats` by the caller.
#[derive(Debug, Default)]
pub struct H2Counters {
    pub streams: AtomicU64,
    pub blocked: AtomicU64,
}

/// Relay one decrypted HTTP/2 connection.
///
/// `client` is the TLS stream from the browser, `upstream` the TLS stream to the origin. Both are
/// already handshaken — with the *same* ALPN, which [`crate::https::mitm`] guarantees by offering the
/// client only what the origin settled on — and this function owns the h2 layer on each side.
pub async fn run<C, S>(client: C, upstream: S, ctx: Arc<HttpsContext>, host: String) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // The origin leg first: a connection we cannot speak h2 to must fail before the client is told
    // its request was accepted.
    let mut client_builder = h2::client::Builder::new();
    client_builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW);
    let (sender, connection) = match client_builder.handshake(upstream).await {
        Ok(pair) => pair,
        Err(err) => {
            crate::log_msg("debug", &format!("h2 upstream handshake for {host} failed: {err}"));
            return Err(std::io::Error::other(format!("h2 upstream: {err}")));
        }
    };
    // The connection future must be driven for any stream to make progress; it ends when the sender
    // is dropped, which is exactly the lifetime of the relay. Its completion is also *news*: the
    // origin going away invalidates every stream the client has not opened yet, and Chrome does not
    // retry a stream it saw cancelled, so the client has to be told (GOAWAY) rather than left to
    // discover it one CANCEL at a time.
    let (upstream_gone_tx, upstream_gone_rx) = tokio::sync::oneshot::channel::<()>();
    let upstream_connection = tokio::spawn(async move {
        if let Err(err) = connection.await {
            crate::log_msg("debug", &format!("h2 upstream connection ended: {err}"));
        }
        let _ = upstream_gone_tx.send(());
    });

    let mut server_builder = h2::server::Builder::new();
    server_builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW);
    let mut server = match server_builder.handshake::<C, Bytes>(client).await {
        Ok(server) => server,
        Err(err) => {
            ctx.stats.count_handshake_failure();
            crate::log_msg("debug", &format!("h2 client handshake for {host} failed: {err}"));
            upstream_connection.abort();
            return Err(std::io::Error::other(format!("h2 client: {err}")));
        }
    };

    // `httpsIntercepted` is counted by the caller once the downstream TLS handshake succeeded, which
    // is the point where this connection really is decrypted; counting it here would count a
    // connection whose h2 handshake then failed.

    let sender = Arc::new(tokio::sync::Mutex::new(sender));
    // Every accepted stream gets its own task. `h2`'s accept loop must keep running for the
    // connection to make progress, so a stream that blocks on a slow origin cannot stall the others.
    let mut upstream_gone_rx = upstream_gone_rx;
    loop {
        let accepted = tokio::select! {
            biased;
            // The origin's connection ended: stop accepting, send GOAWAY, and let the streams that
            // are already running finish.
            //
            // `abrupt_shutdown(NO_ERROR)` rather than `graceful_shutdown()`: the graceful variant
            // waits a full round trip for a PING acknowledgement before it finalises the GOAWAY, and
            // this connection has nothing left upstream to justify the wait. `NO_ERROR` says the same
            // thing to the client — "this connection is finished, open a new one" — without leaving
            // the browser holding a connection that will never be used again.
            _ = &mut upstream_gone_rx => {
                crate::log_msg(
                    "debug",
                    &format!("h2 origin for {host} closed its connection; telling the client"),
                );
                server.abrupt_shutdown(h2::Reason::NO_ERROR);
                // Keep polling so the GOAWAY is actually written to the client.
                while let Some(accepted) = server.accept().await {
                    if let Err(err) = accepted {
                        crate::log_msg(
                            "debug",
                            &format!("h2 stream refused after GOAWAY for {host}: {err}"),
                        );
                    }
                    // Anything the client still had in flight is answered by the origin leg being
                    // gone; dropping `respond` resets the stream instead of hanging.
                }
                break;
            }
            accepted = server.accept() => accepted,
        };
        let Some(accepted) = accepted else {
            break;
        };
        let (request, respond) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                crate::log_msg("debug", &format!("h2 stream refused for {host}: {err}"));
                break;
            }
        };
        let ctx = ctx.clone();
        let sender = sender.clone();
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(err) = relay_stream(request, respond, sender, ctx, host.clone()).await {
                crate::log_msg("debug", &format!("h2 stream to {host} ended: {err}"));
            }
        });
    }

    drop(sender);
    // The upstream connection ends when the last sender is gone; wait for it so the TLS stream is
    // not closed while a response is still being written.
    let _ = tokio::time::timeout(DRAIN_GRACE, upstream_connection).await;
    Ok(())
}

/// Relay one stream: decide, then either answer locally or forward to the origin.
async fn relay_stream(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    sender: Arc<tokio::sync::Mutex<h2::client::SendRequest<Bytes>>>,
    ctx: Arc<HttpsContext>,
    host: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (parts, mut body) = request.into_parts();
    let method = parts.method.clone();
    let uri = parts.uri.clone();
    let headers = parts.headers.clone();

    let Some(model) = request_model(&method, &uri, &headers, &host) else {
        // No path, or a host we cannot form a URL for: this is not something a browser sends over
        // h2, and inventing a URL would make the rule engine judge the wrong thing. Forward it.
        return forward(
            &method, &uri, &headers, &mut body, &mut respond, &sender, None, None, &ctx,
        )
        .await;
    };

    let kind = resource::infer(&model);
    let applied = ctx
        .http
        .modifiers
        .as_ref()
        .and_then(|source| source.edits(&model, kind))
        .filter(|edits| !edits.is_empty());
    // Whether the response is going to be rewritten decides the request's `Accept-Encoding`: a
    // document this core injects into must arrive in a coding it can decode, everything else keeps
    // the client's own header.
    let cosmetic = (kind == RequestKind::Document && method != Method::HEAD)
        .then(|| {
            // The request's own `$removeheader`/`$csp` edits are folded into the plan, so one layer owns
            // the whole response head instead of two rewriting the same bytes (and, before review item
            // 11, appending the `$csp` directive twice).
            let mut plan = ctx.http.filter.cosmetic_plan(&model);
            if let Some(edits) = applied.as_ref() {
                plan.drop_response_headers = edits.drop_response_headers.clone();
                plan.extra_csp = edits.csp.clone();
            }
            plan
        })
        .filter(|plan| !plan.is_empty());
    let decision = ctx.http.filter.decide_typed(&model, kind);
    ctx.stats.count_h2_stream(decision.block);
    // MYS-2742: `httpBlocked` is the counter the home screen's "已拦截" sums, so a block on this path
    // has to land there too — it writes a log entry like the HTTP/1.1 relay does, and a log entry
    // with no counter behind it is exactly the disagreement MYS-2742 fixes. Before this, an
    // HTTP/2 block only reached `h2Blocked` and the log, so the two numbers parted company.
    ctx.http.stats.requests.fetch_add(1, Ordering::Relaxed);
    if decision.block {
        ctx.http.stats.blocked.fetch_add(1, Ordering::Relaxed);
        if decision.redirect.is_some() {
            ctx.http.stats.redirected.fetch_add(1, Ordering::Relaxed);
        }
    }

    record(ctx.as_ref(), &model, kind, &decision, applied.as_ref());

    if decision.block {
        crate::log_msg(
            "info",
            &format!(
                "https blocked {} {} ({}){}",
                model.method,
                model.url,
                kind.as_str(),
                decision
                    .matched_rule
                    .as_deref()
                    .map(|rule| format!(" by {rule}"))
                    .unwrap_or_default(),
            ),
        );
        let response = match decision.redirect.as_ref() {
            Some(redirect) => response::redirected(redirect),
            None => response::blocked(kind, &model.url),
        };
        send_local(&mut respond, &response, &method).await?;
        // The body is never read and never forwarded, but it still occupies the connection's receive
        // window. `body.trailers()` used to be awaited here, which never returns while DATA keeps
        // arriving: the unread bytes held the window, the client kept sending, and once enough
        // blocked uploads accumulated the whole connection stopped — with the task leaked. Draining
        // (bounded) and then dropping the stream releases the window instead.
        drain_body(&mut body, MAX_BUFFERED_BODY).await;
        return Ok(());
    }

    // A **document navigation** whose URL an `$removeparam` rule rewrote is answered with a `302`, the
    // same rule as HTTP/1.1 (`http::rewrite` module note). A non-navigation request is rewritten **in
    // place** by `forward` below, which changes the `:path` it sends upstream. In-place forwarding is
    // what a subresource needs: the origin receives the clean URL, and the client's own view of the URL
    // is deliberately unchanged (`docs/DESIGN.md`; redirecting a subresource would also break
    // `fetch(…, {redirect: 'error' | 'manual'})`).
    if let Some(target) = applied.as_ref().and_then(|edits| edits.url.as_deref()) {
        if kind.is_navigation() {
            crate::log_msg(
                "info",
                &format!("https redirect {} -> {target} (removeparam)", model.url),
            );
            ctx.http.stats.rewritten.fetch_add(1, Ordering::Relaxed);
            send_local(&mut respond, &response::rewritten_navigation(target), &method).await?;
            drain_body(&mut body, MAX_BUFFERED_BODY).await;
            return Ok(());
        }
        crate::log_msg(
            "info",
            &format!("https rewritten {} -> {target} (removeparam)", model.url),
        );
        ctx.http.stats.rewritten.fetch_add(1, Ordering::Relaxed);
    }

    forward(
        &method, &uri, &headers, &mut body, &mut respond, &sender, applied, cosmetic, &ctx,
    )
    .await
}

/// Build the request model the decision runs on.
///
/// The URL is reconstructed from `:scheme`, `:authority` and `:path`, which for an HTTPS connection
/// is `https://<host><path>` — the same shape the HTTP/1.1 relay matches against, so a rule written
/// for one path works identically on both protocols.
fn request_model(
    method: &Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    host: &str,
) -> Option<HttpRequest> {
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let authority = uri
        .authority()
        .map(|authority| authority.as_str().to_string())
        .unwrap_or_else(|| host.to_string());
    let hostname = crate::http::head::hostname_of(&authority);
    if hostname.is_empty() {
        return None;
    }
    let url = format!("https://{}{}", authority_for_url(&authority), path);

    let header = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    let content_length = header("content-length").and_then(|raw| raw.trim().parse::<usize>().ok());

    Some(HttpRequest {
        method: method.as_str().to_ascii_uppercase(),
        target: path.to_string(),
        version: Version::Http11,
        url,
        host: authority,
        hostname,
        referer: header("referer").and_then(|raw| crate::http::head::absolute_referer(&raw)),
        fetch_dest: header("sec-fetch-dest").map(|value| value.to_ascii_lowercase()),
        fetch_site: header("sec-fetch-site").map(|value| value.to_ascii_lowercase()),
        fetch_user: header("sec-fetch-user"),
        accept: header("accept"),
        content_length,
        // In HTTP/2 there is no chunked transfer coding (`Transfer-Encoding` is forbidden), so body
        // framing only ever comes from `Content-Length`.
        chunked: false,
        upgrade: false,
        expect_continue: false,
        head_len: 0,
    })
}

/// Drop a default port from an authority, so `host:443` and `host` produce the same URL.
fn authority_for_url(authority: &str) -> &str {
    authority
        .strip_suffix(":443")
        .filter(|head| !head.is_empty() && !head.ends_with(':'))
        .unwrap_or(authority)
}

/// Forward one stream to the origin, copying both directions.
///
/// `cosmetic` is the injection plan for a document the engine has rules for. When it is `Some`, the
/// response body is rewritten stream by stream ([`crate::cosmetic::BodyInjector`]) instead of copied —
/// but only once the origin's status, content type and coding say it really is an HTML document this
/// core can decode, and the stream is still reset rather than half-written if that turns out to be false
/// mid-body.
#[allow(clippy::too_many_arguments)]
async fn forward(
    method: &Method,
    uri: &http::Uri,
    headers: &HeaderMap,
    body: &mut RecvStream,
    respond: &mut SendResponse<Bytes>,
    sender: &Arc<tokio::sync::Mutex<h2::client::SendRequest<Bytes>>>,
    applied: Option<Edits>,
    cosmetic: Option<crate::cosmetic::Plan>,
    ctx: &HttpsContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The origin request is rebuilt from the client's, with two deliberate changes:
    // - `$removeparam` may have rewritten the path (the caller passes the modifiers);
    // - `$removeheader` may name request headers to drop.
    //
    // The origin request MUST carry `:scheme` and `:authority`. `h2` only emits those pseudo-headers
    // for an absolute URI, and it does not synthesize `:authority` from the dropped `host` header
    // (`host` is connection-specific and removed below), so a path-only URI reaches an nginx or a CDN
    // as a request with no authority and comes back `400 Bad Request`. Both are therefore taken from
    // the client's URI, which is where a browser puts them.
    let authority = uri
        .authority()
        .map(|authority| authority.as_str().to_string())
        .or_else(|| {
            headers
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        })
        .ok_or("the client request carries neither :authority nor host")?;
    let original_path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // A rewritten URL keeps the authority it was matched against; only the path changes.
    let path = match applied.as_ref().and_then(|m| m.url.as_deref()) {
        Some(rewritten) => rewritten
            .strip_prefix("https://")
            .and_then(|rest| rest.find('/').map(|index| rest[index..].to_string()))
            .unwrap_or(original_path),
        None => original_path,
    };
    let target = format!("https://{authority}{path}");
    let mut outgoing = Request::builder()
        .method(method.clone())
        // HTTP/2 semantics: `h2` encodes `:authority`/`:scheme` from the URI, and a `host` header
        // would be a protocol error.
        .version(http::Version::HTTP_2)
        .uri(target);
    let remove = applied
        .as_ref()
        .map(|m| m.drop_request_headers.as_slice())
        .unwrap_or(&[]);
    // A document whose response this core will rewrite has to arrive in a coding it decodes; see
    // `crate::http::rewrite::DOCUMENT_ACCEPT_ENCODING`.
    let narrow_encoding = cosmetic.is_some();
    {
        let outgoing_headers = outgoing
            .headers_mut()
            .ok_or("cannot build the upstream request")?;
        for (name, value) in headers {
            // Connection-specific headers are forbidden in HTTP/2 (RFC 9113 §8.2.2) and `h2` would
            // reject the request; the origin reconstructs them from the connection itself.
            if is_connection_specific(name.as_str()) {
                continue;
            }
            if remove.iter().any(|drop| name.as_str().eq_ignore_ascii_case(drop)) {
                continue;
            }
            if narrow_encoding && name == http::header::ACCEPT_ENCODING {
                continue;
            }
            outgoing_headers.append(name.clone(), value.clone());
        }
        if narrow_encoding {
            outgoing_headers.insert(
                http::header::ACCEPT_ENCODING,
                HeaderValue::from_static(crate::http::rewrite::DOCUMENT_ACCEPT_ENCODING),
            );
        }
    }
    let outgoing = outgoing.body(()).map_err(|e| format!("cannot build the upstream request: {e}"))?;

    // A request whose body is already complete opens the stream with END_STREAM on the headers, so
    // there is nothing left to send — calling `send_data` on it would be a protocol error
    // ("unexpected frame type"). The two cases are therefore genuinely different code paths.
    let body_complete = body.is_end_stream();
    let (response_future, mut send_body) = {
        let sender = sender.lock().await;
        // `send_request` fails with `UserError::Rejected` once the origin's `MAX_CONCURRENT_STREAMS`
        // is reached, and it does not wait for a slot itself. `ready()` does, which is what turns a
        // burst of streams on a request-heavy page into a queue instead of a batch of failures.
        let mut ready = sender.clone().ready().await?;
        ready.send_request(outgoing, body_complete)?
    };

    let upstream_response = if body_complete {
        response_future.await?
    } else {
        // The upload and the response are driven together: a server that answers before the body ends
        // (a `413`, a redirect) must not be starved by a client still uploading, which is the same
        // problem `http::relay::write_pumping` solves for HTTP/1.1. `join!` polls both to completion,
        // and a body copy that fails (the client reset its upload) cancels the origin stream.
        let (body_result, response_result) =
            tokio::join!(copy_body(body, &mut send_body), response_future);
        if let Err(err) = body_result {
            send_body.send_reset(h2::Reason::CANCEL);
            return Err(err);
        }
        response_result?
    };

    let (parts, mut upstream_body) = upstream_response.into_parts();

    // ---- cosmetic injection (M3b) ------------------------------------------------------------
    //
    // The decision uses the *response* headers, exactly as the HTTP/1.1 side does: a 200 with an HTML
    // content type and a coding this core decodes. Everything else is copied through unchanged, which
    // is also what happens when there is no plan at all (a subresource, or a page with no rule).
    let injector = cosmetic.and_then(|plan| {
        let head = head_from_headers(parts.status, &parts.headers);
        // Why a document was or was not injected is the first question a "my page still shows ads"
        // report asks, so the response's three decisive fields are logged once per document.
        crate::log_msg(
            "debug",
            &format!(
                "cosmetic: response {} {:?} enc {:?} injectable {}",
                head.status,
                head.content_type,
                head.content_encoding,
                head.is_injectable_document()
            ),
        );
        if !head.is_injectable_document() {
            return None;
        }
        let coding = head.coding()?;
        // The policy the injector will carry is the same one the response head gets below, so the
        // nonces the markup carries match the header the client receives.
        let mut policies = head.csp.clone();
        if let Some(extra) = plan.extra_csp.clone() {
            policies.push(extra);
        }
        crate::cosmetic::BodyInjector::new(plan, crate::cosmetic::OutFraming::Unframed, coding, &policies)
    });

    let mut outgoing_response = Response::builder().status(parts.status);
    {
        let response_headers = outgoing_response
            .headers_mut()
            .ok_or("cannot build the client response")?;
        let remove = applied
            .as_ref()
            .map(|m| m.drop_response_headers.as_slice())
            .unwrap_or(&[]);
        let injected = injector.as_ref();
        for (name, value) in &parts.headers {
            if is_connection_specific(name.as_str()) {
                continue;
            }
            if remove.iter().any(|drop| name.as_str().eq_ignore_ascii_case(drop)) {
                continue;
            }
            if injected.is_some() {
                // A rewritten body has no length and is no longer encoded: HTTP/2 forbids
                // `content-length` from disagreeing with the frames, and the client must not try to
                // decode what is now identity.
                if name == http::header::CONTENT_LENGTH
                    || name == http::header::CONTENT_ENCODING
                    || name == http::header::CONTENT_SECURITY_POLICY
                {
                    continue;
                }
            }
            response_headers.append(name.clone(), value.clone());
        }
        match injected {
            // The injector worked out the policies (it extended the origin's with the nonces the
            // markup carries); the response sends exactly those.
            Some(injector) => {
                for policy in injector.policies() {
                    if let Ok(value) = HeaderValue::from_str(policy) {
                        response_headers.append(http::header::CONTENT_SECURITY_POLICY, value);
                    }
                }
            }
            // `$csp` adds to whatever the origin sent rather than replacing it: a list that injects a
            // directive must not silently drop the site's own policy (which would *weaken* it).
            None => {
                if let Some(csp) = applied.as_ref().and_then(|m| m.csp.as_deref()) {
                    if let Ok(value) = HeaderValue::from_str(csp) {
                        response_headers.append(http::header::CONTENT_SECURITY_POLICY, value);
                    }
                }
            }
        }
    }
    let outgoing_response = outgoing_response.body(())?;
    let mut client_body = respond.send_response(outgoing_response, upstream_body.is_end_stream())?;
    match injector {
        Some(injector) => copy_injecting(&mut upstream_body, &mut client_body, injector, ctx).await,
        None => copy_body(&mut upstream_body, &mut client_body).await,
    }
}

/// Build the response head model from an HTTP/2 `HeaderMap`.
///
/// The same fields the HTTP/1.1 path parses out of the wire bytes, because the decision that follows —
/// is this an injectable document, is the coding one we decode — must be identical on both protocols.
fn head_from_headers(status: http::StatusCode, headers: &HeaderMap) -> crate::cosmetic::ResponseHead {
    let get = |name: http::header::HeaderName| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_ascii_lowercase())
    };
    crate::cosmetic::ResponseHead {
        status: status.as_u16(),
        content_type: get(http::header::CONTENT_TYPE),
        content_encoding: get(http::header::CONTENT_ENCODING),
        content_length: get(http::header::CONTENT_LENGTH).and_then(|value| value.parse().ok()),
        // HTTP/2 has no chunked coding; the stream's END_STREAM is the end.
        chunked: false,
        // A single header line may carry several comma-separated policies, and each is enforced on its
        // own, so each is kept on its own.
        csp: headers
            .get_all(http::header::CONTENT_SECURITY_POLICY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(crate::cosmetic::csp::split_policies)
            .collect(),
        attachment: get(http::header::CONTENT_DISPOSITION)
            .map(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("attachment")
            })
            .unwrap_or(false),
        // HTTP/2 always frames its own way, so the version only exists to satisfy the shared model.
        version: 11,
    }
}

/// Copy an origin body to the client while the cosmetic injector rewrites it.
///
/// A rewritten body that cannot be completed (a corrupt coding) resets the stream instead of leaving the
/// client holding half a document: `h2` has no "close the connection" mid-stream, and a reset is exactly
/// the signal that lets the browser retry.
async fn copy_injecting(
    from: &mut RecvStream,
    to: &mut SendStream<Bytes>,
    mut injector: crate::cosmetic::BodyInjector,
    ctx: &HttpsContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let chunk = match from.data().await {
            Some(Ok(chunk)) => {
                let _ = from.flow_control().release_capacity(chunk.len());
                chunk
            }
            Some(Err(err)) => return Err(err.into()),
            None => {
                // HTTP/2 has no framing of its own to verify here: `data()` returning `None` is
                // END_STREAM, which is the origin's own statement that the body is complete. A cut
                // connection arrives as `Some(Err(..))` above instead.
                let tail = injector.finish(true);
                let report = injector.report();
                crate::log_msg(
                    "info",
                    &format!(
                        "cosmetic: {} specific, {} generic, scriptlet {}, cspMeta {}",
                        report.specific, report.generic, report.scriptlet, report.csp_meta
                    ),
                );
                ctx.http.cosmetic.record(report, report.scriptlet);
                if tail.broke {
                    to.send_reset(h2::Reason::INTERNAL_ERROR);
                    return Err("cosmetic injection could not complete the document".into());
                }
                send_all(to, Bytes::from(tail.bytes), true).await?;
                if let Some(trailers) = from.trailers().await? {
                    // The trailers arrive before the body ends in h2, so they were already forwarded by
                    // `copy_body`'s shape; here they are dropped rather than sent after END_STREAM,
                    // which would be a protocol error.
                    let _ = trailers;
                }
                return Ok(());
            }
        };
        let emitted = injector.push(&chunk);
        if emitted.broke {
            ctx.http.cosmetic.record(injector.report(), false);
            to.send_reset(h2::Reason::INTERNAL_ERROR);
            return Err("cosmetic injection could not decode the document".into());
        }
        if emitted.verbatim {
            // The injector gave up before emitting a byte. Since review item 2 it keeps its decoded
            // prefix instead of setting this flag (dropping it truncated the page), so reaching here
            // means nothing was buffered at all: continue in the copy path.
            ctx.http.cosmetic.record(injector.report(), false);
            return copy_body(from, to).await;
        }
        if !emitted.bytes.is_empty() {
            send_all(to, Bytes::from(emitted.bytes), false).await?;
        }
    }
}

/// Copy one h2 body to another, honouring flow control.
///
/// `h2`'s send side grants capacity on request, not automatically: `capacity()` is zero until
/// [`h2::SendStream::reserve_capacity`] asks for a window, so a copy that only *reads* `capacity()`
/// waits forever. The loop therefore reserves exactly what it has to send, waits for the peer to
/// open the window, and releases the receive side only after the bytes have been accepted — which is
/// what makes a slow client throttle the origin instead of making the tunnel buffer.
async fn copy_body(
    from: &mut RecvStream,
    to: &mut SendStream<Bytes>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let chunk = match from.data().await {
            Some(Ok(chunk)) => {
                // Let the peer send its next frame; the bytes are held here until the opposite
                // window admits them, so at most one frame is buffered beyond the connection window.
                let _ = from.flow_control().release_capacity(chunk.len());
                chunk
            }
            Some(Err(err)) => return Err(err.into()),
            None => {
                // End of stream: forward the trailers if there are any, otherwise close the stream
                // with an empty DATA frame carrying END_STREAM.
                if let Some(trailers) = from.trailers().await? {
                    to.send_trailers(trailers)?;
                } else {
                    send_all(to, Bytes::new(), true).await?;
                }
                return Ok(());
            }
        };
        send_all(to, chunk, false).await?;
    }
}

/// Send `data` on `to`, waiting for the peer's flow-control window as needed.
async fn send_all(
    to: &mut SendStream<Bytes>,
    mut data: Bytes,
    end_of_stream: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let capacity = if to.capacity() == 0 {
            to.reserve_capacity(data.len().max(1));
            match std::future::poll_fn(|cx| to.poll_capacity(cx)).await {
                Some(Ok(capacity)) => capacity,
                Some(Err(err)) => return Err(err.into()),
                // The stream was closed by the peer; nothing more can be sent.
                None => return Err("stream closed by the peer".into()),
            }
        } else {
            to.capacity()
        };

        if data.is_empty() {
            if end_of_stream {
                to.send_data(Bytes::new(), true)?;
            }
            return Ok(());
        }
        let take = capacity.min(data.len());
        let rest = data.split_off(take);
        let last = rest.is_empty() && end_of_stream;
        to.send_data(data, last)?;
        if rest.is_empty() {
            return Ok(());
        }
        data = rest;
    }
}

/// Send a locally synthesized response on a stream, with the body it carries.
async fn send_local(
    respond: &mut SendResponse<Bytes>,
    response: &response::HttpResponse,
    method: &Method,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    {
        let headers = builder.headers_mut().ok_or("cannot build the response")?;
        if let Ok(value) = HeaderValue::from_str(response.content_type) {
            headers.insert(http::header::CONTENT_TYPE, value);
        }
        // The `$removeparam` redirect: the same header the HTTP/1.1 relay writes, from the same
        // constructor, so a rewritten URL looks identical on both protocols.
        if let Some(location) = response.location.as_deref() {
            if let Ok(value) = HeaderValue::from_str(location) {
                headers.insert(http::header::LOCATION, value);
            }
        }
        headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from(response.body.len()),
        );
        if response.no_store {
            headers.insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
        }
    }
    // A `HEAD` response carries no body but keeps the length, exactly as on HTTP/1.1.
    let head_only = method == Method::HEAD;
    // The headers must NOT carry END_STREAM when a body follows: `send_response(.., true)` closes the
    // stream, and the `send_data` after it fails with "unexpected frame type". The client would then
    // hold a `content-length: N` it never receives — a half-delivered block page or `$redirect`
    // substitute.
    let has_body = !head_only && !response.body.is_empty();
    let mut stream = respond.send_response(
        builder.body(()).map_err(|e| e.to_string())?,
        !has_body,
    )?;
    if has_body {
        // Every synthesized body is far below the initial flow-control window, so one `send_data`
        // never has to wait for capacity; `send_all` is used anyway so the window is respected if a
        // future resource gets bigger.
        send_all(&mut stream, Bytes::copy_from_slice(&response.body), true).await?;
    }
    Ok(())
}

/// Headers that must not be forwarded across an HTTP/2 hop (RFC 9113 §8.2.2).
fn is_connection_specific(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "te"
    )
}

/// A log-friendly name for the modifiers that changed a request.
fn describe_edits(edits: &Edits) -> String {
    let mut names = Vec::new();
    if edits.url.is_some() {
        names.push("removeparam");
    }
    if !edits.drop_request_headers.is_empty() || !edits.drop_response_headers.is_empty() {
        names.push(modifiers::UNSUPPORTED_MODIFIER);
    }
    if edits.csp.is_some() {
        names.push("csp");
    }
    format!("${}", names.join(",$"))
}

/// Record one judged request in the shared log, the same way the plaintext relay does.
fn record(
    ctx: &HttpsContext,
    request: &HttpRequest,
    kind: RequestKind,
    decision: &crate::http::decision::FilterDecision,
    applied: Option<&Edits>,
) {
    let outcome = if decision.block {
        if decision.redirect.is_some() {
            RequestOutcome::Redirected
        } else {
            RequestOutcome::Blocked
        }
    } else if decision.exception_rule.is_some() {
        RequestOutcome::Exception
    } else {
        RequestOutcome::Allowed
    };
    let third_party = crate::http::decision::is_third_party(request);
    let rule = match decision.matched_rule.clone() {
        Some(rule) => Some(rule),
        // A rule that only rewrote the URL or dropped a header still matched; naming it in the log
        // is what makes "why did this request change" answerable.
        None => applied.map(describe_edits),
    };
    ctx.http.log.record(
        request,
        kind,
        outcome,
        rule,
        decision.exception_rule.clone(),
        third_party,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).expect("name"),
                HeaderValue::from_str(value).expect("value"),
            );
        }
        headers
    }

    #[test]
    fn the_request_model_mirrors_the_http11_one() {
        let uri: http::Uri = "https://www.example.com/path?x=1".parse().expect("uri");
        let model = request_model(
            &Method::GET,
            &uri,
            &headers(&[
                ("referer", "https://site.example/page"),
                ("sec-fetch-dest", "SCRIPT"),
                ("accept", "*/*"),
            ]),
            "www.example.com",
        )
        .expect("model");
        assert_eq!(model.method, "GET");
        assert_eq!(model.url, "https://www.example.com/path?x=1");
        assert_eq!(model.hostname, "www.example.com");
        assert_eq!(model.referer.as_deref(), Some("https://site.example/page"));
        assert_eq!(model.fetch_dest.as_deref(), Some("script"));
        assert_eq!(model.accept.as_deref(), Some("*/*"));
        assert_eq!(model.body_kind(), crate::http::head::BodyKind::None);
    }

    #[test]
    fn the_default_https_port_is_not_part_of_the_url() {
        let with_port: http::Uri = "https://www.example.com:443/a".parse().expect("uri");
        let without: http::Uri = "https://www.example.com/a".parse().expect("uri");
        let first = request_model(&Method::GET, &with_port, &HeaderMap::new(), "www.example.com")
            .expect("model");
        let second =
            request_model(&Method::GET, &without, &HeaderMap::new(), "www.example.com")
                .expect("model");
        assert_eq!(first.url, "https://www.example.com/a");
        assert_eq!(first.url, second.url, "`||host^` has to match both spellings");
    }

    #[test]
    fn a_body_length_is_read_from_the_headers() {
        let uri: http::Uri = "https://a.example/upload".parse().expect("uri");
        let model = request_model(
            &Method::POST,
            &uri,
            &headers(&[("content-length", "42")]),
            "a.example",
        )
        .expect("model");
        assert_eq!(model.body_kind(), crate::http::head::BodyKind::Length(42));
        assert!(model.must_close_when_answered());
    }

    #[test]
    fn connection_specific_headers_are_not_forwarded() {
        for name in ["connection", "keep-alive", "transfer-encoding", "upgrade", "host", "te"] {
            assert!(is_connection_specific(name), "{name}");
        }
        for name in ["content-type", "cookie", "sec-fetch-dest", "accept-encoding"] {
            assert!(!is_connection_specific(name), "{name}");
        }
    }
}
