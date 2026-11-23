//! The plaintext HTTP relay: one TCP connection, many requests, each judged before it is forwarded.
//!
//! # Why the client→server direction is reframed
//!
//! M2a forwarded a connection with `copy_bidirectional`, which cannot see request boundaries.
//! Filtering needs them: a rule matches one request (method + full URL + source + type), and a
//! keep-alive connection carries many. So the client→server direction is parsed request by request
//! (task card §4), while the server→client direction stays a straight copy — the response is not
//! ours to interpret, and buffering it would add latency to every byte.
//!
//! ```text
//! client ─▶ head parse ─▶ decide ──block──▶ synthesized response ─▶ FIN
//!                              │
//!                              └─allow─▶ head bytes verbatim + body ─▶ server
//! server ──────────────────── response bytes ──────────────────────▶ client
//! ```
//!
//! An allowed head is forwarded **byte for byte as it arrived**: rewriting it can only change
//! semantics the filter has no business changing, and a re-rendered head could never be exact.
//!
//! # Degrading instead of guessing
//!
//! Three situations hand the rest of the connection back to a verbatim copy:
//!
//! - the bytes are not HTTP/1.x at all (an HTTP/2 preface, a protocol we do not speak);
//! - the head is unusable — larger than the budget, contradictory framing (`Content-Length` plus
//!   `Transfer-Encoding`, duplicate lengths), or chunked framing we cannot follow;
//! - the client upgrades the connection (`CONNECT`, `Upgrade: h2c`, a WebSocket handshake).
//!
//! A connection that stops being filtered is a small loss; a connection that breaks because of a
//! parser is not acceptable.
//!
//! # Concurrency
//!
//! One task drives both directions through `select!`: reads from the client and from the server are
//! both always pending, so a response flows back while a request is still being uploaded and neither
//! direction can starve the other. Writing a request to the server is itself a `select!` against
//! reading from it, because a server that answers early (a `413`, a rejected upload) can otherwise
//! deadlock a large body. No task is spawned and no lock is held across a write, which keeps the
//! energy profile of M2a (`docs/PERF.md` §10.4) intact.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::http::body::{ChunkProgress, ChunkedScanner};
use crate::http::rewrite::{self, Edits, ModifierSource, ResponseRewriter};
use crate::http::head::{self, BodyKind, HttpRequest, ParseResult};
use crate::http::log::{RequestLog, RequestOutcome};
use crate::http::resource::{self, RequestKind};
use crate::http::response;
use crate::http::responses::{BodyRule, Progress, ResponseTracker};
use crate::http::{decision::FilterDecision, decision::HttpFilter};

/// Copy buffer per direction. Same size as the tunnel's relay buffer, for the same reason.
const COPY_BUFFER: usize = 32 * 1024;

/// Hard ceiling on a request head this relay will buffer, whatever the configuration says.
pub const MAX_HEAD_LIMIT: usize = 64 * 1024;


/// Counters for the HTTP layer, exposed through `statsJson` (task card §5).
#[derive(Debug, Default)]
pub struct HttpStats {
    /// Requests judged since the tunnel started.
    pub requests: AtomicU64,
    /// Requests answered with a synthesized response.
    pub blocked: AtomicU64,
    /// Blocked requests answered with a `$redirect` substitute instead of a plain block.
    pub redirected: AtomicU64,
    /// Connections whose filtering stopped part-way (non-HTTP, upgrade, unusable head).
    pub degraded: AtomicU64,
    /// Requests whose URL `$removeparam` rewrote, on either protocol.
    ///
    /// Shared by the HTTP/1.1 relay and the HTTP/2 one so the number means the same thing whichever
    /// protocol a page happened to negotiate.
    pub rewritten: AtomicU64,
}

/// A snapshot of [`HttpStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HttpSnapshot {
    pub requests: u64,
    pub blocked: u64,
    pub redirected: u64,
    pub degraded: u64,
    pub rewritten: u64,
}

impl HttpStats {
    pub fn snapshot(&self) -> HttpSnapshot {
        let relaxed = Ordering::Relaxed;
        HttpSnapshot {
            requests: self.requests.load(relaxed),
            blocked: self.blocked.load(relaxed),
            redirected: self.redirected.load(relaxed),
            degraded: self.degraded.load(relaxed),
            rewritten: self.rewritten.load(relaxed),
        }
    }
}

/// Everything one relay needs.
///
/// The rule snapshot is taken per request (inside [`HttpFilter`]), so a reload landing mid-connection
/// applies from the next request on, and no single request is judged by two rule sets.
#[derive(Clone)]
pub struct HttpContext {
    pub filter: Arc<HttpFilter>,
    pub log: Arc<RequestLog>,
    pub stats: Arc<HttpStats>,
    /// Buffering budget for one request head.
    pub head_limit: usize,
    /// The scheme this connection speaks, so a request's absolute URL is matched with it.
    ///
    /// `Http` on an M2b plaintext connection, `Https` on a decrypted one
    /// ([`crate::https::mitm`]). Getting it wrong makes every path-level and `$https` rule miss.
    pub scheme: crate::http::head::Scheme,
    /// Counters for cosmetic injection (`statsJson`).
    pub cosmetic: Arc<crate::cosmetic::CosmeticStats>,
    /// How the response body is framed when this code rewrites it.
    ///
    /// Chunked on an HTTP/1.1 connection (a rewritten body has no length to declare) and unframed on
    /// HTTP/2 (the stream's END_STREAM is the end). The value has no effect unless the body is actually
    /// rewritten.
    pub framing: crate::cosmetic::OutFraming,
    /// The decrypted-only modifiers (`$removeparam`, `$removeheader`, `$csp`).
    ///
    /// `None` on a plaintext connection: `$removeparam` would change the URL a user can see in the
    /// clear, `$csp` needs a document that is actually HTTPS-protected to mean anything, and keeping
    /// M2b's byte-for-byte forwarding is what makes its behaviour unchanged by this milestone.
    pub modifiers: Option<Arc<dyn ModifierSource>>,
}

impl HttpContext {
    fn limit(&self) -> usize {
        self.head_limit.clamp(1024, MAX_HEAD_LIMIT)
    }
}

/// How one connection ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayOutcome {
    pub requests: u64,
    pub blocked: u64,
    pub redirected: u64,
    /// Bytes forwarded to the server.
    pub bytes_up: u64,
    /// Bytes forwarded to the client.
    pub bytes_down: u64,
    /// Requests whose URL was rewritten by `$removeparam` and forwarded in place.
    pub rewritten: u64,
    /// The relay stopped filtering and copied the rest verbatim.
    pub degraded: bool,
    /// Both directions ended without an error, so the connection may be closed with a FIN.
    pub clean: bool,
}

/// Relay one plaintext HTTP connection.
///
/// `initial` holds the bytes the sniff phase already read from the client — they are the front of the
/// client→server stream and are parsed like any other bytes.
pub async fn run<C, S>(
    client: &mut C,
    server: &mut S,
    ctx: &HttpContext,
    initial: Vec<u8>,
) -> RelayOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut server_r, mut server_w) = tokio::io::split(server);

    let mut outcome = RelayOutcome::default();
    // Client→server bytes read but not yet written. A partial head stays at the front until more
    // bytes complete it, so nothing is ever forwarded before its decision.
    let mut pending: Vec<u8> = initial;
    let mut body = BodyState::None;
    // What the origin still owes for requests already forwarded. A synthetic response has to wait
    // until nothing is in flight, otherwise it would be written in the middle of a previous body.
    let mut responses = ResponseState::with_framing(ctx.framing);
    // Whether the request just decided is a document this connection will inject into. Set per request
    // (it decides the `Accept-Encoding` of that request only) and false for every other one, which is
    // also what the initial value means.
    let mut cosmetic_document;
    let mut client_done = false;
    let mut server_done = false;
    let mut client_buf = vec![0u8; COPY_BUFFER];
    let mut server_buf = vec![0u8; COPY_BUFFER];

    loop {
        // ---- 1. Body bytes of an already-approved request go straight through ----------------
        if !matches!(body, BodyState::None) {
            match forward_body(
                &mut body,
                &mut pending,
                &mut server_w,
                &mut server_r,
                &mut client_w,
                &mut server_buf,
                &mut outcome,
                &mut responses,
                ctx,
            )
            .await
            {
                Ok(()) => {}
                Err(BodyError::Io(err)) => return finish(outcome, err),
                Err(BodyError::Malformed) => {
                    // A request whose chunked framing we cannot follow. Everything up to the break
                    // has already been forwarded by `forward_body` — dropping it would hand the
                    // server a truncated body (review item 1) — and the rest of the connection can no
                    // longer be reframed, so it becomes an opaque copy.
                    //
                    // Only an *allowed* request can reach here: a blocked one with a body has already
                    // closed the connection above (review item 2).
                    outcome.degraded = true;
                    ctx.stats.degraded.fetch_add(1, Ordering::Relaxed);
                    outcome.clean = passthrough(
                        &pending,
                        &mut client_r,
                        &mut client_w,
                        &mut server_r,
                        &mut server_w,
                        &mut outcome,
                        ctx,
                    )
                    .await;
                    return outcome;
                }
            }
        }

        // ---- 2. A complete request head is decided -------------------------------------------
        if matches!(body, BodyState::None) {
            match head::parse_with_scheme_and_head(&pending, ctx.limit(), ctx.scheme) {
                (ParseResult::Complete, Some(parsed)) => {
                    let request = parsed.request;
                    outcome.requests += 1;
                    ctx.stats.requests.fetch_add(1, Ordering::Relaxed);

                    if request.is_tunnel_request() || request.is_upgrade() {
                        // `CONNECT` / `Upgrade`: an opaque stream from here on.
                        outcome.degraded = true;
                        ctx.stats.degraded.fetch_add(1, Ordering::Relaxed);
                        outcome.clean = passthrough(
                            &pending,
                            &mut client_r,
                            &mut client_w,
                            &mut server_r,
                            &mut server_w,
                            &mut outcome,
                            ctx,
                        )
                        .await;
                        return outcome;
                    }

                    let kind = resource::infer(&request);
                    cosmetic_document = false;
                    let decision = ctx.filter.decide_typed(&request, kind);
                    let log_id = record(ctx, &request, kind, &decision);

                    // The head is consumed either way: after a block, the body (if any) is discarded
                    // below and the connection continues, so a browser's other keep-alive
                    // connections and its subsequent same-connection requests behave normally.
                    let body_kind = request.body_kind();
                    pending.drain(..request.head_len);
                    body = BodyState::from(body_kind);

                    if decision.block {
                        // One line per block so `adb logcat | grep ZShieldCore` shows exactly what
                        // was filtered and by which rule — the acceptance criterion asks for the
                        // blocked request to be visible, and this is the cheapest place to say so.
                        crate::log_msg(
                            "info",
                            &format!(
                                "http blocked {} {} ({}){}",
                                request.method,
                                request.url,
                                kind.as_str(),
                                decision
                                    .matched_rule
                                    .as_deref()
                                    .map(|rule| format!(" by {rule}"))
                                    .unwrap_or_default(),
                            ),
                        );
                        outcome.blocked += 1;
                        // The shared counter is bumped here, not at the end of the relay: a blocked
                        // request is counted the moment it is answered, so the total stays correct
                        // even when the connection is torn down before the relay returns.
                        ctx.stats.blocked.fetch_add(1, Ordering::Relaxed);
                        let mut response = match decision.redirect.as_ref() {
                            Some(redirect) => {
                                outcome.redirected += 1;
                                ctx.stats.redirected.fetch_add(1, Ordering::Relaxed);
                                response::redirected(redirect)
                            }
                            None => response::blocked(kind, &request.url),
                        };
                        // A blocked request that carries a body, or that is waiting for
                        // `100 Continue`, cannot be answered and then kept on the same connection:
                        // the client may never send the body it promised, so the next request would
                        // be read as that body (review item 4). Closing is what RFC 9112 §9.6
                        // prescribes for a server that answers before reading the body.
                        let must_close = request.must_close_when_answered();
                        response.close = must_close;

                        // An earlier request's response may still be on the wire, and a synthetic
                        // response written now would be spliced into that body (review item 6).
                        //
                        // Chosen resolution: **hand the connection to the verbatim copy** and count
                        // it in `httpDegraded`, rather than waiting for the origin. Waiting is the
                        // textbook answer (responses go out in request order), but it needs an
                        // unbounded wait on a socket the filter does not control: an origin that
                        // accepts the request and then stalls would freeze the whole connection
                        // behind a decision we could have made locally. Degrading is bounded, cannot
                        // deadlock, and is visible in the counters.
                        //
                        // The cost is that on a pipelined connection a blocked request after an
                        // unanswered one is let through. Browsers do not pipeline HTTP/1.1 (it was
                        // removed from every engine years ago), so this is a correctness-preserving
                        // fallback for a path that is otherwise unreachable.
                        if !responses.idle() {
                            outcome.degraded = true;
                            ctx.stats.degraded.fetch_add(1, Ordering::Relaxed);
                            outcome.clean = passthrough(
                                &pending,
                                &mut client_r,
                                &mut client_w,
                                &mut server_r,
                                &mut server_w,
                                &mut outcome,
                                ctx,
                            )
                            .await;
                            return outcome;
                        }

                        let bytes = response.render(request.method == "HEAD");
                        if client_w.write_all(&bytes).await.is_err()
                            || client_w.flush().await.is_err()
                        {
                            return finish(outcome, io::Error::from(io::ErrorKind::BrokenPipe));
                        }
                        outcome.bytes_down += bytes.len() as u64;

                        if must_close {
                            // Nothing more may be read from this connection: the blocked body was
                            // never read, and it must not reach the server.
                            let _ = client_w.shutdown().await;
                            let _ = server_w.shutdown().await;
                            outcome.clean = true;
                            return outcome;
                        }
                        // Only a bodiless request gets here (a body always sets `must_close`), so the
                        // connection stays usable and the next request is judged normally.
                        continue;
                    }

                    // Allowed. On a plaintext connection the head is forwarded verbatim, followed by
                    // whatever body bytes already arrived — one write, so a request that came in a
                    // single segment goes out in a single segment. A decrypted connection may have
                    // modifiers that rewrite the request line, drop a header, or annotate the
                    // response head; `edits` is `None` when nothing applies, which is the common case
                    // and is the same code path as before.
                    let edits = ctx
                        .modifiers
                        .as_ref()
                        .and_then(|source| source.edits(&request, kind))
                        .filter(|edits| !edits.is_empty());

                    // A **document navigation** whose URL an `$removeparam` rule rewrote is answered
                    // with a `302` rather than forwarded under a URL the address bar does not show; the
                    // client re-enters the filter with the clean URL, which is what makes the rewrite
                    // visible instead of silently changing what the user is looking at
                    // (`docs/DESIGN.md`, and `http::rewrite`'s module note).
                    //
                    // A **non-navigation** request is rewritten **in place** instead — see the
                    // `rewrite_request_head` call below. Forwarding it under the clean URL is invisible
                    // to the client, and that is deliberate: `response.url` reporting the URL the script
                    // asked for is a client-side observation limit, not a filtering failure. What matters
                    // for a subresource is which URL the origin receives, and in-place forwarding gets
                    // that exactly right on both protocols. A redirect here would also change the
                    // request's observable shape for no filtering benefit, and `redirect: 'error'` /
                    // `redirect: 'manual'` fetches would break.
                    if let Some(edits) = edits.as_ref() {
                        if edits.url.is_some() && kind.is_navigation() {
                            let target = edits.url.as_deref().unwrap_or_default();
                            if !responses.idle() {
                                // A previous response is still on the wire; a redirect written now
                                // would be spliced into its body.
                                outcome.degraded = true;
                                ctx.stats.degraded.fetch_add(1, Ordering::Relaxed);
                                outcome.clean = passthrough(
                                    &pending,
                                    &mut client_r,
                                    &mut client_w,
                                    &mut server_r,
                                    &mut server_w,
                                    &mut outcome,
                                    ctx,
                                )
                                .await;
                                return outcome;
                            }
                            crate::log_msg(
                                "info",
                                &format!("http redirect {} -> {target} (removeparam)", request.url),
                            );
                            outcome.rewritten += 1;
                            ctx.stats.rewritten.fetch_add(1, Ordering::Relaxed);
                            let bytes = rewrite::redirect_response(target, request.method == "HEAD");
                            if client_w.write_all(&bytes).await.is_err() {
                                return finish(outcome, io::Error::from(io::ErrorKind::BrokenPipe));
                            }
                            outcome.bytes_down += bytes.len() as u64;
                            // The body of the original request (if any) is never forwarded; RFC 9112
                            // §9.6 is what lets the connection close instead of reading a body nobody
                            // will use.
                            let _ = client_w.shutdown().await;
                            let _ = server_w.shutdown().await;
                            outcome.clean = true;
                            return outcome;
                        }
                    }

                    responses.expect(if request.method == "HEAD" || request.method == "CONNECT" {
                        BodyRule::Never
                    } else {
                        BodyRule::Framed
                    });
                    // The response head is rewritten only when a modifier asked for it.
                    if let Some(edits) = edits.as_ref() {
                        if edits.touches_response() {
                            responses.arm(edits.clone());
                        }
                    }
                    // Cosmetic injection owns the whole response when the engine has anything for this
                    // document. Only a forwarded document can be injected into: a subresource has no
                    // body this code would rewrite, and asking the engine for its cosmetic resources
                    // walks the hostname-keyed rules for nothing.
                    if kind == RequestKind::Document && request.method != "HEAD" {
                        let plan = ctx.filter.cosmetic_plan(&request);
                        if !plan.is_empty() {
                            // The request's own `$removeheader`/`$csp` edits are folded in, so one layer
                            // owns the response instead of two rewriting the same bytes.
                            responses.arm_cosmetic(plan, edits.as_ref(), log_id);
                            cosmetic_document = true;
                        }
                    }
                    // A response this core may rewrite must be one it can decode: offering the origin
                    // only `gzip, identity` is what makes that true whatever the browser asked for.
                    // Every other request keeps the client's own `Accept-Encoding`.
                    let base_head = if cosmetic_document {
                        rewrite::narrow_accept_encoding(&parsed.head_bytes)
                    } else {
                        parsed.head_bytes.clone()
                    };
                    let mut to_send = match edits.as_ref().and_then(|edits| edits.url.as_deref()) {
                        Some(url) if rewrite::same_authority(&request, url) => {
                            match rewrite::target_of(url) {
                                Some(target) => {
                                    // The in-place rewrite: the origin receives the clean URL. Logged
                                    // because "did the rewrite reach the origin" is the question the
                                    // acceptance criterion asks, and only the outgoing head can answer it.
                                    outcome.rewritten += 1;
                                    ctx.stats.rewritten.fetch_add(1, Ordering::Relaxed);
                                    crate::log_msg(
                                        "info",
                                        &format!("http rewritten {} -> {url} (removeparam)", request.url),
                                    );
                                    rewrite::rewrite_request_head(
                                        &base_head,
                                        Some(target),
                                        &edits.as_ref().expect("edits").drop_request_headers,
                                    )
                                }
                                None => base_head,
                            }
                        }
                        _ => match edits.as_ref() {
                            Some(edits) if !edits.drop_request_headers.is_empty() => {
                                rewrite::rewrite_request_head(
                                    &base_head,
                                    None,
                                    &edits.drop_request_headers,
                                )
                            }
                            _ => base_head,
                        },
                    };
                    if let BodyState::Remaining(remaining) = &mut body {
                        let take = (*remaining).min(pending.len());
                        *remaining -= take;
                        to_send.extend(pending.drain(..take));
                        if *remaining == 0 {
                            body = BodyState::None;
                        }
                    }
                    if let Err(err) = write_pumping(
                        &to_send,
                        &mut server_w,
                        &mut server_r,
                        &mut client_w,
                        &mut server_buf,
                        &mut outcome,
                        &mut responses,
                        ctx,
                    )
                    .await
                    {
                        return finish(outcome, err);
                    }
                    continue;
                }
                (ParseResult::Incomplete, _) => {}
                (ParseResult::NotHttp, _)
                | (ParseResult::TooLarge, _)
                | (ParseResult::Unusable, _)
                | (ParseResult::Complete, None) => {
                    outcome.degraded = true;
                    ctx.stats.degraded.fetch_add(1, Ordering::Relaxed);
                    outcome.clean = passthrough(
                        &pending,
                        &mut client_r,
                        &mut client_w,
                        &mut server_r,
                        &mut server_w,
                        &mut outcome,
                        ctx,
                    )
                    .await;
                    return outcome;
                }
            }
        }

        if client_done && server_done {
            outcome.clean = true;
            return outcome;
        }

        // Either side's FIN prevents further HTTP exchanges. Once every framed response has
        // drained, waiting for the other FIN only retains a task and a FIN_WAIT2/CLOSE_WAIT socket.
        // Unknown or close-delimited responses remain in flight, so their bodies are not cut short.
        if (client_done || server_done)
            && pending.is_empty()
            && matches!(body, BodyState::None)
            && responses.idle()
            && !responses.tracker.is_broken()
        {
            if let Err(err) = client_w.shutdown().await {
                return finish(outcome, err);
            }
            outcome.clean = true;
            return outcome;
        }

        // ---- 3. Wait for whichever direction has something -----------------------------------
        tokio::select! {
            read = client_r.read(&mut client_buf), if !client_done => {
                match read {
                    Ok(0) => {
                        client_done = true;
                        // Propagate the half-close so the server learns no more requests are coming.
                        let _ = server_w.shutdown().await;
                    }
                    Ok(n) => pending.extend_from_slice(&client_buf[..n]),
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return finish(outcome, err),
                }
            }
            read = server_r.read(&mut server_buf), if !server_done => {
                match read {
                    Ok(0) => {
                        server_done = true;
                        // The origin ended the connection. A cosmetic rewriter still armed is waiting
                        // for the end of a body that `Content-Length`/chunked framing did not declare
                        // (or that ended exactly here), so it is finished now — otherwise its terminal
                        // chunk would never be written and the client would hold an unterminated body.
                        let tail = responses.finish_cosmetic();
                        if !tail.bytes.is_empty() && client_w.write_all(&tail.bytes).await.is_err() {
                            return finish(outcome, io::Error::from(io::ErrorKind::BrokenPipe));
                        }
                        let _ = client_w.flush().await;
                        record_cosmetic(ctx, &mut responses);
                        // A truncated body was not closed with a terminal chunk, so the connection's
                        // close is what tells the client the response ended short. Either way the
                        // connection is done; `finish` reports it as unclean when the body was cut.
                        let _ = client_w.shutdown().await;
                        if responses.broke() {
                            return finish(
                                outcome,
                                io::Error::from(io::ErrorKind::ConnectionAborted),
                            );
                        }
                    }
                    Ok(n) => {
                        outcome.bytes_down += n as u64;
                        // The tracker only observes; the bytes go out as they arrived unless a
                        // modifier asked for the response head to be rewritten.
                        responses.observe(&server_buf[..n]);
                        // Sampled before *and* after: `outbound` takes the rewriter when the response
                        // completes in this read, so either side being true means these bytes are ours.
                        let armed = responses.rewriting();
                        let outbound = responses.outbound(&server_buf[..n]);
                        if !outbound.is_empty() && client_w.write_all(&outbound).await.is_err() {
                            return finish(outcome, io::Error::from(io::ErrorKind::BrokenPipe));
                        }
                        // A rewritten body is not the origin's bytes: `WriteHalf` of a TLS session
                        // buffers what does not fit one record, and nothing later on this path would
                        // flush the tail. Without this the response stalls a chunk short of its end.
                        if armed || responses.rewriting() {
                            let _ = client_w.flush().await;
                        }
                        record_cosmetic(ctx, &mut responses);
                        if responses.broke() {
                            // A document whose coding broke after decoding started cannot be completed:
                            // the client would hold half a response. Closing is what tells it so.
                            let _ = client_w.shutdown().await;
                            let _ = server_w.shutdown().await;
                            return finish(outcome, io::Error::from(io::ErrorKind::ConnectionAborted));
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => return finish(outcome, err),
                }
            }
            else => {
                // Neither arm can progress. The server closed for good; a client that only closed
                // its write half would still have been readable above.
                outcome.clean = server_done;
                return outcome;
            }
        }
    }
}

/// Finish a relay that hit an I/O error: the connection is unusable, so it is not clean.
fn finish(outcome: RelayOutcome, err: io::Error) -> RelayOutcome {
    // Client disconnects are normal and far too frequent to log at a level someone reads.
    if err.kind() != io::ErrorKind::BrokenPipe && err.kind() != io::ErrorKind::ConnectionReset {
        crate::log_msg("debug", &format!("http relay ended: {err}"));
    }
    RelayOutcome {
        clean: false,
        ..outcome
    }
}

fn record(
    ctx: &HttpContext,
    request: &HttpRequest,
    kind: RequestKind,
    decision: &FilterDecision,
) -> u64 {
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
    ctx.log.record(
        request,
        kind,
        outcome,
        decision.matched_rule.clone(),
        decision.exception_rule.clone(),
        third_party,
    )
}

/// Mark a document's log entry and bump the counters once its response has been rewritten.
///
/// Called after every server read: the cosmetic rewriter retires itself when the response ends, and this
/// is where that news reaches `statsJson` and the request log (task card §5).
fn record_cosmetic(ctx: &HttpContext, responses: &mut ResponseState) {
    let Some((log_id, report)) = responses.take_finished_report() else {
        return;
    };
    if report.injected {
        ctx.log.mark_cosmetic(log_id);
    }
    crate::log_msg(
        "info",
        &format!(
            "cosmetic: {} specific, {} generic, scriptlet {}, cspMeta {}",
            report.specific, report.generic, report.scriptlet, report.csp_meta
        ),
    );
    ctx.cosmetic.record(report, report.scriptlet);
}

/// Why forwarding a body stopped early.
enum BodyError {
    Io(io::Error),
    /// The chunked framing is broken; the caller must relay verbatim.
    Malformed,
}

/// Forward whatever of `pending` belongs to the current request body.
#[allow(clippy::too_many_arguments)]
async fn forward_body<C, S>(
    body: &mut BodyState,
    pending: &mut Vec<u8>,
    server_w: &mut WriteHalf<S>,
    server_r: &mut ReadHalf<S>,
    client_w: &mut WriteHalf<C>,
    server_buf: &mut [u8],
    outcome: &mut RelayOutcome,
    responses: &mut ResponseState,
    ctx: &HttpContext,
) -> Result<(), BodyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    if pending.is_empty() {
        return Ok(());
    }
    match body {
        BodyState::None => Ok(()),
        BodyState::Remaining(remaining) => {
            let take = (*remaining).min(pending.len());
            let chunk: Vec<u8> = pending.drain(..take).collect();
            *remaining -= take;
            if *remaining == 0 {
                *body = BodyState::None;
            }
            write_pumping(&chunk, server_w, server_r, client_w, server_buf, outcome, responses, ctx)
                .await
                .map_err(BodyError::Io)
        }
        BodyState::Chunked(scanner) => {
            let (consumed, malformed) = match scanner.feed(pending) {
                ChunkProgress::More(consumed) | ChunkProgress::Done(consumed) => (consumed, false),
                ChunkProgress::Malformed(consumed) => (consumed, true),
            };
            // The bytes before the break are still body bytes (review item 1). Dropping them would
            // hand the server a truncated body — silently corrupt, and worse than relaying it — so an
            // allowed request forwards them before the caller switches to a verbatim copy.
            if malformed {
                let chunk: Vec<u8> = pending.drain(..consumed).collect();
                if !chunk.is_empty() {
                    write_pumping(&chunk, server_w, server_r, client_w, server_buf, outcome, responses, ctx)
                        .await
                        .map_err(BodyError::Io)?;
                }
                return Err(BodyError::Malformed);
            }
            let chunk: Vec<u8> = pending.drain(..consumed).collect();
            let done = scanner.is_done();
            if done {
                *body = BodyState::None;
            }
            if chunk.is_empty() {
                return Ok(());
            }
            write_pumping(&chunk, server_w, server_r, client_w, server_buf, outcome, responses, ctx)
                .await
                .map_err(BodyError::Io)
        }
    }
}

/// Write `data` to the server while keeping the server→client direction flowing.
///
/// Needed because a request body can be large: if the server answers early (a `413`, a `401`) and its
/// response fills our buffer while we are still writing, a plain `write_all` deadlocks — the server
/// waits for us to read, we wait for the server to read. Reading while writing removes the cycle.
#[allow(clippy::too_many_arguments)]
async fn write_pumping<C, S>(
    mut data: &[u8],
    server_w: &mut WriteHalf<S>,
    server_r: &mut ReadHalf<S>,
    client_w: &mut WriteHalf<C>,
    server_buf: &mut [u8],
    outcome: &mut RelayOutcome,
    responses: &mut ResponseState,
    ctx: &HttpContext,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    while !data.is_empty() {
        tokio::select! {
            written = server_w.write(data) => {
                let n = written?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }
                outcome.bytes_up += n as u64;
                data = &data[n..];
            }
            read = server_r.read(server_buf) => {
                let n = read?;
                if n == 0 {
                    // The server closed while we were still sending the request.
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                outcome.bytes_down += n as u64;
                responses.observe(&server_buf[..n]);
                let armed = responses.rewriting();
                let outbound = responses.outbound(&server_buf[..n]);
                if !outbound.is_empty() {
                    client_w.write_all(&outbound).await?;
                    // See the main loop: a rewritten body is this core's own chunks, and a buffering
                    // transport only puts the tail on the wire when it is flushed.
                    if armed || responses.rewriting() {
                        client_w.flush().await?;
                    }
                }
                record_cosmetic(ctx, responses);
                if responses.broke() {
                    return Err(io::Error::from(io::ErrorKind::ConnectionAborted));
                }
            }
        }
    }
    Ok(())
}

/// What the origin still owes, and how to tell when it has paid.
///
/// Bundled so the write path carries one reference instead of three: every byte the server sends
/// passes through here, whether it is being copied by the main loop, by `write_pumping` while a
/// request body is still going up, or by `await_response` while a synthetic response waits its turn.
struct ResponseState {
    tracker: ResponseTracker,
    /// Requests forwarded whose response has not completed yet.
    awaiting: u32,
    /// The body rule the in-flight response follows (a `HEAD` response has none).
    rule: BodyRule,
    /// Rewrites the response head of the next response when a modifier asked for it.
    rewriter: ResponseRewriter,
    /// Rewrites the whole response of a document the cosmetic engine has rules for.
    ///
    /// Only one of `rewriter` and `cosmetic` is ever doing work on a response: when the cosmetic
    /// rewriter is armed it also applies the head edits (`$removeheader`, `$csp`) itself, from the
    /// [`crate::cosmetic::Plan`]. If it gives up it replays the origin's own bytes, which then flow
    /// through `rewriter` exactly as they would have without it.
    cosmetic: Option<crate::cosmetic::Rewriter>,
    /// Offset one past the response that the last [`ResponseState::observe`] completed, if any.
    completed_at: Option<usize>,
    /// Set when a rewritten body could not be completed (a corrupt coding), so the connection has to
    /// be closed rather than left half-written.
    broke: bool,
    /// The request-log entry the cosmetic rewriter is working on, marked once the body is done.
    cosmetic_log_id: Option<u64>,
    /// The report of the cosmetic rewriter that finished in the last [`ResponseState::outbound`].
    finished_report: Option<crate::cosmetic::CosmeticReport>,
    /// How a rewritten body is framed (chunked over HTTP/1.1).
    framing: crate::cosmetic::OutFraming,
}

impl Default for ResponseState {
    fn default() -> Self {
        Self::with_framing(crate::cosmetic::OutFraming::Chunked)
    }
}

impl ResponseState {
    fn with_framing(framing: crate::cosmetic::OutFraming) -> Self {
        Self {
            tracker: ResponseTracker::new(),
            awaiting: 0,
            rule: BodyRule::Framed,
            rewriter: ResponseRewriter::new(),
            cosmetic: None,
            completed_at: None,
            broke: false,
            cosmetic_log_id: None,
            finished_report: None,
            framing,
        }
    }

    /// A request has been forwarded; the origin now owes exactly one response for it.
    fn expect(&mut self, rule: BodyRule) {
        self.awaiting += 1;
        self.rule = rule;
    }

    /// Note bytes the server sent, and retire a completed response.
    ///
    /// The tracker observes the **original** bytes, not the rewritten ones: the rewrite never changes
    /// the framing (a header is dropped or added, no body byte moves), and the tracker's state is
    /// derived from the head that actually came off the wire.
    fn observe(&mut self, data: &[u8]) {
        self.completed_at = None;
        if self.tracker.observe(data, self.rule) == Progress::Completed {
            self.awaiting = self.awaiting.saturating_sub(1);
            self.completed_at = self.tracker.completed_at();
        }
    }

    /// Arm the head rewriter for the response this request is about to receive.
    fn arm(&mut self, edits: Edits) {
        if edits.touches_response() {
            self.rewriter.arm(edits);
        }
    }

    /// Arm the cosmetic rewriter for the response this request is about to receive.
    ///
    /// The head edits from the same request are folded in, so one layer owns the whole response instead
    /// of two rewriting the same bytes. `log_id` is the request-log entry the response belongs to: once
    /// the body has been rewritten, that entry is marked `cosmetic: true` (task card §5).
    fn arm_cosmetic(&mut self, plan: crate::cosmetic::Plan, edits: Option<&Edits>, log_id: u64) {
        let mut plan = plan;
        if let Some(edits) = edits {
            plan.drop_response_headers = edits.drop_response_headers.clone();
            plan.extra_csp = edits.csp.clone();
        }
        self.cosmetic = Some(crate::cosmetic::Rewriter::new(plan, self.framing));
        self.cosmetic_log_id = Some(log_id);
    }

    /// The bytes to write to the client for a chunk read from the server.
    fn outbound(&mut self, data: &[u8]) -> Vec<u8> {
        let Some(cosmetic) = self.cosmetic.as_mut() else {
            return self.rewriter.push(data);
        };
        // A read can carry the end of this response and the start of the next one. The injector only
        // ever sees the part that belongs to its own response.
        let split = self.completed_at.unwrap_or(data.len()).min(data.len());
        let (mine, rest) = data.split_at(split);
        let mut out = Vec::new();
        let emitted = cosmetic.push(mine);
        if emitted.broke {
            self.broke = true;
        }
        // Either way the injector has produced the response's head bytes — rewritten for injection, or
        // the origin's own with the request's `$removeheader`/`$csp` edits applied — so the head
        // rewriter must not run over them a second time.
        if emitted.verbatim {
            self.cosmetic = None;
        }
        self.rewriter = ResponseRewriter::new();
        out.extend(emitted.bytes);
        if self.completed_at.is_some() {
            if let Some(mut cosmetic) = self.cosmetic.take() {
                // The tracker only reports a completion for a response whose framing it followed to the
                // end, so reaching here *is* the origin's framing being complete.
                let tail = cosmetic.finish(true);
                if tail.broke || tail.verbatim {
                    // A body that cannot be completed leaves the response inconsistent; the caller
                    // closes the connection (`broke`). `verbatim` here would mean nothing was written,
                    // which `push` has already handled above.
                    self.broke |= tail.broke;
                }
                self.finished_report = Some(cosmetic.report());
                out.extend(tail.bytes);
            }
            if !rest.is_empty() {
                out.extend(self.rewriter.push(rest));
            }
        }
        out
    }

    /// True when a response could not be delivered consistently and the connection must close.
    fn broke(&self) -> bool {
        self.broke
    }

    /// True while a cosmetic rewriter owns the response in flight.
    ///
    /// The driver needs it because a rewritten response is written to the client in chunks this core
    /// produced, not in the origin's: a transport that buffers writes (`tokio-rustls`' session writer
    /// holds a partial record) only hands the tail to the socket when it is flushed, and nothing else
    /// on this path would ever flush — the next write is a different response's, or none at all.
    fn rewriting(&self) -> bool {
        self.cosmetic.is_some()
    }

    /// Finish the cosmetic rewriter if one is still armed, and return its last bytes.
    ///
    /// Called when the origin closes: that is the end of a body the framing headers did not delimit, and
    /// it is also the last chance to write the terminal chunk.
    fn finish_cosmetic(&mut self) -> crate::cosmetic::Emitted {
        let Some(mut cosmetic) = self.cosmetic.take() else {
            return crate::cosmetic::Emitted::default();
        };
        // Reached because the origin closed, which is only a *complete* body if the framing said so —
        // `completed_at` is set exactly when the tracker followed `Content-Length` or chunked framing to
        // its end. A body cut short must not be closed as if it were whole (review item 3).
        let origin_complete = self.completed_at.is_some();
        let tail = cosmetic.finish(origin_complete);
        self.finished_report = Some(cosmetic.report());
        if tail.broke || tail.verbatim {
            // The head was already rewritten and the body cannot be completed: the caller closes the
            // connection (`broke`), which is what tells the client the response is short.
            self.broke |= tail.broke || tail.verbatim;
        }
        self.cosmetic_log_id = self.cosmetic_log_id.take();
        tail
    }

    /// A report for the cosmetic work this response finished, if one finished in the last call.
    fn take_finished_report(&mut self) -> Option<(u64, crate::cosmetic::CosmeticReport)> {
        let id = self.cosmetic_log_id.take()?;
        Some((id, self.finished_report.take()?))
    }

    /// True when the origin owes no response, so a synthetic one can be written now.
    fn idle(&self) -> bool {
        self.awaiting == 0
    }
}

/// Forward `pending`, then copy both directions verbatim until they close.
async fn passthrough<C, S>(
    pending: &[u8],
    client_r: &mut ReadHalf<C>,
    client_w: &mut WriteHalf<C>,
    server_r: &mut ReadHalf<S>,
    server_w: &mut WriteHalf<S>,
    outcome: &mut RelayOutcome,
    ctx: &HttpContext,
) -> bool
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_buf = vec![0u8; COPY_BUFFER];
    // Framing has already been abandoned on this path, so the response tracker is a no-op here.
    if !pending.is_empty() {
        if let Err(err) = write_pumping(
            pending,
            server_w,
            server_r,
            client_w,
            &mut server_buf,
            outcome,
            &mut ResponseState::with_framing(ctx.framing),
            ctx,
        )
        .await
        {
            crate::log_msg("debug", &format!("http passthrough ended: {err}"));
            return false;
        }
    }
    copy_each_way(client_r, client_w, server_r, server_w, outcome).await
}

/// Copy both directions until both close. Returns true when both ended cleanly.
async fn copy_each_way<C, S>(
    client_r: &mut ReadHalf<C>,
    client_w: &mut WriteHalf<C>,
    server_r: &mut ReadHalf<S>,
    server_w: &mut WriteHalf<S>,
    outcome: &mut RelayOutcome,
) -> bool
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf = vec![0u8; COPY_BUFFER];
    let mut server_buf = vec![0u8; COPY_BUFFER];
    let mut client_done = false;
    let mut server_done = false;
    loop {
        if client_done && server_done {
            return true;
        }
        tokio::select! {
            read = client_r.read(&mut client_buf), if !client_done => {
                match read {
                    Ok(0) => {
                        client_done = true;
                        let _ = server_w.shutdown().await;
                    }
                    Ok(n) => {
                        outcome.bytes_up += n as u64;
                        if server_w.write_all(&client_buf[..n]).await.is_err() {
                            return false;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return false,
                }
            }
            read = server_r.read(&mut server_buf), if !server_done => {
                match read {
                    Ok(0) => {
                        server_done = true;
                        let _ = client_w.shutdown().await;
                    }
                    Ok(n) => {
                        outcome.bytes_down += n as u64;
                        if client_w.write_all(&server_buf[..n]).await.is_err() {
                            return false;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return false,
                }
            }
            else => return client_done && server_done,
        }
    }
}

/// What is left of a request body.
enum BodyState {
    /// Between requests: the next bytes are a request head.
    None,
    /// `Content-Length` framing: this many bytes remain.
    Remaining(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked(ChunkedScanner),
}

impl From<BodyKind> for BodyState {
    fn from(kind: BodyKind) -> Self {
        match kind {
            BodyKind::None | BodyKind::Length(0) => BodyState::None,
            BodyKind::Length(len) => BodyState::Remaining(len),
            BodyKind::Chunked => BodyState::Chunked(ChunkedScanner::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(body: &[u8]) -> (ChunkProgress, bool) {
        let mut scanner = ChunkedScanner::new();
        let progress = scanner.feed(body);
        (progress, scanner.is_done())
    }

    #[test]
    fn chunked_framing_is_scanned_incrementally() {
        let body = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        let (progress, done) = feed_all(body);
        assert_eq!(progress, ChunkProgress::Done(body.len()));
        assert!(done);
    }

    #[test]
    fn chunked_split_across_reads_is_still_tracked() {
        // The pathological split points: inside the size line, inside chunk data, inside the CRLF.
        let body = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        for split in 1..body.len() {
            let mut scanner = ChunkedScanner::new();
            match scanner.feed(&body[..split]) {
                ChunkProgress::More(n) => assert_eq!(n, split, "every body byte must be counted"),
                other => panic!("split at {split} finished early: {other:?}"),
            }
            let rest = &body[split..];
            assert_eq!(
                scanner.feed(rest),
                ChunkProgress::Done(rest.len()),
                "split at {split} did not complete"
            );
            assert!(scanner.is_done());
        }
    }

    #[test]
    fn chunk_extensions_and_trailers_are_tolerated() {
        let body = b"4;ext=1\r\nwxyz\r\n0\r\nX-Checksum: 1\r\n\r\n";
        let (progress, done) = feed_all(body);
        assert_eq!(progress, ChunkProgress::Done(body.len()));
        assert!(done);
    }

    #[test]
    fn broken_chunk_framing_is_reported_not_guessed() {
        assert!(matches!(
            feed_all(b"3\r\nabcX\r\n0\r\n\r\n").0,
            ChunkProgress::Malformed(_)
        ));
        assert!(matches!(
            feed_all(b"zz\r\nabc\r\n").0,
            ChunkProgress::Malformed(_)
        ));
        let mut body = vec![b'a'; 64];
        body.extend_from_slice(b"\r\n");
        assert!(matches!(feed_all(&body).0, ChunkProgress::Malformed(_)));
    }

    #[test]
    fn an_empty_chunked_body_ends_immediately() {
        let (progress, done) = feed_all(b"0\r\n\r\n");
        assert_eq!(progress, ChunkProgress::Done(5));
        assert!(done);
    }

    #[test]
    fn body_state_maps_from_the_head() {
        assert!(matches!(BodyState::from(BodyKind::None), BodyState::None));
        assert!(matches!(BodyState::from(BodyKind::Length(0)), BodyState::None));
        assert!(matches!(
            BodyState::from(BodyKind::Length(42)),
            BodyState::Remaining(42)
        ));
        assert!(matches!(
            BodyState::from(BodyKind::Chunked),
            BodyState::Chunked(_)
        ));
    }

    #[test]
    fn the_head_limit_is_clamped() {
        let context = |limit| HttpContext {
            cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
            framing: crate::cosmetic::OutFraming::Chunked,
            filter: Arc::new(HttpFilter::new(adblock::Engine::default())),
            log: Arc::new(RequestLog::new()),
            stats: Arc::new(HttpStats::default()),
            head_limit: limit,
            scheme: crate::http::head::Scheme::Http,
            modifiers: None,
        };
        assert_eq!(context(0).limit(), 1024);
        assert_eq!(context(8192).limit(), 8192);
        assert_eq!(context(usize::MAX).limit(), MAX_HEAD_LIMIT);
    }
}
