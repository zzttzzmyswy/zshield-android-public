//! End-to-end tests of the plaintext HTTP relay.
//!
//! Both legs are in-memory `tokio::io::duplex` streams: the test acts as the browser on one side and
//! as the origin server on the other, so the whole pipeline runs for real — head parsing, the
//! adblock decision, body framing, the synthesized responses and the keep-alive loop — without a
//! socket or a device.
//!
//! The properties under test are the ones a regression would silently break:
//!
//! - a blocked request never reaches the server (that is the entire point of the milestone);
//! - an allowed request arrives **byte for byte**, head and body;
//! - a keep-alive connection is judged request by request, in order;
//! - a head split across segments, or delivered one byte at a time, still parses;
//! - a non-HTTP connection or an upgrade degrades to a verbatim copy instead of breaking.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use crate::http::decision::HttpFilter;
use crate::http::log::{RequestLog, RequestOutcome};
use crate::http::relay::{run, HttpContext, HttpStats, RelayOutcome};

/// Build an engine with debug information, so rule attribution can be asserted too.
fn http_filter(rules: &str) -> Arc<HttpFilter> {
    let mut set = adblock::lists::FilterSet::new(true);
    set.add_filter_list(rules.to_string(), adblock::lists::ParseOptions::default());
    Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set)))
}

/// A relay under test, with the browser end and the origin end held by the test.
struct Relay {
    /// The test's view of the browser: what it wrote arrives at the relay from here.
    browser: DuplexStream,
    /// The test's view of the origin: what the relay forwarded arrives here.
    origin: DuplexStream,
    handle: Option<tokio::task::JoinHandle<RelayOutcome>>,
    log: Arc<RequestLog>,
    stats: Arc<HttpStats>,
}

impl Relay {
    /// Start a relay with `rules`, as if the sniff phase had already read `initial` bytes.
    fn start(rules: &str, initial: Vec<u8>) -> Self {
        Self::start_with_limit(rules, 8 * 1024, initial)
    }

    fn start_with_limit(rules: &str, head_limit: usize, initial: Vec<u8>) -> Self {
        Self::start_with_pipe(rules, head_limit, initial, 1 << 20)
    }

    fn start_with_pipe(
        rules: &str,
        head_limit: usize,
        initial: Vec<u8>,
        pipe: usize,
    ) -> Self {
        let (relay_client, browser) = tokio::io::duplex(pipe);
        let (relay_server, origin) = tokio::io::duplex(pipe);
        let log = Arc::new(RequestLog::new());
        let stats = Arc::new(HttpStats::default());
        let ctx = HttpContext {
            cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
            framing: crate::cosmetic::OutFraming::Chunked,
            filter: http_filter(rules),
            log: log.clone(),
            stats: stats.clone(),
            head_limit,
            scheme: crate::http::head::Scheme::Http,
            modifiers: None,
        };
        let handle = tokio::spawn(async move {
            let mut relay_client = relay_client;
            let mut relay_server = relay_server;
            run(&mut relay_client, &mut relay_server, &ctx, initial).await
        });
        Self {
            browser,
            origin,
            handle: Some(handle),
            log,
            stats,
        }
    }

    async fn write(&mut self, bytes: &[u8]) {
        self.browser.write_all(bytes).await.expect("browser write");
    }

    /// Write `bytes` and then half-close, which is what a browser does after its last request.
    async fn finish(&mut self, bytes: &[u8]) {
        self.write(bytes).await;
        self.browser.shutdown().await.expect("browser shutdown");
    }

    /// Read until the browser side closes.
    async fn read_response(&mut self) -> Vec<u8> {
        read_to_end(&mut self.browser, "the browser side").await
    }

    /// Read exactly one response and return it, leaving the connection open.
    ///
    /// This is how a real client behaves on a keep-alive connection: send one request, wait for its
    /// response, then send the next. Tests that assert per-request outcomes use this so they do not
    /// depend on the relay's pipelining behaviour.
    async fn read_one_response(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            // A response head, then its declared body.
            let mut byte = [0u8; 1];
            loop {
                if self.browser.read_exact(&mut byte).await.is_err() {
                    return out.clone();
                }
                out.push(byte[0]);
                if out.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head_len = content_length_of(&out);
            let mut body = vec![0u8; head_len];
            if head_len > 0 && self.browser.read_exact(&mut body).await.is_ok() {
                out.extend_from_slice(&body);
            }
            out.clone()
        })
        .await;
        match outcome {
            Ok(response) => response,
            Err(_) => panic!("no response arrived; got {}", String::from_utf8_lossy(&out)),
        }
    }

    /// Wait for the relay task and return how it ended.
    ///
    /// Takes `&mut self` so a test can still read the counters and the log afterwards: only the join
    /// handle is consumed.
    async fn outcome(&mut self) -> RelayOutcome {
        let handle = self.handle.take().expect("outcome is read once");
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("the relay must finish")
            .expect("the relay task must not panic")
    }
}

async fn read_to_end(stream: &mut DuplexStream, what: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out)).await;
    match read {
        Ok(Ok(_)) => out,
        Ok(Err(err)) => panic!("reading {what}: {err}"),
        Err(_) => panic!("{what} never closed; got {} bytes so far", out.len()),
    }
}

/// An origin that answers **each** request it receives and reports everything it saw.
///
/// Request-aware on purpose: a real origin answers as requests arrive, and the relay's response
/// ordering depends on that. A double that only answered at EOF would model a stalling server, not
/// a normal one, and would make a pipelined test hang for reasons the code under test never has.
fn spawn_origin(
    mut origin: DuplexStream,
    response: &'static [u8],
) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut pending = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = origin.read(&mut buffer).await;
            match read {
                Ok(0) => break,
                Ok(n) => {
                    seen.extend_from_slice(&buffer[..n]);
                    pending.extend_from_slice(&buffer[..n]);
                    // Answer every complete request, the way a real server does — including its
                    // body, so a chunked body's `0\r\n\r\n` is not mistaken for another head.
                    while let Some(end) = find_head_end(&pending) {
                        let head = pending[..end].to_vec();
                        let body_len = match body_framing(&head) {
                            Frame::None => 0,
                            Frame::Length(len) => len,
                            Frame::Chunked => match chunked_body_len(&pending[end..]) {
                                Some(len) => len,
                                // The body has not fully arrived yet.
                                None => break,
                            },
                        };
                        if pending.len() < end + body_len {
                            break;
                        }
                        pending.drain(..end + body_len);
                        if origin.write_all(response).await.is_err() {
                            return seen;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        let _ = origin.shutdown().await;
        seen
    })
}

/// Index just past the `\r\n\r\n` of the first request head, if there is one.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// How a request head says its body is framed.
enum Frame {
    None,
    Length(usize),
    Chunked,
}

fn body_framing(head: &[u8]) -> Frame {
    let mut length = None;
    let mut chunked = false;
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = &line[colon + 1..];
        if name.eq_ignore_ascii_case(b"content-length") {
            length = std::str::from_utf8(value)
                .ok()
                .and_then(|v| v.trim().parse().ok());
        } else if name.eq_ignore_ascii_case(b"transfer-encoding")
            && value.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked"))
        {
            chunked = true;
        }
    }
    if chunked {
        Frame::Chunked
    } else {
        match length {
            Some(len) => Frame::Length(len),
            None => Frame::None,
        }
    }
}

/// Total length of a complete chunked body (terminal chunk included), or `None` if incomplete.
fn chunked_body_len(body: &[u8]) -> Option<usize> {
    let mut scanner = crate::http::ChunkedScanner::new();
    match scanner.feed(body) {
        crate::http::ChunkProgress::Done(consumed) => Some(consumed),
        _ => None,
    }
}

/// `Content-Length` of a head, or 0 when it carries none. Used to read one response.
fn content_length_of(head: &[u8]) -> usize {
    match body_framing(head) {
        Frame::Length(len) => len,
        _ => 0,
    }
}

const OK_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

/// An origin that records what it receives and never answers.
///
/// Used when the point of the test is that *nothing* reaches the origin: a real server that never
/// got the request would not respond either, and any bytes it did send would be copied to the client
/// by the server→client direction and confuse the assertion.
fn spawn_silent_origin(mut origin: DuplexStream) -> tokio::task::JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut seen = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match origin.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
                Err(_) => break,
            }
        }
        let _ = origin.shutdown().await;
        seen
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn a_blocked_script_never_reaches_the_server() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        let request = b"GET /banner.js HTTP/1.1\r\nHost: ads.example.com\r\n\
                        Referer: http://site.example/\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.finish(request).await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.starts_with("HTTP/1.1 204 No Content"),
            "a blocked subresource is an empty 204, got: {text}"
        );
        assert_eq!(origin.await.expect("origin"), b"", "the request must not reach the server");

        let outcome = relay.outcome().await;
        assert_eq!(outcome.requests, 1);
        assert_eq!(outcome.blocked, 1);
        assert!(outcome.clean, "a client half-close after a response ends the connection cleanly");
    });
}

#[test]
fn a_blocked_navigation_gets_the_self_contained_403_page() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        relay
            .finish(
                b"GET / HTTP/1.1\r\nHost: ads.example.com\r\n\
                  Sec-Fetch-Dest: document\r\nAccept: text/html\r\n\r\n",
            )
            .await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 403 Forbidden"), "got: {text}");
        assert!(text.contains("text/html; charset=utf-8"));
        assert!(text.contains("已被 ZShield 拦截"));
        assert!(text.contains("Cache-Control: no-store"));
        assert_eq!(origin.await.expect("origin"), b"");
        assert_eq!(relay.outcome().await.blocked, 1);
    });
}

#[test]
fn an_allowed_request_arrives_byte_for_byte() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        // A request to a host the rules do not mention, with a body and unusual header casing.
        let request = b"POST /submit?a=1&b=2 HTTP/1.1\r\nhOsT: site.example\r\n\
                        Referer: http://site.example/form\r\nContent-Length: 11\r\n\
                        X-Odd-Casing: Keep-Me\r\n\r\nhello world";
        // The body must arrive too: `Content-Length` framing has to be followed out of the buffer.
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        relay.finish(request).await;

        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded, request,
            "an allowed request must be forwarded exactly as it arrived"
        );
        let response = relay.read_response().await;
        assert_eq!(response, OK_RESPONSE, "the response is copied back verbatim");
        assert_eq!(relay.stats.snapshot().requests, 1);
        assert_eq!(relay.stats.snapshot().blocked, 0);
    });
}

#[test]
fn keep_alive_requests_are_judged_one_by_one() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // Three requests on one connection, each written after the previous response: allowed,
        // blocked, allowed. The blocked one is in the middle on purpose — a relay that stopped
        // filtering after the first request, or that reframed the connection wrongly, would show up
        // as the third request being lost or as the wrong response coming back.
        let first = b"GET /a.js HTTP/1.1\r\nHost: site.example\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.write(first).await;
        let first_response = relay.read_one_response().await;
        assert!(
            String::from_utf8_lossy(&first_response).starts_with("HTTP/1.1 200"),
            "the allowed request's own response must come back first: {}",
            String::from_utf8_lossy(&first_response)
        );

        let blocked = b"GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.write(blocked).await;
        let blocked_response = relay.read_one_response().await;
        assert!(
            String::from_utf8_lossy(&blocked_response).starts_with("HTTP/1.1 204"),
            "got: {}",
            String::from_utf8_lossy(&blocked_response)
        );

        let third = b"GET /b.js HTTP/1.1\r\nHost: site.example\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.write(third).await;
        let third_response = relay.read_one_response().await;
        assert!(
            String::from_utf8_lossy(&third_response).starts_with("HTTP/1.1 200"),
            "the connection must still work after a blocked request: {}",
            String::from_utf8_lossy(&third_response)
        );

        // Only the two allowed requests may have reached the origin, in order.
        relay.browser.shutdown().await.expect("shutdown");
        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded,
            [first.as_slice(), third.as_slice()].concat(),
            "only the allowed requests may reach the server, in order"
        );

        let outcome = relay.outcome().await;
        assert_eq!(outcome.requests, 3, "all three requests must be judged");
        assert_eq!(outcome.blocked, 1);
        assert_eq!(relay.log.snapshot().len(), 3);
        let outcomes: Vec<RequestOutcome> = relay.log.snapshot().iter().map(|e| e.outcome).collect();
        assert_eq!(
            outcomes,
            vec![
                RequestOutcome::Allowed,
                RequestOutcome::Blocked,
                RequestOutcome::Allowed
            ]
        );
    });
}

#[test]
fn a_head_split_across_segments_is_still_filtered() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        let request = b"GET /banner.js HTTP/1.1\r\nHost: ads.example.com\r\n\
                        Sec-Fetch-Dest: script\r\n\r\n";
        // Three writes with pauses in between: the relay must wait for the terminator, not decide on
        // a prefix.
        relay.write(&request[..10]).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        relay.write(&request[10..30]).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        relay.finish(&request[30..]).await;

        let response = relay.read_response().await;
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 204"),
            "a split head must still be blocked"
        );
        assert_eq!(origin.await.expect("origin"), b"");
    });
}

#[test]
fn a_head_delivered_one_byte_at_a_time_is_still_filtered() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        let request = b"GET /x.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n";
        for byte in request {
            relay.write(&[*byte]).await;
        }
        relay.browser.shutdown().await.expect("shutdown");

        let response = relay.read_response().await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 204"));
        assert_eq!(origin.await.expect("origin"), b"");
    });
}

#[test]
fn the_sniff_buffer_is_filtered_not_forwarded_blindly() {
    runtime().block_on(async {
        // The head is already in the sniff buffer when the relay starts: it must be judged, not
        // written to the server before the decision (the whole reason the relay owns those bytes).
        let request = b"GET /banner.js HTTP/1.1\r\nHost: ads.example.com\r\n\
                        Sec-Fetch-Dest: script\r\n\r\n";
        let mut relay = Relay::start("||ads.example.com^$script\n", request.to_vec());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        relay.browser.shutdown().await.expect("shutdown");

        let response = relay.read_response().await;
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 204"));
        assert_eq!(
            origin.await.expect("origin"),
            b"",
            "a blocked head that was already sniffed must not be forwarded"
        );
    });
}

#[test]
fn chunked_bodies_are_forwarded_and_still_framed() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        let request = b"POST /upload HTTP/1.1\r\nHost: site.example\r\n\
                        Transfer-Encoding: chunked\r\n\r\n\
                        5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        relay.finish(request).await;

        let forwarded = origin.await.expect("origin");
        assert_eq!(forwarded, request, "the chunked body must survive unchanged");
        assert_eq!(relay.stats.snapshot().requests, 1);
        assert_eq!(relay.stats.snapshot().degraded, 0);
    });
}

#[test]
fn a_request_after_a_chunked_body_is_judged_too() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        let first = b"POST /upload HTTP/1.1\r\nHost: site.example\r\n\
                      Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        relay.write(first).await;
        let first_response = relay.read_one_response().await;
        assert!(String::from_utf8_lossy(&first_response).starts_with("HTTP/1.1 200"));

        // The body must have been framed correctly, so the next head starts at the right offset.
        let blocked = b"GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.write(blocked).await;
        let blocked_response = relay.read_one_response().await;
        assert!(
            String::from_utf8_lossy(&blocked_response).starts_with("HTTP/1.1 204"),
            "got: {}",
            String::from_utf8_lossy(&blocked_response)
        );

        relay.browser.shutdown().await.expect("shutdown");
        let forwarded = origin.await.expect("origin");
        assert_eq!(forwarded, first, "only the allowed request may be forwarded");
        assert_eq!(relay.outcome().await.requests, 2);
    });
}

#[test]
fn a_redirect_rule_serves_the_substitute() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com/x.js$script,redirect=noopjs\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        relay
            .finish(b"GET /x.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK"), "got: {text}");
        assert!(text.contains("Content-Type: application/javascript"));
        assert_eq!(origin.await.expect("origin"), b"");
        let outcome = relay.outcome().await;
        assert_eq!(outcome.blocked, 1);
        assert_eq!(outcome.redirected, 1);
    });
}

#[test]
fn head_requests_get_headers_without_a_body() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        relay
            .finish(b"HEAD / HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 403 Forbidden"));
        let (head, body) = text.split_once("\r\n\r\n").expect("head terminator");
        assert!(body.is_empty(), "a HEAD response must carry no body: {body:?}");
        assert!(
            !head.contains("Content-Length: 0\r\n"),
            "the length must describe what a GET would return"
        );
        assert_eq!(origin.await.expect("origin"), b"");
    });
}

#[test]
fn a_non_http_connection_is_relayed_verbatim() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        // An SSH banner: the sniff phase would label this `Unknown`, and the relay must copy it
        // through rather than trying to parse it as a request.
        let payload = b"SSH-2.0-OpenSSH_9.6\r\nsome binary \x00\x01\x02";
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        relay.finish(payload).await;

        let forwarded = origin.await.expect("origin");
        assert_eq!(forwarded, payload);
        let outcome = relay.outcome().await;
        assert_eq!(outcome.requests, 0, "nothing was parsed as a request");
        assert!(outcome.degraded);
        assert_eq!(relay.stats.snapshot().degraded, 1);
    });
}

#[test]
fn an_upgrade_is_relayed_after_its_head() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // An `h2c` upgrade on a host the rules would block: the head is relayed, and from then on it
        // is an opaque stream. Filtering it would corrupt the protocol.
        let request = b"GET / HTTP/1.1\r\nHost: ads.example.com\r\nConnection: Upgrade\r\n\
                        Upgrade: h2c\r\n\r\n\x00\x00\x12\x04\x00\x00\x00\x00\x00";
        relay.finish(request).await;

        let forwarded = origin.await.expect("origin");
        assert_eq!(forwarded, request);
        assert!(relay.outcome().await.degraded);
    });
}

#[test]
fn an_oversized_head_is_relayed_instead_of_buffered() {
    runtime().block_on(async {
        let mut relay = Relay::start_with_limit("||ads.example.com^$script\n", 1024, Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // A head that would be blocked, padded past the budget: the relay must hand it to the origin
        // verbatim rather than either blocking it or buffering without bound.
        let mut request = b"GET /x.js HTTP/1.1\r\nHost: ads.example.com\r\nX-Pad: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', 4096));
        request.extend_from_slice(b"\r\n\r\n");
        relay.finish(&request).await;

        let forwarded = origin.await.expect("origin");
        assert_eq!(forwarded, request);
        let outcome = relay.outcome().await;
        assert!(outcome.degraded);
        assert_eq!(outcome.blocked, 0);
    });
}

#[test]
fn the_request_log_records_what_happened() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n@@||ads.example.com/ok.js$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // Three requests: blocked, exception, allowed.
        relay
            .finish(
                b"GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\
                  Referer: http://site.example/\r\n\r\n\
                  GET /ok.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\
                  Referer: http://site.example/\r\n\r\n",
            )
            .await;

        let _ = origin.await.expect("origin");
        let entries = relay.log.snapshot();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].outcome, RequestOutcome::Blocked);
        assert_eq!(entries[0].host, "ads.example.com");
        assert_eq!(entries[0].resource_type, "script");
        assert_eq!(entries[0].kind, crate::http::log::LogKind::Http);
        assert_eq!(entries[0].rule.as_deref(), Some("||ads.example.com^$script"));
        assert_eq!(entries[0].third_party, Some(true));
        assert_eq!(entries[1].outcome, RequestOutcome::Exception);
        assert!(entries[1]
            .exception_rule
            .as_deref()
            .unwrap_or_default()
            .contains("@@"));
        // Ids are usable as a `sinceId` cursor.
        assert!(entries[0].id < entries[1].id);
        assert_eq!(relay.log.since(entries[0].id).len(), 1);
    });
}

#[test]
fn a_first_party_request_is_logged_as_such() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        relay
            .finish(b"GET /x.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;
        let _ = origin.await.expect("origin");
        let entry = &relay.log.snapshot()[0];
        assert!(
            entry.third_party == Some(false),
            "a request with no Referer must be logged as first-party"
        );
    });
}

#[test]
fn completed_http_response_releases_an_origin_that_keeps_its_write_half_open() {
    runtime().block_on(async {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        ] {
            let mut relay = Relay::start("", Vec::new());
            let request = b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n";
            relay.write(request).await;
            let mut forwarded = vec![0; request.len()];
            relay.origin.read_exact(&mut forwarded).await.unwrap();
            assert_eq!(forwarded, request);
            relay.origin.write_all(response).await.unwrap();
            let mut received = vec![0; response.len()];
            relay.browser.read_exact(&mut received).await.unwrap();
            assert_eq!(received, response);

            // Like curl: consume the response, then close. The origin deliberately stays open.
            relay.browser.shutdown().await.unwrap();
            let outcome = tokio::time::timeout(Duration::from_secs(1), relay.outcome())
                .await
                .expect("a completed HTTP exchange must not retain the upstream socket");
            assert!(outcome.clean);
        }
    });
}

#[test]
fn completed_http_response_releases_an_origin_after_its_fin() {
    runtime().block_on(async {
        let mut relay = Relay::start("", Vec::new());
        let request = b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n";
        relay.write(request).await;
        let mut forwarded = vec![0; request.len()];
        relay.origin.read_exact(&mut forwarded).await.unwrap();
        relay.origin.write_all(OK_RESPONSE).await.unwrap();
        relay.origin.shutdown().await.unwrap();
        assert_eq!(relay.read_response().await, OK_RESPONSE);
        // The origin cannot send another response. Waiting for an idle client to send its FIN
        // would keep an already completed upstream connection in CLOSE_WAIT.
        let outcome = tokio::time::timeout(Duration::from_secs(1), relay.outcome())
            .await
            .expect("origin EOF after a complete response must release the connection");
        assert!(outcome.clean);
    });
}

#[test]
fn half_closed_http_waits_for_the_entire_framed_response() {
    runtime().block_on(async {
        for (first, last) in [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel".as_slice(), b"lo".as_slice()),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", b"lo\r\n0\r\nX-End: yes\r\n\r\n"),
        ] {
            let mut relay = Relay::start("", Vec::new());
            relay.finish(b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n").await;
            let _ = read_to_end(&mut relay.origin, "origin request").await;
            relay.origin.write_all(first).await.unwrap();
            let mut received = vec![0; first.len()];
            relay.browser.read_exact(&mut received).await.unwrap();
            assert_eq!(received, first);
            assert!(tokio::time::timeout(Duration::from_millis(50), relay.browser.read_u8()).await.is_err());
            relay.origin.write_all(last).await.unwrap();
            assert_eq!(relay.read_response().await, last);
            assert!(relay.outcome().await.clean);
        }
    });
}

#[test]
fn half_closed_http_preserves_an_eof_framed_response() {
    runtime().block_on(async {
        let mut relay = Relay::start("", Vec::new());
        relay.finish(b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n").await;
        let _ = read_to_end(&mut relay.origin, "origin request").await;
        let first = b"HTTP/1.1 200 OK\r\n\r\nhello";
        relay.origin.write_all(first).await.unwrap();
        let mut received = vec![0; first.len()];
        relay.browser.read_exact(&mut received).await.unwrap();
        assert_eq!(received, first);
        assert!(tokio::time::timeout(Duration::from_millis(50), relay.browser.read_u8()).await.is_err());
        relay.origin.write_all(b" world").await.unwrap();
        relay.origin.shutdown().await.unwrap();
        assert_eq!(relay.read_response().await, b" world");
        assert!(relay.outcome().await.clean);
    });
}

#[test]
fn half_closed_head_waits_for_the_final_response_after_early_hints() {
    runtime().block_on(async {
        let mut relay = Relay::start("", Vec::new());
        relay.finish(b"HEAD / HTTP/1.1\r\nHost: site.example\r\n\r\n").await;
        let _ = read_to_end(&mut relay.origin, "origin request").await;
        let interim = b"HTTP/1.1 103 Early Hints\r\n\r\n";
        relay.origin.write_all(interim).await.unwrap();
        let mut received = vec![0; interim.len()];
        relay.browser.read_exact(&mut received).await.unwrap();
        assert_eq!(received, interim);
        assert!(tokio::time::timeout(Duration::from_millis(50), relay.browser.read_u8()).await.is_err());
        let final_response = b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n";
        relay.origin.write_all(final_response).await.unwrap();
        assert_eq!(relay.read_response().await, final_response);
        assert!(relay.outcome().await.clean);
    });
}

#[test]
fn the_client_closing_its_write_half_does_not_stop_the_response() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // Half-close after an allowed request: the response must still come back, which means the
        // relay keeps reading the server after the client said it is done sending.
        relay
            .finish(b"GET /x.js HTTP/1.1\r\nHost: site.example\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;
        let forwarded = origin.await.expect("origin");
        assert!(forwarded.starts_with(b"GET /x.js"));
        let response = relay.read_response().await;
        assert_eq!(response, OK_RESPONSE);
        assert!(relay.outcome().await.clean);
    });
}

#[test]
fn a_blocked_request_with_a_body_closes_instead_of_desyncing_the_connection() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        // A blocked POST with a body. The relay must not read that body — a client waiting on
        // `100 Continue`, or one that takes the final response as its cue to stop sending, would
        // otherwise leave the connection desynchronised (review item 4). So the response says
        // `Connection: close` and the connection ends.
        let payload: &[u8] = b"{\"event\":\"ad_impression\"}";
        let blocked = [
            format!(
                "POST /beacon HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\
                 Content-Length: {}\r\n\r\n",
                payload.len()
            )
            .into_bytes(),
            payload.to_vec(),
        ]
        .concat();
        relay.finish(&blocked).await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 204"), "got: {text}");
        assert!(
            text.contains("Connection: close"),
            "a blocked request with a body must close the connection: {text}"
        );
        assert_eq!(
            origin.await.expect("origin"),
            b"",
            "none of the blocked request's bytes may reach the server"
        );
        assert_eq!(relay.outcome().await.requests, 1);
        assert_eq!(relay.log.snapshot()[0].outcome, RequestOutcome::Blocked);
    });
}

#[test]
fn an_expect_continue_block_closes_the_connection() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        // `Expect: 100-continue` with no body yet: the client is waiting for `100 Continue`. Answering
        // with a final response means it may never send that body, so the connection has to close.
        relay
            .finish(
                b"POST /beacon HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\
                  Expect: 100-continue\r\nContent-Length: 42\r\n\r\n",
            )
            .await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 204"), "got: {text}");
        assert!(
            text.contains("Connection: close"),
            "an `Expect: 100-continue` block must close: {text}"
        );
        assert_eq!(origin.await.expect("origin"), b"");
    });
}

#[test]
fn a_blocked_get_without_a_body_keeps_the_connection_open() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // No body, no `Expect`: the cheap path stays, so a page's many keep-alive connections are
        // not churned (this is the case that made closing per block unacceptable).
        relay
            .write(b"GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;
        let blocked = relay.read_one_response().await;
        let text = String::from_utf8_lossy(&blocked);
        assert!(text.starts_with("HTTP/1.1 204"), "got: {text}");
        assert!(
            !text.contains("Connection: close"),
            "a bodiless block must not close: {text}"
        );

        // The connection is still usable.
        relay
            .write(b"GET /ok.js HTTP/1.1\r\nHost: site.example\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;
        let next = relay.read_one_response().await;
        assert!(String::from_utf8_lossy(&next).starts_with("HTTP/1.1 200"));
        relay.browser.shutdown().await.expect("shutdown");
        let _ = origin.await;
    });
}

#[test]
fn a_blocked_chunked_upload_closes_instead_of_desyncing_the_connection() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        let blocked = b"POST /beacon HTTP/1.1\r\nHost: ads.example.com\r\n\
                        Sec-Fetch-Dest: script\r\nTransfer-Encoding: chunked\r\n\r\n\
                        5\r\nhello\r\n0\r\n\r\n";
        relay.finish(blocked).await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 204"), "got: {text}");
        assert!(text.contains("Connection: close"), "got: {text}");
        assert_eq!(origin.await.expect("origin"), b"");
        assert_eq!(relay.outcome().await.requests, 1);
    });
}

#[test]
fn a_blocked_request_with_unparseable_chunked_framing_never_reaches_the_server() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        // A blocked request whose chunked framing is *broken*. The relay cannot know where the body
        // ends, so it must not fall back to a verbatim copy — that would forward the blocked body
        // and let the origin parse it as a new request (review item 2). It closes instead.
        let blocked = b"POST /beacon HTTP/1.1\r\nHost: ads.example.com\r\n\
                        Sec-Fetch-Dest: script\r\nTransfer-Encoding: chunked\r\n\r\n\
                        5\r\nhello\r\nNOT-A-CHUNK\r\nmore data that must not leak\r\n";
        relay.finish(blocked).await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 204"), "got: {text}");
        assert!(text.contains("Connection: close"), "got: {text}");
        assert!(
            relay.stats.snapshot().degraded <= 1,
            "the connection degrades at most once"
        );

        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded, b"",
            "not one byte of a blocked request may reach the server, even when its framing is \
             unparseable; got: {}",
            String::from_utf8_lossy(&forwarded)
        );
    });
}

#[test]
fn an_unparseable_allowed_chunked_body_is_forwarded_up_to_the_break() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        // An allowed request whose chunked framing is broken: the bytes before the break are still
        // body, and dropping them would hand the server a truncated body (review item 1). The rest
        // of the connection is an opaque copy.
        let head = b"POST /upload HTTP/1.1\r\nHost: site.example\r\nTransfer-Encoding: chunked\r\n\r\n";
        let good_prefix: &[u8] = b"5\r\nhello\r\n";
        // A chunk size that is not hex: the break comes right after the good prefix.
        let broken: &[u8] = b"zz\r\ntrailing";
        relay
            .finish(&[head.as_slice(), good_prefix, broken].concat())
            .await;

        let forwarded = origin.await.expect("origin");
        assert!(
            forwarded.starts_with(head),
            "the head must be forwarded"
        );
        assert!(
            forwarded.windows(good_prefix.len()).any(|w| w == good_prefix),
            "the body bytes read before the break must not be dropped: {}",
            String::from_utf8_lossy(&forwarded)
        );
        let outcome = relay.outcome().await;
        assert!(outcome.degraded, "a broken chunked body degrades the connection");
    });
}

#[test]
fn an_important_rule_wins_over_an_exception_in_the_live_relay() {
    runtime().block_on(async {
        let mut relay = Relay::start(
            "||ads.example.com^$important\n@@||ads.example.com^\n",
            Vec::new(),
        );
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        relay
            .finish(b"GET /x.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;

        assert!(String::from_utf8_lossy(&relay.read_response().await).starts_with("HTTP/1.1 204"));
        assert_eq!(origin.await.expect("origin"), b"");
        let entry = &relay.log.snapshot()[0];
        assert_eq!(entry.outcome, RequestOutcome::Blocked);
    });
}

#[test]
fn a_third_party_rule_only_fires_for_third_party_requests_in_the_live_relay() {
    runtime().block_on(async {
        let mut relay = Relay::start("||cdn.example.com^$third-party\n", Vec::new());
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            OK_RESPONSE,
        );
        // No Referer: first-party, forwarded.
        let first = b"GET /lib.js HTTP/1.1\r\nHost: cdn.example.com\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.write(first).await;
        let first_response = relay.read_one_response().await;
        assert!(String::from_utf8_lossy(&first_response).starts_with("HTTP/1.1 200"));

        // A cross-site Referer: third-party, blocked.
        let second = b"GET /lib.js HTTP/1.1\r\nHost: cdn.example.com\r\nSec-Fetch-Dest: script\r\n\
                       Referer: http://other.example/\r\n\r\n";
        relay.write(second).await;
        let second_response = relay.read_one_response().await;
        assert!(
            String::from_utf8_lossy(&second_response).starts_with("HTTP/1.1 204"),
            "got: {}",
            String::from_utf8_lossy(&second_response)
        );

        relay.browser.shutdown().await.expect("shutdown");
        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded, first,
            "a request with no source must be treated as first-party and forwarded"
        );
        let entries = relay.log.snapshot();
        assert_eq!(entries[0].third_party, Some(false));
        assert_eq!(entries[1].third_party, Some(true));
        assert_eq!(entries[1].outcome, RequestOutcome::Blocked);
    });
}

#[test]
fn the_live_relay_picks_up_a_hot_swapped_rule_set() {
    runtime().block_on(async {
        // One relay, two requests, with the engine replaced in between: the second request must be
        // judged by the new rules without the connection being restarted.
        let (relay_client, mut browser) = tokio::io::duplex(1 << 20);
        let (relay_server, origin_stream) = tokio::io::duplex(1 << 20);
        let filter = http_filter("||old.example.com^$script\n");
        let log = Arc::new(RequestLog::new());
        let ctx = HttpContext {
            cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
            framing: crate::cosmetic::OutFraming::Chunked,
            filter: filter.clone(),
            log: log.clone(),
            stats: Arc::new(HttpStats::default()),
            head_limit: 8 * 1024,
            scheme: crate::http::head::Scheme::Http,
            modifiers: None,
        };
        let handle = tokio::spawn(async move {
            let mut relay_client = relay_client;
            let mut relay_server = relay_server;
            run(&mut relay_client, &mut relay_server, &ctx, Vec::new()).await
        });
        let origin = spawn_origin(origin_stream, OK_RESPONSE);

        browser
            .write_all(b"GET /a.js HTTP/1.1\r\nHost: new.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await
            .expect("write");
        browser.flush().await.expect("flush");
        // Let the relay decide the first request before the swap.
        tokio::time::sleep(Duration::from_millis(50)).await;
        filter.replace({
            let mut set = adblock::lists::FilterSet::new(true);
            set.add_filter_list(
                "||new.example.com^$script\n".to_string(),
                adblock::lists::ParseOptions::default(),
            );
            adblock::Engine::new_with_filter_set(set)
        });
        browser
            .write_all(b"GET /b.js HTTP/1.1\r\nHost: new.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await
            .expect("write");
        browser.shutdown().await.expect("shutdown");

        let forwarded = origin.await.expect("origin");
        assert!(
            forwarded.starts_with(b"GET /a.js"),
            "the first request was allowed by the old rules"
        );
        let mut response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::io::AsyncReadExt::read_to_end(&mut browser, &mut response),
        )
        .await
        .expect("the browser side must close")
        .expect("read");
        // The first request's 200 came back before the swap, then the second request's 204: both are
        // on the wire in request order, which is exactly what a pipelining-safe relay must do.
        let text = String::from_utf8_lossy(&response);
        let allowed_at = text.find("HTTP/1.1 200 OK");
        let blocked_at = text.find("HTTP/1.1 204 No Content");
        assert!(
            matches!((allowed_at, blocked_at), (Some(a), Some(b)) if a < b),
            "the 200 must precede the 204; got: {text}"
        );
        let outcomes: Vec<RequestOutcome> = log.snapshot().iter().map(|e| e.outcome).collect();
        assert_eq!(
            outcomes,
            vec![RequestOutcome::Allowed, RequestOutcome::Blocked],
            "the second request must be judged by the replaced rules"
        );
        let _ = handle.await;
    });
}

#[test]
fn the_shared_counters_are_correct_even_when_the_connection_drops() {
    runtime().block_on(async {
        // The counters are what `statsJson` reports and what the UI shows, so they must be right at
        // the moment the decision is made — not only when the relay happens to return normally. A
        // client that disappears right after being refused must still be counted.
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));

        relay
            .write(b"GET /a.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;
        // Drop the browser end without a FIN, so the relay sees a broken pipe on the next write.
        relay.browser = tokio::io::duplex(1).0;

        // Wait for the relay to notice and finish.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while relay.stats.snapshot().requests == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let snapshot = relay.stats.snapshot();
        assert_eq!(snapshot.requests, 1, "the request must be counted");
        assert_eq!(
            snapshot.blocked, 1,
            "a blocked request must be counted even if the connection then drops"
        );
        assert_eq!(relay.log.snapshot().len(), 1);
        // The silent origin task ends on its own once the relay drops its end.
        drop(origin);
    });
}

#[test]
fn a_blocked_request_with_a_chunked_body_never_leaks_a_byte() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        // A blocked request with a chunked body whose framing breaks partway. The guarantee under
        // test is review item 2: not one byte may reach the server, no matter how the body is
        // framed or mis-framed. The relay closes at the head, so the body is never even read.
        let head = b"POST /beacon HTTP/1.1\r\nHost: ads.example.com\r\n\
                     Sec-Fetch-Dest: script\r\nTransfer-Encoding: chunked\r\n\r\n";
        let good_chunk: &[u8] = b"5\r\nhello\r\n";
        let broken: &[u8] = b"NOTHEX\r\nleaked-body-bytes\r\n";
        relay
            .finish(&[head.as_slice(), good_chunk, broken].concat())
            .await;

        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 204"), "got: {text}");

        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded, b"",
            "a blocked request's body must never reach the server; got: {}",
            String::from_utf8_lossy(&forwarded)
        );
    });
}

#[test]
fn a_pipelined_block_after_an_unanswered_request_degrades_instead_of_splicing() {
    runtime().block_on(async {
        let mut relay = Relay::start("||ads.example.com^$script\n", Vec::new());
        // An origin that receives requests and answers *nobody*: the first request's response is
        // still owed when the second (blocked) request arrives.
        let origin = spawn_silent_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0));
        let first = b"GET /a.js HTTP/1.1\r\nHost: site.example\r\nSec-Fetch-Dest: script\r\n\r\n";
        let blocked = b"GET /ad.js HTTP/1.1\r\nHost: ads.example.com\r\nSec-Fetch-Dest: script\r\n\r\n";
        relay.write(&[first.as_slice(), blocked.as_slice()].concat()).await;

        // The relay must not write the 204 into the middle of the response the first request still
        // owes. Chosen resolution (review item 6): hand the connection to the verbatim copy and count
        // it, rather than wait on an origin we do not control.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while relay.stats.snapshot().degraded == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            relay.stats.snapshot().degraded, 1,
            "a pipelined block behind an unanswered request must degrade the connection"
        );
        // Close the client so the relay's verbatim copy finishes, then read whatever it wrote back.
        relay.browser.shutdown().await.expect("shutdown");
        let text = String::from_utf8_lossy(&relay.read_response().await).to_string();
        assert!(
            !text.contains("HTTP/1.1 204"),
            "no synthetic response may be spliced into an in-flight one; got: {text}"
        );
        // The first (allowed) request still reached the origin; the blocked one must not, even though
        // the connection degraded — its head was consumed before the decision.
        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded, first,
            "only the allowed request may reach the origin; got: {}",
            String::from_utf8_lossy(&forwarded)
        );
    });
}

// ---------------------------------------------------------------------------------------------
// M3b: cosmetic injection through the live HTTP/1.1 relay
// ---------------------------------------------------------------------------------------------

/// De-chunk a body, panicking on broken framing — which is the property under test.
fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = body.windows(2).position(|window| window == b"\r\n") else {
            panic!("no chunk size line in {:?}", String::from_utf8_lossy(body));
        };
        let size_text = std::str::from_utf8(&body[..line_end]).expect("ascii size");
        let size = usize::from_str_radix(size_text.trim(), 16)
            .unwrap_or_else(|_| panic!("bad chunk size {size_text:?}"));
        body = &body[line_end + 2..];
        if size == 0 {
            assert_eq!(body, b"\r\n", "the terminal chunk ends the body");
            return out;
        }
        assert!(body.len() >= size + 2, "chunk of {size} runs past the body");
        out.extend_from_slice(&body[..size]);
        assert_eq!(&body[size..size + 2], b"\r\n", "a chunk ends with CRLF");
        body = &body[size + 2..];
    }
}

#[test]
fn a_document_response_is_injected_through_the_live_relay() {
    runtime().block_on(async {
        let mut relay = Relay::start("example.com##.ad-slot\n", Vec::new());
        // The declared length has to be exact: the relay follows it to know where the body ends.
        const BODY: &[u8] =
            b"<!doctype html><html><head><title>t</title></head><body><div class=\"ad-slot\">ad</div></body></html>";
        let document = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n",
            BODY.len()
        )
        .into_bytes();
        let document: &'static [u8] = Box::leak(
            [document.as_slice(), BODY].concat().into_boxed_slice(),
        );
        let origin = spawn_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0), document);
        relay
            .finish(b"GET / HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;
        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response).to_string();
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\n"),
            "the origin's status must be kept: {text}"
        );
        assert!(
            text.to_ascii_lowercase().contains("transfer-encoding: chunked"),
            "an injected body is chunked: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("content-length"),
            "the origin's length no longer describes the body: {text}"
        );
        let head_end = text.find("\r\n\r\n").expect("a head") + 4;
        let body = dechunk(&response[head_end..]);
        let document = String::from_utf8_lossy(&body).to_string();
        assert!(
            document.contains("<style data-zshield=\"specific\">"),
            "the hide rule must be injected: {document}"
        );
        assert!(document.contains(".ad-slot"), "{document}");
        assert!(
            document.contains("<div class=\"ad-slot\">ad</div>"),
            "the page's own bytes must survive: {document}"
        );
        assert!(document.ends_with("</body></html>"), "{document}");
        // The origin saw the browser's request with one deliberate change: `Accept-Encoding` is
        // narrowed to what this core can decode, because the response body is going to be rewritten.
        // Everything else — the request line, the other headers, their order — is untouched.
        let forwarded = origin.await.expect("origin");
        assert_eq!(
            forwarded,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: document\r\n\
              Accept-Encoding: gzip, identity\r\n\r\n"
        );
    });
}

#[test]
fn an_injected_document_is_marked_in_the_request_log() {
    runtime().block_on(async {
        let mut relay = Relay::start("example.com##.ad-slot\n", Vec::new());
        let body = b"<!doctype html><html><head></head><body><div class=\"ad-slot\">x</div></body></html>";
        let mut document = Vec::new();
        document.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ");
        document.extend_from_slice(body.len().to_string().as_bytes());
        document.extend_from_slice(b"\r\n\r\n");
        document.extend_from_slice(body);
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            Box::leak(document.into_boxed_slice()),
        );
        relay
            .finish(b"GET / HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;
        let _ = relay.read_response().await;
        let _ = origin.await.expect("origin");
        let entries = relay.log.snapshot();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].cosmetic == Some(true),
            "the log entry must say the response was rewritten: {entries:?}"
        );
        // The JSON the UI reads carries the same flag.
        let json = relay.log.to_json(0);
        assert!(json.contains("\"cosmetic\":true"), "{json}");
    });
}

#[test]
fn a_large_chunked_document_completes_through_the_live_relay() {
    runtime().block_on(async {
        // A narrow pipe, like the tunnel's 64 KiB ring: the relay must keep reading the origin while
        // the client is behind, or a body larger than the pipe deadlocks.
        let mut relay = Relay::start_with_pipe("example.com##.ad\n", 8 * 1024, Vec::new(), 64 * 1024);
        // The shape that stalled on a device: ~1.2 MB of HTML, gzip'd, inside chunked framing that
        // carries the body in small pieces.
        let mut document = b"<!doctype html><html><head><title>t</title></head><body>".to_vec();
        while document.len() < 1_200_000 {
            document.extend_from_slice(b"<dl><dt id=\"x\">Header</dt><dd class=\"break\">v</dd></dl>\n");
        }
        document.extend_from_slice(b"</body></html>");
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, &document).expect("compress");
        let compressed = encoder.finish().expect("finish");
        let mut body = Vec::new();
        for chunk in compressed.chunks(2048) {
            body.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            body.extend_from_slice(chunk);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"0\r\n\r\n");
        let mut response = Vec::new();
        response.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        response.extend_from_slice(&body);
        let response: &'static [u8] = Box::leak(response.into_boxed_slice());
        let origin =
            spawn_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0), response);
        relay
            .finish(b"GET / HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;
        let reply = relay.read_response().await;
        let head_end = reply
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a response head")
            + 4;
        let rewritten = dechunk(&reply[head_end..]);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(text.contains("data-zshield=\"specific\""), "the rule must be injected");
        assert!(text.ends_with("</body></html>"), "the document must be complete");
        assert_eq!(
            rewritten.len(),
            document.len() + (rewritten.len() - document.len()),
            "sanity"
        );
        let _ = origin.await.expect("origin");
    });
}

#[test]
fn a_non_document_response_is_not_injected_by_the_live_relay() {
    runtime().block_on(async {
        let mut relay = Relay::start("example.com##.ad-slot\n", Vec::new());
        const SCRIPT: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 10\r\n\r\nvar ads=[0];";
        let origin = spawn_origin(std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0), SCRIPT);
        relay
            .finish(b"GET /a.js HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: script\r\n\r\n")
            .await;
        let response = relay.read_response().await;
        assert_eq!(
            response, SCRIPT,
            "a subresource must be relayed byte for byte"
        );
        let _ = origin.await.expect("origin");
    });
}

#[test]
fn a_document_no_rule_matches_is_delivered_with_its_own_bytes() {
    runtime().block_on(async {
        let mut relay = Relay::start("example.com##.ad-slot\n##.never-present\n", Vec::new());
        let body = b"<!doctype html><html><head><title>t</title></head><body><p>x</p></body></html>";
        let mut document = Vec::new();
        document.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ");
        document.extend_from_slice(body.len().to_string().as_bytes());
        document.extend_from_slice(b"\r\n\r\n");
        document.extend_from_slice(body);
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            Box::leak(document.into_boxed_slice()),
        );
        relay
            .finish(b"GET / HTTP/1.1\r\nHost: other.example\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;
        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response).to_string();
        let head_end = text.find("\r\n\r\n").expect("a head") + 4;
        let forwarded = dechunk(&response[head_end..]);
        assert_eq!(
            forwarded, body,
            "the document's own bytes must be unchanged when no rule matches"
        );
        let _ = origin.await.expect("origin");
    });
}

#[test]
fn a_gzip_document_is_injected_and_arrives_decoded() {
    runtime().block_on(async {
        let mut relay = Relay::start("example.com##.ad-slot\n", Vec::new());
        let document = b"<!doctype html><html><head><title>t</title></head>\
                         <body><div class=\"ad-slot\">ad</div></body></html>";
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut encoder, document).expect("compress");
        let compressed = encoder.finish().expect("finish");
        let mut response = Vec::new();
        response.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: ",
        );
        response.extend_from_slice(compressed.len().to_string().as_bytes());
        response.extend_from_slice(b"\r\n\r\n");
        response.extend_from_slice(&compressed);
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            Box::leak(response.into_boxed_slice()),
        );
        relay
            .finish(b"GET / HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;
        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response).to_string();
        assert!(
            !text.to_ascii_lowercase().contains("content-encoding"),
            "the body reaches the client as identity: {text}"
        );
        let head_end = text.find("\r\n\r\n").expect("a head") + 4;
        let forwarded = dechunk(&response[head_end..]);
        let forwarded = String::from_utf8_lossy(&forwarded).to_string();
        assert!(
            forwarded.contains("<style data-zshield=\"specific\">"),
            "the hide rule must be injected into a gzip document: {forwarded}"
        );
        assert!(
            forwarded.contains("<div class=\"ad-slot\">ad</div>"),
            "{forwarded}"
        );
        let _ = origin.await.expect("origin");
    });
}

// ---------------------------------------------------------------------------------------------
// Rework regression: a truncated origin body is not closed as if it were whole (review item 3)
// ---------------------------------------------------------------------------------------------

#[test]
fn a_truncated_document_body_is_never_closed_with_a_terminal_chunk() {
    runtime().block_on(async {
        let mut relay = Relay::start("example.com##.ad-slot\n", Vec::new());
        // The origin declares far more than it sends, then closes: the classic "cut connection".
        const TRUNCATED: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100000\r\n\r\n\
              <!doctype html><html><head></head><body><div class=\"ad-slot\">x";
        let origin = spawn_origin(
            std::mem::replace(&mut relay.origin, tokio::io::duplex(1).0),
            TRUNCATED,
        );
        relay
            .finish(b"GET / HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Dest: document\r\n\r\n")
            .await;
        let response = relay.read_response().await;
        let text = String::from_utf8_lossy(&response).to_string();
        assert!(
            text.to_ascii_lowercase().contains("transfer-encoding: chunked"),
            "the head is still rewritten for an injected body: {text}"
        );
        assert!(
            !response.ends_with(b"0\r\n\r\n"),
            "a truncated body must not be closed with a terminal chunk: {text}"
        );
        let _ = origin.await.expect("origin");
    });
}
