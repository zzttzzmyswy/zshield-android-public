//! Request/response rewriting for the decrypted-connection modifiers (task card §3).
//!
//! The plaintext relay of M2b forwards an allowed request **byte for byte**, which is the right
//! default: re-rendering a head can never be exact, and a filter has no business changing semantics
//! it was not asked to change. Three modifiers are the exception, because changing the bytes *is*
//! what they mean:
//!
//! | Modifier | Effect on the stream |
//! |---|---|
//! | `$removeparam` | the request-target of a subresource is replaced in place; a document is answered with a `302` to the rewritten URL |
//! | `$removeheader` | the named headers are deleted from the request head and from the response head |
//! | `$csp` | a `Content-Security-Policy` header is appended to a document's response head |
//!
//! Everything here works on the *original bytes* and touches only the lines it must, so a head that
//! needs no rewrite is returned unchanged (byte-identical, not re-rendered).
//!
//! # Why a document gets a `302` and a subresource does not
//!
//! A subresource's URL is only visible to the engine, so rewriting it in flight is invisible and
//! exact. A document's URL is in the address bar and in the page's own `<base>`/relative links: a
//! silent rewrite would leave the browser believing it is on a different URL than it is. A redirect
//! makes the change visible and keeps the browser's state consistent, which is what uBO and AdGuard
//! both do.

use crate::http::head::{hostname_of, HttpRequest};
use crate::http::resource::RequestKind;

/// The edits one request needs. Empty edits are never produced; the caller uses `None` for that.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edits {
    /// The URL after `$removeparam`, when the rule set rewrote it.
    pub url: Option<String>,
    /// Request headers to delete (`$removeheader`).
    pub drop_request_headers: Vec<String>,
    /// Response headers to delete (`$removeheader`).
    pub drop_response_headers: Vec<String>,
    /// `Content-Security-Policy` to append to the response head (`$csp`).
    pub csp: Option<String>,
}

impl Edits {
    pub fn is_empty(&self) -> bool {
        self.url.is_none()
            && self.drop_request_headers.is_empty()
            && self.drop_response_headers.is_empty()
            && self.csp.is_none()
    }

    /// True when the response head has to be rewritten.
    pub fn touches_response(&self) -> bool {
        !self.drop_response_headers.is_empty() || self.csp.is_some()
    }
}

/// Where a source of edits comes from.
///
/// A trait rather than a concrete type so the plaintext relay (M2b) can be compiled and tested with
/// no modifier source at all, which is what keeps its behaviour unchanged and its fast path free of
/// an extra branch per byte.
pub trait ModifierSource: Send + Sync + std::fmt::Debug {
    /// The edits for one request, or `None` when no modifier applies.
    fn edits(&self, request: &HttpRequest, kind: RequestKind) -> Option<Edits>;
}

/// Rewrite an allowed HTTP/1.x request head.
///
/// Only two things can change: the request-target in the request line (`$removeparam`) and the
/// presence of named header lines (`$removeheader`). Every other byte — header order, casing, the
/// terminator, and each line's own `CRLF` — is preserved exactly, which is what makes a rewritten
/// head still trustworthy to the origin's own framing.
pub fn rewrite_request_head(head: &[u8], target: Option<&str>, drop: &[String]) -> Vec<u8> {
    if target.is_none() && drop.is_empty() {
        return head.to_vec();
    }
    let Some(end) = find_head_end(head) else {
        // A head we cannot find the end of is not ours to rewrite.
        return head.to_vec();
    };
    let (head_part, terminator) = head.split_at(end);
    let mut out = Vec::with_capacity(head.len() + 32);
    let mut first = true;
    for line in head_lines(head_part) {
        if first {
            first = false;
            match target {
                Some(target) => {
                    // `METHOD SP target SP HTTP/x.y`: replace only the middle token.
                    let bare = strip_cr(line);
                    let mut parts = bare.splitn(3, |byte| *byte == b' ');
                    if let (Some(method), Some(_old), Some(version)) =
                        (parts.next(), parts.next(), parts.next())
                    {
                        out.extend_from_slice(method);
                        out.push(b' ');
                        out.extend_from_slice(target.as_bytes());
                        out.push(b' ');
                        out.extend_from_slice(version);
                        out.extend_from_slice(&line[bare.len()..]);
                        continue;
                    }
                    // Not the shape we expect: leave the line alone rather than corrupt it.
                    out.extend_from_slice(line);
                    continue;
                }
                None => {
                    out.extend_from_slice(line);
                    continue;
                }
            }
        }
        if let Some(name) = header_name(line) {
            if drop.iter().any(|drop| drop.eq_ignore_ascii_case(name)) {
                continue;
            }
        }
        out.extend_from_slice(line);
    }
    // `find_head_end` leaves the terminator in the second slice, so it is appended verbatim.
    out.extend_from_slice(terminator);
    out
}

/// The `Accept-Encoding` a document request is narrowed to.
///
/// A document whose body this core will rewrite has to be decoded locally: the injection changes the
/// length, so the response cannot stay compressed. Offering the origin only the codings this core
/// decodes means the answer is always one it can handle, and the client never sees a body that claims
/// to be encoded when it is not. `gzip` covers essentially every origin; `identity` keeps an origin that
/// only offers nothing compressed working.
pub const DOCUMENT_ACCEPT_ENCODING: &str = "gzip, identity";

/// Replace (or insert) `Accept-Encoding` in a request head, leaving every other byte alone.
///
/// Used only for a document the cosmetic engine will inject into: for every other request the head is
/// forwarded exactly as the client sent it, because narrowing the coding for a response nobody rewrites
/// would be a change with no benefit. Returns the head unchanged when it has no terminator.
pub fn narrow_accept_encoding(head: &[u8]) -> Vec<u8> {
    let Some(end) = find_head_end(head) else {
        return head.to_vec();
    };
    // The last header line arrives without its CRLF: `find_head_end` points *at* the terminator, so
    // `head_part` ends where that header's line terminator would have started. Every line is therefore
    // copied through `ensure_crlf`.
    let (head_part, terminator) = head.split_at(end);
    let mut out = Vec::with_capacity(head.len() + 8);
    let mut written = false;
    for (index, line) in head_lines(head_part).enumerate() {
        if index == 0 {
            out.extend_from_slice(line);
            continue;
        }
        match header_name(line) {
            Some(name) if name.eq_ignore_ascii_case("accept-encoding") => {
                if !written {
                    written = true;
                    out.extend_from_slice(b"Accept-Encoding: ");
                    out.extend_from_slice(DOCUMENT_ACCEPT_ENCODING.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
                continue;
            }
            _ => out.extend_from_slice(line),
        }
        // Only the final header line lacks its CRLF; the ones before it still carry theirs.
        if !out.ends_with(b"\n") {
            out.extend_from_slice(b"\r\n");
        }
    }
    if !written {
        out.extend_from_slice(b"Accept-Encoding: ");
        out.extend_from_slice(DOCUMENT_ACCEPT_ENCODING.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // Every header line above — kept or replaced — ends with its own CRLF, so the terminator's first
    // pair is already accounted for: only the empty line is still missing.
    out.extend_from_slice(&terminator[2..]);
    out
}

/// Rewrite a response head: delete named headers and append a `Content-Security-Policy`.
pub fn rewrite_response_head(head: &[u8], drop: &[String], csp: Option<&str>) -> Vec<u8> {
    if drop.is_empty() && csp.is_none() {
        return head.to_vec();
    }
    let Some(end) = find_head_end(head) else {
        return head.to_vec();
    };
    let (head_part, terminator) = head.split_at(end);
    let mut out = Vec::with_capacity(head.len() + 64);
    let mut first = true;
    // An existing `Content-Security-Policy` is appended to rather than replaced: replacing it would
    // *weaken* a site's own policy, which is the opposite of what a privacy filter should do. The
    // original lines are dropped and one merged line is emitted in their place, so the head never
    // carries the same directive twice.
    let mut existing_csp: Option<String> = None;
    for line in head_lines(head_part) {
        if first {
            first = false;
            out.extend_from_slice(line);
            continue;
        }
        if let Some(name) = header_name(line) {
            if drop.iter().any(|drop| drop.eq_ignore_ascii_case(name)) {
                continue;
            }
            if name.eq_ignore_ascii_case("content-security-policy") && csp.is_some() {
                let value = std::str::from_utf8(strip_cr(line))
                    .unwrap_or("")
                    .split_once(':')
                    .map(|(_, value)| value.trim().to_string())
                    .unwrap_or_default();
                existing_csp = Some(match existing_csp {
                    Some(existing) => format!("{existing},{value}"),
                    None => value,
                });
                continue;
            }
        }
        out.extend_from_slice(line);
    }
    if let Some(csp) = csp {
        // Two policy lists in one header value are both enforced (a browser takes the intersection),
        // so the extra directive can only tighten.
        out.extend_from_slice(b"Content-Security-Policy: ");
        if let Some(existing) = existing_csp.as_deref() {
            if !existing.is_empty() {
                out.extend_from_slice(existing.as_bytes());
                out.push(b',');
            }
        }
        out.extend_from_slice(csp.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(terminator);
    out
}

/// Split a head into lines, each keeping its own line terminator.
fn head_lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = head;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        match rest.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                let (line, tail) = rest.split_at(index + 1);
                rest = tail;
                Some(line)
            }
            None => {
                let line = rest;
                rest = &[];
                Some(line)
            }
        }
    })
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r\n")
        .or_else(|| line.strip_suffix(b"\n"))
        .unwrap_or(line)
}

/// The header name of one head line, or `None` for the status/request line and for junk.
fn header_name(line: &[u8]) -> Option<&str> {
    let bare = strip_cr(line);
    let colon = bare.iter().position(|byte| *byte == b':')?;
    std::str::from_utf8(&bare[..colon]).ok().map(str::trim)
}

/// The `302` a rewritten document navigation is answered with.
///
/// A redirect, not a silent rewrite: the browser has to update its idea of the URL, and a client that
/// follows it re-enters the filter with the clean URL. `Cache-Control: no-store` keeps the redirect
/// from being cached in place of the page.
pub fn redirect_response(location: &str, head_only: bool) -> Vec<u8> {
    // The URL is client-controlled, so it is percent-escaped for the wire: a header value cannot
    // carry a bare CR/LF, and a rule that rewrote a URL containing one would otherwise be a response
    // splitting primitive.
    let location = escape_header_value(location);
    let head = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
         Cache-Control: no-store\r\n\r\n"
    );
    let _ = head_only;
    head.into_bytes()
}

/// Percent-encode everything that cannot appear in a header value.
///
/// Encoding rather than stripping: a stripped byte would silently point the client at a *different*
/// URL than the rule produced, while `%0D` keeps the URL meaning exactly what it says and cannot
/// split the header.
fn escape_header_value(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            // Control characters, space, and DEL: never legal in a header value unencoded.
            0x00..=0x20 | 0x7f => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
            _ => out.push(byte as char),
        }
    }
    out
}

/// The origin-form target of a rewritten absolute URL, or `None` when it has no path.
pub fn target_of(url: &str) -> Option<&str> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    match rest.find('/') {
        Some(index) => Some(&rest[index..]),
        // `https://host?x=1` is legal (an empty path); the target then starts at the query.
        None => rest.find('?').map(|index| &rest[index..]),
    }
}

fn find_head_end(head: &[u8]) -> Option<usize> {
    // The terminator itself is not part of the returned length: `split_at(end)` leaves it in the
    // second slice, so the caller appends it verbatim.
    head.windows(4).position(|window| window == b"\r\n\r\n")
}

/// A streaming response-head rewriter.
///
/// The relay forwards server bytes as they arrive, so a rewrite has to happen while the head is
/// still streaming: bytes are buffered until the head terminator appears, the head is rewritten once,
/// and everything after it passes through untouched. After the first response the rewriter is a
/// passthrough for the rest of the connection unless another response arms it again.
///
/// Armed per *response* rather than per connection because the edits belong to one request: a
/// `$csp` for a document must not leak onto the next response on the same keep-alive connection.
#[derive(Debug, Default)]
pub struct ResponseRewriter {
    /// The head bytes seen so far, while the head is still incomplete.
    pending: Vec<u8>,
    /// Edits for the response currently being rewritten, if any.
    armed: Option<Edits>,
    /// True once the head of the armed response has been emitted.
    done: bool,
}

/// Longest response head the rewriter will buffer while looking for the terminator.
///
/// A head larger than this is not something this app's own responses (or any real one) produce; it is
/// passed through unrewritten rather than buffered without bound.
pub const MAX_HEAD_BYTES: usize = 32 * 1024;

impl ResponseRewriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm the rewriter for the next response head.
    pub fn arm(&mut self, edits: Edits) {
        self.armed = Some(edits);
        self.pending.clear();
        self.done = false;
    }

    /// True when a rewrite is waiting for its response head.
    pub fn is_armed(&self) -> bool {
        self.armed.is_some() && !self.done
    }

    /// Feed server→client bytes, returning what should actually be written.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if self.armed.is_none() {
            return data.to_vec();
        }
        if self.done {
            return data.to_vec();
        }
        self.pending.extend_from_slice(data);
        let Some(end) = find_head_end(&self.pending) else {
            if self.pending.len() > MAX_HEAD_BYTES {
                // Give up on this head and forward what was held back: a response that is not
                // rewritten is a small loss, one that never reaches the client is not.
                self.done = true;
                let pending = std::mem::take(&mut self.pending);
                return pending;
            }
            return Vec::new();
        };
        let head_end = end + 4;
        let head: Vec<u8> = self.pending.drain(..head_end).collect();
        let rest: Vec<u8> = std::mem::take(&mut self.pending);
        let edits = self.armed.take().expect("armed");
        self.done = true;
        let mut out = rewrite_response_head(
            &head,
            &edits.drop_response_headers,
            edits.csp.as_deref(),
        );
        out.extend_from_slice(&rest);
        out
    }

    /// Bytes still held back. Non-empty only while a head is incomplete.
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }
}

/// Whether a request's own authority still matches a rewritten URL.
///
/// A rewrite that changed the host would turn a forwarded request into a proxy request for another
/// site — something no `$removeparam` rule means. The caller drops such a rewrite rather than
/// forwarding it.
pub fn same_authority(request: &HttpRequest, url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    hostname_of(authority) == request.hostname
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::head::{parse, ParseResult, DEFAULT_HEAD_LIMIT};

    fn request(head: &str) -> HttpRequest {
        match parse(head.as_bytes(), DEFAULT_HEAD_LIMIT) {
            (ParseResult::Complete, Some(request)) => request,
            other => panic!("expected a complete request, got {other:?}"),
        }
    }

    #[test]
    fn a_head_with_no_edits_is_returned_verbatim() {
        let head = b"GET /a?b=1 HTTP/1.1\r\nHost: x.example\r\nCookie: a=1\r\n\r\n";
        assert_eq!(rewrite_request_head(head, None, &[]), head.to_vec());
        assert_eq!(rewrite_response_head(head, &[], None), head.to_vec());
    }

    #[test]
    fn the_request_target_is_replaced_and_nothing_else_changes() {
        let head = b"GET /a?utm_source=x&b=1 HTTP/1.1\r\nHost: x.example\r\nCookie: a=1\r\n\r\n";
        let rewritten = rewrite_request_head(head, Some("/a?b=1"), &[]);
        assert_eq!(
            rewritten,
            b"GET /a?b=1 HTTP/1.1\r\nHost: x.example\r\nCookie: a=1\r\n\r\n".to_vec()
        );
        // Exactly the one line changed; the rest is byte-identical.
        let original = String::from_utf8_lossy(head);
        let rewritten_text = String::from_utf8_lossy(&rewritten);
        for line in original.lines().filter(|line| !line.starts_with("GET ")) {
            assert!(rewritten_text.contains(line), "{line} disappeared");
        }
    }

    #[test]
    fn named_request_headers_are_deleted_case_insensitively() {
        let head = b"GET /a HTTP/1.1\r\nHost: x.example\r\nX-Drop: 1\r\nx-keep: 2\r\n\r\n";
        let rewritten = rewrite_request_head(head, None, &["x-drop".to_string()]);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(!text.to_ascii_lowercase().contains("x-drop"));
        assert!(text.contains("x-keep: 2"), "other headers stay");
        assert!(text.starts_with("GET /a HTTP/1.1\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "the terminator is preserved");
    }

    #[test]
    fn named_response_headers_are_deleted() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Test: drop\r\n\r\n";
        let rewritten = rewrite_response_head(head, &["x-test".to_string()], None);
        let text = String::from_utf8_lossy(&rewritten);
        assert!(!text.to_ascii_lowercase().contains("x-test"));
        assert!(text.contains("Content-Type: text/html"));
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_csp_is_appended_to_an_existing_policy_not_in_place_of_it() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\r\n";
        let rewritten = rewrite_response_head(head, &[], Some("script-src 'none'"));
        let text = String::from_utf8_lossy(&rewritten);
        assert_eq!(
            text.matches("Content-Security-Policy:").count(),
            1,
            "one header line: {text}"
        );
        assert!(text.contains("default-src 'self',script-src 'none'"), "{text}");

        // No existing policy: a plain header line.
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let rewritten = rewrite_response_head(head, &[], Some("script-src 'none'"));
        let text = String::from_utf8_lossy(&rewritten);
        assert!(text.contains("Content-Security-Policy: script-src 'none'\r\n"));
    }

    #[test]
    fn a_head_without_its_terminator_is_not_rewritten() {
        // A truncated head is not ours to guess at: forwarding it unchanged is the only safe answer.
        let head = b"GET /a HTTP/1.1\r\nHost: x.example\r\n";
        assert_eq!(
            rewrite_request_head(head, Some("/b"), &["host".to_string()]),
            head.to_vec()
        );
        assert_eq!(
            rewrite_response_head(head, &["host".to_string()], Some("x")),
            head.to_vec()
        );
    }

    #[test]
    fn the_document_accept_encoding_is_narrowed_and_nothing_else_changes() {
        let head = b"GET / HTTP/1.1\r\nHost: x.example\r\nAccept-Encoding: br, gzip, deflate\r\n\
                     Cookie: a=1\r\n\r\n";
        let narrowed = narrow_accept_encoding(head);
        let text = String::from_utf8_lossy(&narrowed);
        assert!(text.contains("Accept-Encoding: gzip, identity\r\n"), "{text}");
        assert!(!text.contains("br"), "{text}");
        assert!(text.contains("Host: x.example\r\n"), "{text}");
        assert!(text.contains("Cookie: a=1\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "the terminator is preserved");
        assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{text}");

        // Two lines are collapsed to one: the client's second line must not re-offer `br`.
        let doubled = b"GET / HTTP/1.1\r\nAccept-Encoding: br\r\nAccept-Encoding: zstd\r\n\r\n";
        let narrowed = String::from_utf8_lossy(&narrow_accept_encoding(doubled)).to_string();
        assert_eq!(narrowed.matches("Accept-Encoding:").count(), 1, "{narrowed}");
        assert!(!narrowed.contains("zstd"), "{narrowed}");

        // No header at all: one is added.
        let bare = b"GET / HTTP/1.1\r\nHost: x.example\r\n\r\n";
        let narrowed = String::from_utf8_lossy(&narrow_accept_encoding(bare)).to_string();
        assert!(narrowed.contains("Accept-Encoding: gzip, identity\r\n"), "{narrowed}");

        // A truncated head is not ours to touch.
        let truncated = b"GET / HTTP/1.1\r\nAccept-Encoding: br\r\n";
        assert_eq!(narrow_accept_encoding(truncated), truncated.to_vec());
    }

    #[test]
    fn a_redirect_carries_a_sanitised_location() {
        let response = redirect_response("https://x.example/a?b=1", false);
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 302 Found\r\n"));
        assert!(text.contains("Location: https://x.example/a?b=1\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.contains("Cache-Control: no-store\r\n"));

        // A CR/LF in the URL cannot become a second header line: it is percent-encoded, which keeps
        // the URL meaning exactly what it says instead of silently pointing somewhere else.
        let response = redirect_response("https://x.example/a\r\nX-Evil: 1", false);
        let text = String::from_utf8_lossy(&response);
        assert_eq!(
            text.matches("\r\n").count(),
            5,
            "exactly the head's own CRLFs: {text:?}"
        );
        assert!(text.contains("Location: https://x.example/a%0D%0AX-Evil:%201\r\n"), "{text:?}");
    }

    #[test]
    fn the_target_of_a_rewritten_url_is_the_origin_form() {
        assert_eq!(target_of("https://x.example/a?b=1"), Some("/a?b=1"));
        assert_eq!(target_of("http://x.example:8080/a"), Some("/a"));
        assert_eq!(target_of("https://x.example?b=1"), Some("?b=1"));
        assert_eq!(target_of("not a url"), None);
        assert_eq!(target_of("https://x.example"), None);
    }

    #[test]
    fn a_rewrite_that_changed_the_host_is_detectable() {
        let req = request("GET /a HTTP/1.1\r\nHost: x.example\r\n\r\n");
        assert!(same_authority(&req, "https://x.example/a?b=1"));
        assert!(same_authority(&req, "https://X.Example:443/a"));
        assert!(
            !same_authority(&req, "https://other.example/a"),
            "a rewrite must not turn a forwarded request into a proxy request for another site"
        );
    }

    #[test]
    fn edits_report_whether_the_response_needs_touching() {
        let mut edits = Edits::default();
        assert!(edits.is_empty());
        assert!(!edits.touches_response());
        edits.url = Some("https://x.example/a".to_string());
        assert!(!edits.is_empty());
        assert!(!edits.touches_response(), "a URL rewrite does not touch the response");
        edits.csp = Some("script-src 'none'".to_string());
        assert!(edits.touches_response());
    }
}
