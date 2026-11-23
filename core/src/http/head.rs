//! Incremental parsing of an HTTP/1.x request head.
//!
//! The tunnel sees a client stream as a byte sequence with no framing, so the parser has to work on
//! whatever has arrived so far and say "I need more" instead of failing. It produces exactly the
//! fields the filter decision needs — method, full URL (`Host` + request target), `Referer`,
//! `Sec-Fetch-Dest`, `Accept`, `Content-Length`/`Transfer-Encoding` for body framing — and drops
//! everything else.
//!
//! Three rules keep this from ever being the reason a connection breaks:
//!
//! 1. **Bounded.** A head that does not fit in the caller's budget (8 KiB by default) is rejected as
//!    [`ParseResult::TooLarge`] and the connection is relayed verbatim (task card §4: 超长头拒绝).
//! 2. **Strict about the request line, lenient about everything else.** A malformed header line is
//!    skipped rather than fatal: real clients send junk, and a header we do not read cannot change a
//!    decision we do make.
//! 3. **Pipelining-aware.** [`HttpRequest::head_len`] is the exact byte length of the head, so the
//!    caller can hand the remainder of the buffer to the body without re-parsing it.
//!
//! `CONNECT` and requests with `Connection: upgrade` / an `Upgrade` header are recognised and
//! reported ([`HttpRequest::is_tunnel_request`] / [`HttpRequest::is_upgrade`]) so the relay can step
//! out of the way: those become an opaque byte stream after the head and must not be reframed.

/// HTTP version from the request line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }
}

/// One parsed request head.
///
/// `url` is already the absolute-form URL the engine matches against: `scheme://host[:port]` +
/// origin-form target. `host` keeps the authority as the client sent it (port included) while
/// `hostname` is the lowercased name without the port, which is what domain rules and the logs use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Upper-case method as sent (`GET`, `POST`, ...).
    pub method: String,
    /// Origin-form request target (`/path?query`), or an absolute URI when a proxy client sent one.
    pub target: String,
    pub version: Version,
    /// Absolute-form URL used for rule matching.
    pub url: String,
    /// Authority as sent, e.g. `ads.example.com:8080`.
    pub host: String,
    /// Lowercased hostname without the port, e.g. `ads.example.com`.
    pub hostname: String,
    /// `Referer`, resolved to an absolute URL when it was usable.
    pub referer: Option<String>,
    /// `Sec-Fetch-Dest`, lowercased.
    pub fetch_dest: Option<String>,
    /// `Sec-Fetch-Site`, lowercased (`cross-site`, `same-origin`, `same-site`, `none`).
    ///
    /// Fetch Metadata (W3C), sent by every current browser. `$popup` is defined in terms of these three
    /// fields rather than of an out-of-band window handle, which a TLS-tunnel filter cannot see —
    /// see [`crate::https::extras::is_popup_navigation`].
    pub fetch_site: Option<String>,
    /// `Sec-Fetch-User` as sent; `?1` is the user-activated form.
    pub fetch_user: Option<String>,
    /// `Accept`, as sent.
    pub accept: Option<String>,
    /// `Content-Length`, when present and well-formed.
    pub content_length: Option<usize>,
    /// True when the body is chunked (no `Content-Length` framing applies).
    pub chunked: bool,
    /// True when the client asked to upgrade the connection (`Upgrade` header or `CONNECT`).
    pub upgrade: bool,
    /// `Expect: 100-continue`: the client is waiting for a `100 Continue` before sending the body.
    ///
    /// The relay has to know this because answering such a request with a final response means the
    /// client may never send that body — so the connection cannot stay open (review item 4).
    pub expect_continue: bool,
    /// Byte length of the head, terminator included; the body starts here.
    pub head_len: usize,
}

impl HttpRequest {
    /// `CONNECT host:port HTTP/1.1`: the rest of the connection is an opaque tunnel.
    pub fn is_tunnel_request(&self) -> bool {
        self.method == "CONNECT"
    }

    /// The connection stops being HTTP after this head (`Upgrade: h2c`, `Upgrade: websocket`).
    pub fn is_upgrade(&self) -> bool {
        self.upgrade
    }

    /// The URL a decision should be made against: absolute, with the port kept only when it is not
    /// the scheme default (a `:80` in the URL would make `||host^` rules miss).
    pub fn matched_url(&self) -> &str {
        &self.url
    }

    /// True when answering this request ends the connection: it carries a body we would have to
    /// read and discard, or it is an `Expect: 100-continue` request whose body may never arrive.
    ///
    /// Used only for blocked requests. Reading a body we are not going to forward keeps the
    /// connection usable, but it deadlocks against a client that is waiting for `100 Continue` and
    /// against one that takes the final response as its cue to stop sending — so those are answered
    /// with `Connection: close` instead.
    pub fn must_close_when_answered(&self) -> bool {
        // `Content-Length: 0` is a body kind of `Length(0)` but there are no bytes to read, so it is
        // not a reason to close.
        self.expect_continue
            || match self.body_kind() {
                BodyKind::None | BodyKind::Length(0) => false,
                BodyKind::Length(_) | BodyKind::Chunked => true,
            }
    }

    /// Body framing for this request.
    pub fn body_kind(&self) -> BodyKind {
        if self.chunked {
            BodyKind::Chunked
        } else if let Some(len) = self.content_length {
            BodyKind::Length(len)
        } else {
            BodyKind::None
        }
    }
}

/// How the request body is framed on the wire (`RFC 9112` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    None,
    Length(usize),
    Chunked,
}

/// Why a buffer could not be turned into a request head yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseResult {
    /// A complete head was parsed.
    Complete,
    /// More bytes are needed. The caller should keep buffering up to its budget.
    Incomplete,
    /// The buffer does not look like an HTTP/1.x request at all (an HTTP/2 preface, TLS, a binary
    /// protocol, a server-first greeting). The caller must relay verbatim.
    NotHttp,
    /// The head exceeded the caller's budget.
    TooLarge,
    /// The head parsed but its body framing is contradictory or unparseable.
    ///
    /// `Content-Length` that is not plain decimal (`+5`, `0x5`), two differing lengths, or
    /// `Transfer-Encoding` with a coding we cannot frame. RFC 9112 §6.2/§6.3 leave the recipient a
    /// choice; this core relays the connection verbatim, because guessing a length is exactly the
    /// request-smuggling shape the rule exists to reject (review item 7).
    Unusable,
}

/// Parse one request head out of the front of `buf`.
///
/// `limit` is the caller's buffering budget. The function never reads past `limit`.
pub fn parse(buf: &[u8], limit: usize) -> (ParseResult, Option<HttpRequest>) {
    parse_with_scheme(buf, limit, Scheme::Http)
}

/// The scheme a request came in on.
///
/// The request line of an `origin-form` target (`GET /path HTTP/1.1` plus a `Host` header) carries no
/// scheme, so the parser has to be told which one the connection is. It matters: the rule engine
/// matches the absolute URL, and a decrypted HTTPS request judged as `http://…` would miss every
/// `$https`-scoped rule and every rule anchored past the host — which is how a path-level rule on a
/// decrypted connection silently failed on the first device test of M3a.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    /// The default port of this scheme, which is what `authority_for_url` strips.
    fn default_port(self) -> &'static str {
        match self {
            Scheme::Http => ":80",
            Scheme::Https => ":443",
        }
    }
}

/// A parsed head plus the exact bytes it occupied, so a relay can forward them verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHead {
    pub request: HttpRequest,
    /// `buf[..head_bytes.len()]`: the head as the client sent it, terminator included.
    pub head_bytes: Vec<u8>,
}

/// Like [`parse`], but also returns the head bytes.
///
/// The relay must forward the request exactly as it arrived (rewriting headers would change
/// semantics the filter has no business changing), and re-rendering a parsed head can never be
/// byte-exact — so the original slice is handed back instead.
pub fn parse_with_head(buf: &[u8], limit: usize) -> (ParseResult, Option<ParsedHead>) {
    parse_with_scheme_and_head(buf, limit, Scheme::Http)
}

/// Like [`parse`], for a connection whose scheme is not plain HTTP.
pub fn parse_with_scheme(buf: &[u8], limit: usize, scheme: Scheme) -> (ParseResult, Option<HttpRequest>) {
    let (result, parsed) = parse_with_scheme_and_head(buf, limit, scheme);
    (result, parsed.map(|parsed| parsed.request))
}

/// Like [`parse_with_head`], for a connection whose scheme is not plain HTTP.
pub fn parse_with_scheme_and_head(
    buf: &[u8],
    limit: usize,
    scheme: Scheme,
) -> (ParseResult, Option<ParsedHead>) {
    let (result, request) = parse_inner(buf, limit, scheme);
    match request {
        Some(request) => {
            let head_bytes = buf[..request.head_len].to_vec();
            (
                result,
                Some(ParsedHead {
                    request,
                    head_bytes,
                }),
            )
        }
        None => (result, None),
    }
}

fn parse_inner(buf: &[u8], limit: usize, scheme: Scheme) -> (ParseResult, Option<HttpRequest>) {
    if buf.is_empty() {
        return (ParseResult::Incomplete, None);
    }
    // The HTTP/2 connection preface (RFC 9113 §3.4) and anything else binary is not ours.
    if !starts_like_http(buf) {
        // A prefix of a valid method is not "not HTTP" yet: `GE` could still become `GET`.
        if is_method_prefix(buf) && buf.len() < MAX_METHOD_LEN {
            return (ParseResult::Incomplete, None);
        }
        return (ParseResult::NotHttp, None);
    }

    // The request line is decided at its first newline, not at the end of the head (review item 5).
    // Without this, a client speaking a protocol that happens to start like a method — `get key\r\n`
    // from the memcached text protocol, an HTTP/0.9 `GET /\r\n`, or a request whose head never
    // terminates — would sit in `Incomplete` until the budget ran out while the server sent nothing,
    // which is a regression from M2a (where it was relayed verbatim after one segment).
    match first_line(buf) {
        FirstLine::Pending => {
            if buf.len() >= limit {
                return (ParseResult::TooLarge, None);
            }
            return (ParseResult::Incomplete, None);
        }
        FirstLine::Unsupported => return (ParseResult::NotHttp, None),
        FirstLine::Parsed => {}
    }

    let Some(head_end) = find_head_end(buf) else {
        // The request line is HTTP/1.x but the head is not complete yet. Failing here on size, not
        // on patience, is what makes an endless header stream finite: the connection is then
        // relayed verbatim (task card §4).
        if buf.len() >= limit {
            return (ParseResult::TooLarge, None);
        }
        return (ParseResult::Incomplete, None);
    };
    let head_len = head_end + HEAD_TERMINATOR.len();
    if head_len > limit {
        return (ParseResult::TooLarge, None);
    }

    let head = &buf[..head_end];
    let mut lines = head.split(|byte| *byte == b'\n').map(strip_cr);

    let Some(request_line) = lines.next() else {
        return (ParseResult::NotHttp, None);
    };
    let Some((method, target, version)) = parse_request_line(request_line) else {
        return (ParseResult::NotHttp, None);
    };

    let mut host: Option<String> = None;
    let mut referer: Option<String> = None;
    let mut fetch_dest: Option<String> = None;
    let mut fetch_site: Option<String> = None;
    let mut fetch_user: Option<String> = None;
    let mut accept: Option<String> = None;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut upgrade = false;
    let mut has_transfer_encoding = false;
    let mut expect_continue = false;

    for line in lines {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            // Not a header line. Clients do send junk; a header we cannot read cannot change a
            // decision, so it is dropped instead of failing the whole request.
            continue;
        };
        let name = &line[..colon];
        let value = trim(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"host") {
            if host.is_none() {
                host = Some(String::from_utf8_lossy(value).into_owned());
            }
        } else if name.eq_ignore_ascii_case(b"referer") {
            if referer.is_none() {
                referer = Some(String::from_utf8_lossy(value).into_owned());
            }
        } else if name.eq_ignore_ascii_case(b"sec-fetch-dest") {
            fetch_dest = Some(String::from_utf8_lossy(value).to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case(b"sec-fetch-site") {
            fetch_site = Some(String::from_utf8_lossy(value).to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case(b"sec-fetch-user") {
            fetch_user = Some(String::from_utf8_lossy(value).into_owned());
        } else if name.eq_ignore_ascii_case(b"accept") {
            if accept.is_none() {
                accept = Some(String::from_utf8_lossy(value).into_owned());
            }
        } else if name.eq_ignore_ascii_case(b"content-length") {
            // `usize::from_str` accepts a leading `+`, but `Content-Length: +5` is not a
            // (RFC 9110 §8.6) decimal number and a server that rejects it would disagree with us
            // about where the body starts — so only plain digits are accepted (review item 7).
            // A duplicate with a different value is the same smuggling shape and is refused.
            let Some(parsed) = parse_decimal(value) else {
                return (ParseResult::Unusable, None);
            };
            match content_length {
                None => content_length = Some(parsed),
                // RFC 9110 §8.6 allows a repeated `Content-Length` when every value is identical.
                Some(existing) if existing == parsed => {}
                Some(_) => return (ParseResult::Unusable, None),
            }
        } else if name.eq_ignore_ascii_case(b"expect") {
            // `Expect: 100-continue` (RFC 9110 §10.1.1). Case-insensitive, and a list is legal.
            if contains_ignore_ascii_case(value, b"100-continue") {
                expect_continue = true;
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            has_transfer_encoding = true;
            if contains_ignore_ascii_case(value, b"chunked") {
                chunked = true;
            }
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            upgrade = true;
        }
    }

    // RFC 9112 §6.3: a message carrying both `Transfer-Encoding` and `Content-Length` must be
    // handled as an error (the spec names the smuggling risk). §6.1: a `Transfer-Encoding` whose
    // final coding is not `chunked` leaves the body length unknowable for a server. Both are
    // relayed verbatim rather than guessed at.
    if chunked && content_length.is_some() {
        return (ParseResult::Unusable, None);
    }
    if has_transfer_encoding && !chunked {
        return (ParseResult::Unusable, None);
    }

    // The URL. An absolute-form target (proxy-style) is used as-is; otherwise the authority comes
    // from `Host`, which HTTP/1.1 requires.
    let (host, hostname, url) = match split_absolute(target) {
        Some((absolute_scheme, authority, path)) => {
            // An absolute-form target names its own scheme. On a decrypted connection the transport
            // decides: a request that arrived over TLS is `https` whatever the target claims, and the
            // engine must see the scheme the client is actually speaking.
            let _ = absolute_scheme;
            let authority = String::from_utf8_lossy(authority).into_owned();
            let name = hostname_of(&authority);
            let url = format!(
                "{}://{}{}",
                scheme.as_str(),
                String::from_utf8_lossy(authority.as_bytes()),
                String::from_utf8_lossy(path)
            );
            (authority, name, url)
        }
        None => {
            let Some(host) = host else {
                // No authority anywhere: not a request we can form a URL for (an HTTP/1.0 request
                // without `Host`). Relay it verbatim.
                return (ParseResult::NotHttp, None);
            };
            let host = host.trim().to_string();
            if host.is_empty() {
                return (ParseResult::NotHttp, None);
            }
            let name = hostname_of(&host);
            if name.is_empty() {
                return (ParseResult::NotHttp, None);
            }
            let target = String::from_utf8_lossy(target).into_owned();
            let target = if target.starts_with('/') {
                target
            } else if target == "*" {
                // `OPTIONS *`: there is no path to match, but the URL still has to be well formed.
                "/".to_string()
            } else if method == "CONNECT" {
                // `CONNECT host:port` uses authority-form. The relay degrades a CONNECT to a
                // verbatim copy anyway, so only a well-formed URL is needed here — the request is
                // never matched against a rule.
                "/".to_string()
            } else {
                return (ParseResult::NotHttp, None);
            };
            // Default ports are stripped: `http://host:80/x` and `http://host/x` are the same URL,
            // and the rule `||host^` must match both.
            let url = format!(
                "{}://{}{}",
                scheme.as_str(),
                authority_for_url(&host, scheme),
                target
            );
            (host, name, url)
        }
    };
    if hostname.is_empty() {
        return (ParseResult::NotHttp, None);
    }
    if method == "CONNECT" {
        upgrade = true;
    }

    let request = HttpRequest {
        method,
        target: String::from_utf8_lossy(target).into_owned(),
        version,
        url,
        host,
        hostname,
        referer: referer.and_then(|raw| absolute_referer(&raw)),
        fetch_dest,
        fetch_site,
        fetch_user,
        accept,
        content_length,
        chunked,
        upgrade,
        expect_continue,
        head_len,
    };
    (ParseResult::Complete, Some(request))
}

/// The terminator that ends an HTTP/1.x head.
const HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Longest method token worth waiting for (`PATCH` + margin).
const MAX_METHOD_LEN: usize = 16;

/// Default buffering budget for one request head.
pub const DEFAULT_HEAD_LIMIT: usize = 8 * 1024;

/// Methods the parser accepts. Anything else is a protocol we do not speak, not a broken request.
const METHODS: [&[u8]; 9] = [
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"CONNECT",
    b"OPTIONS",
    b"TRACE",
    b"PATCH",
];

/// True when `buf` begins with a complete method token followed by a space.
fn starts_like_http(buf: &[u8]) -> bool {
    for method in METHODS {
        if buf.len() > method.len()
            && buf[..method.len()].eq_ignore_ascii_case(method)
            && buf[method.len()] == b' '
        {
            return true;
        }
    }
    false
}

/// True when `buf` is an HTTP/1.x request or a prefix that could still become one.
///
/// This is the "is this connection ours to filter" question, asked before buffering anything: a
/// `GET ` prefix is HTTP, TLS is not, and neither is an SSH banner. A buffer too short to tell is
/// treated as HTTP (it may still become a request), which is what keeps a request split across the
/// first two TCP segments filterable.
pub fn looks_like_request(buf: &[u8]) -> bool {
    if buf.is_empty() {
        // Nothing arrived before the sniff deadline. Pretending this is HTTP costs one read; the
        // relay degrades to a verbatim copy as soon as the bytes arrive and are not a request.
        return true;
    }
    starts_like_http(buf) || is_method_prefix(buf)
}

/// True when `buf` could still become `METHOD ` — so the caller keeps buffering instead of
/// concluding the connection is not HTTP. This is what makes a request split across the first two
/// TCP segments parse correctly.
fn is_method_prefix(buf: &[u8]) -> bool {
    let len = buf.len().min(MAX_METHOD_LEN);
    METHODS.iter().any(|method| {
        len <= method.len() && method[..len].eq_ignore_ascii_case(&buf[..len])
    })
}

/// What the first line of the buffer amounts to.
enum FirstLine {
    /// No newline yet: the request line is still arriving.
    Pending,
    /// The line ended and its version is not `HTTP/1.0` or `HTTP/1.1`.
    Unsupported,
    /// The line ended and its version is HTTP/1.x.
    Parsed,
}

/// Classify the first line without waiting for the whole head.
///
/// The version token sits at the end of the request line, so the line ending is enough to decide
/// whether this connection speaks a version we can filter — no need to wait for `\r\n\r\n`.
fn first_line(buf: &[u8]) -> FirstLine {
    let Some(newline) = buf.iter().position(|byte| *byte == b'\n') else {
        return FirstLine::Pending;
    };
    match parse_request_line(strip_cr(&buf[..newline])) {
        Some(_) => FirstLine::Parsed,
        None => FirstLine::Unsupported,
    }
}

/// Parse a `Content-Length` value: digits only, no sign, no whitespace inside.
///
/// `str::parse::<usize>` would accept `+5` and leading zeros galore; `+5` is not a valid
/// `Content-Length` and a server rejecting it while we accept it means the two sides disagree about
/// where the next request starts (review item 7).
fn parse_decimal(value: &[u8]) -> Option<usize> {
    let value = trim(value);
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    // Reject absurd lengths early rather than overflow; `usize::MAX` digits are 20 characters.
    if value.len() > 19 {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse::<usize>().ok()
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEAD_TERMINATOR.len() {
        return None;
    }
    buf.windows(HEAD_TERMINATOR.len())
        .position(|window| window == HEAD_TERMINATOR)
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim(mut value: &[u8]) -> &[u8] {
    while let Some((first, rest)) = value.split_first() {
        if first.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = value.split_last() {
        if last.is_ascii_whitespace() {
            value = rest;
        } else {
            break;
        }
    }
    value
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window.eq_ignore_ascii_case(needle))
}

/// Split `METHOD SP target SP HTTP/x.y`. Returns the method (upper-cased) and version.
fn parse_request_line(line: &[u8]) -> Option<(String, &[u8], Version)> {
    let mut parts = line.splitn(3, |byte| *byte == b' ');
    let method = parts.next()?;
    let target = trim(parts.next()?);
    let version = trim(parts.next()?);
    if target.is_empty() {
        return None;
    }
    let version = match version {
        b"HTTP/1.1" => Version::Http11,
        b"HTTP/1.0" => Version::Http10,
        // HTTP/0.9 and HTTP/2+ never appear in this form; treating them as not-HTTP is what lets
        // the relay fall through to a verbatim copy.
        _ => return None,
    };    let method = String::from_utf8_lossy(method).to_ascii_uppercase();
    Some((method, target, version))
}

/// Split an absolute-form target into `(scheme, authority, path)`. `None` for origin-form targets.
fn split_absolute(target: &[u8]) -> Option<(&'static str, &[u8], &[u8])> {
    let (scheme, scheme_len) = if target
        .get(..7)
        .map(|prefix| prefix.eq_ignore_ascii_case(b"http://"))
        .unwrap_or(false)
    {
        ("http", 7)
    } else if target
        .get(..8)
        .map(|prefix| prefix.eq_ignore_ascii_case(b"https://"))
        .unwrap_or(false)
    {
        ("https", 8)
    } else {
        return None;
    };
    let rest = &target[scheme_len..];
    let (authority, path) = match rest.iter().position(|byte| *byte == b'/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, &b"/"[..]),
    };
    if authority.is_empty() {
        return None;
    }
    Some((scheme, authority, path))
}

/// The hostname of an authority: lowercased, port and IPv6 brackets removed.
pub fn hostname_of(authority: &str) -> String {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]:8080`.
        return match rest.split_once(']') {
            Some((inner, _)) => inner.to_ascii_lowercase(),
            None => authority.to_ascii_lowercase(),
        };
    }
    match authority.rsplit_once(':') {
        Some((head, port))
            if !head.is_empty() && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            head.to_ascii_lowercase()
        }
        _ => authority.to_ascii_lowercase(),
    }
}

/// Drop the scheme's default port from an authority, so `host:443` and `host` produce the same URL.
fn authority_for_url(authority: &str, scheme: Scheme) -> &str {
    authority
        .strip_suffix(scheme.default_port())
        .filter(|head| !head.is_empty() && !head.ends_with(':'))
        .unwrap_or(authority)
}

/// Turn a `Referer` header value into an absolute URL, or `None` when it carries no usable source.
///
/// A referrer that is not `http(s)` (a `file:` page, a `chrome-extension:` page, `about:blank`)
/// carries no first-/third-party meaning for a network rule, and pretending it is third-party would
/// block perfectly good requests, so it is dropped (task card §2: 来源缺失时按首方请求处理).
pub fn absolute_referer(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let lowered = raw.get(..8).map(|p| p.to_ascii_lowercase()).unwrap_or_default();
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        return Some(raw.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(buf: &[u8]) -> HttpRequest {
        match parse(buf, DEFAULT_HEAD_LIMIT) {
            (ParseResult::Complete, Some(request)) => request,
            other => panic!("expected a complete request, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_minimal_request() {
        let request = complete(b"GET /index.html HTTP/1.1\r\nHost: ads.example.com\r\n\r\n");
        assert_eq!(request.method, "GET");
        assert_eq!(request.version, Version::Http11);
        assert_eq!(request.host, "ads.example.com");
        assert_eq!(request.hostname, "ads.example.com");
        assert_eq!(request.url, "http://ads.example.com/index.html");
        assert_eq!(request.target, "/index.html");
        assert_eq!(request.referer, None);
        assert_eq!(request.body_kind(), BodyKind::None);
        assert_eq!(request.head_len, 51);
        assert!(!request.is_upgrade());
    }

    #[test]
    fn one_pixel_and_the_rest_of_the_headers_are_ignored() {
        let raw = b"POST /collect?v=1 HTTP/1.1\r\n\
                    Host: track.example.com:8080\r\n\
                    User-Agent: Mozilla/5.0\r\n\
                    Referer: https://news.example.com/article\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 42\r\n\
                    \r\n";
        let request = complete(raw);
        assert_eq!(request.host, "track.example.com:8080");
        assert_eq!(request.hostname, "track.example.com");
        // The port is kept in the URL because it is not the scheme default.
        assert_eq!(request.url, "http://track.example.com:8080/collect?v=1");
        assert_eq!(
            request.referer.as_deref(),
            Some("https://news.example.com/article")
        );
        assert_eq!(request.body_kind(), BodyKind::Length(42));
        let _ = raw;
    }

    #[test]
    fn the_default_port_is_not_part_of_the_matched_url() {
        // `||ads.example.com^` has to match whether or not the client wrote `:80`.
        assert_eq!(
            complete(b"GET /a HTTP/1.1\r\nHost: ads.example.com:80\r\n\r\n").url,
            "http://ads.example.com/a"
        );
        assert_eq!(
            complete(b"GET /a HTTP/1.1\r\nHost: ads.example.com:8080\r\n\r\n").url,
            "http://ads.example.com:8080/a"
        );
    }

    #[test]
    fn an_empty_path_becomes_a_slash() {
        let request = complete(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(request.url, "http://example.com/");
    }

    #[test]
    fn absolute_form_targets_are_used_as_sent() {
        // A proxy-style client (or an `http://` URL reachable through one) names the whole URL.
        let request = complete(
            b"GET http://cdn.example.com/ads.js?x=1 HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n",
        );
        assert_eq!(request.url, "http://cdn.example.com/ads.js?x=1");
        assert_eq!(request.hostname, "cdn.example.com");
        assert_eq!(request.target, "http://cdn.example.com/ads.js?x=1");
    }

    #[test]
    fn resource_type_hints_are_kept() {
        let request = complete(
            b"GET /ads.js HTTP/1.1\r\n\
              Host: ads.example.com\r\n\
              Sec-Fetch-Dest: SCRIPT\r\n\
              Accept: */*\r\n\
              \r\n",
        );
        assert_eq!(request.fetch_dest.as_deref(), Some("script"));
        assert_eq!(request.accept.as_deref(), Some("*/*"));
    }

    #[test]
    fn a_head_split_across_segments_parses_once_complete() {
        let raw = b"GET /split/ads.js HTTP/1.1\r\nHost: ads.example.com\r\nReferer: http://site.example/\r\n\r\n";
        // Every proper prefix must ask for more, never fail and never produce a request.
        for split in 1..raw.len() {
            match parse(&raw[..split], DEFAULT_HEAD_LIMIT) {
                (ParseResult::Incomplete, None) => {}
                other => panic!("split at {split} gave {other:?}"),
            }
        }
        let request = complete(raw);
        assert_eq!(request.url, "http://ads.example.com/split/ads.js");
        assert_eq!(request.referer.as_deref(), Some("http://site.example/"));
    }

    #[test]
    fn one_byte_at_a_time_still_parses() {
        // The pathological case: a head delivered in single-byte segments (a tiny MSS, or a slow
        // script). It must parse once the terminator arrives.
        let raw = b"GET /byte/ads.js HTTP/1.1\r\nHost: ads.example.com\r\n\r\n";
        let mut buffer = Vec::new();
        for (index, byte) in raw.iter().enumerate() {
            buffer.push(*byte);
            let (result, request) = parse(&buffer, DEFAULT_HEAD_LIMIT);
            if index + 1 < raw.len() {
                assert_eq!(result, ParseResult::Incomplete, "at byte {}", index + 1);
                assert!(request.is_none());
            } else {
                assert_eq!(result, ParseResult::Complete);
                assert_eq!(
                    request.expect("request").url,
                    "http://ads.example.com/byte/ads.js"
                );
            }
        }
    }

    #[test]
    fn an_oversized_head_is_rejected_instead_of_buffered() {
        let mut raw = b"GET /big HTTP/1.1\r\nHost: big.example.com\r\n".to_vec();
        // A header line far beyond the budget, with no terminator in sight.
        raw.extend_from_slice(b"X-Padding: ");
        raw.extend(std::iter::repeat_n(b'a', 4096));
        let limit = 1024;
        let (result, request) = parse(&raw, limit);
        assert_eq!(result, ParseResult::TooLarge);
        assert!(request.is_none());

        // A complete head that is merely bigger than the budget is rejected the same way, so a
        // client cannot slip a huge head past by sending the terminator.
        let mut complete_head = b"GET /big HTTP/1.1\r\nHost: big.example.com\r\nX-Padding: ".to_vec();
        complete_head.extend(std::iter::repeat_n(b'a', 4096));
        complete_head.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse(&complete_head, limit).0, ParseResult::TooLarge);
    }

    #[test]
    fn non_http_first_bytes_are_reported_as_such() {
        // The HTTP/2 connection preface in cleartext (h2c prior knowledge).
        assert_eq!(
            parse(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", DEFAULT_HEAD_LIMIT).0,
            ParseResult::NotHttp
        );
        // A TLS ClientHello, an SSH banner, and a binary protocol.
        assert_eq!(parse(&[0x16, 0x03, 0x01, 0x00, 0x50], DEFAULT_HEAD_LIMIT).0, ParseResult::NotHttp);
        assert_eq!(parse(b"SSH-2.0-OpenSSH\r\n", DEFAULT_HEAD_LIMIT).0, ParseResult::NotHttp);
        assert_eq!(parse(&[0x00, 0x01, 0x02], DEFAULT_HEAD_LIMIT).0, ParseResult::NotHttp);
    }

    #[test]
    fn connect_and_upgrade_are_flagged_for_the_relay() {
        let connect = complete(b"CONNECT ads.example.com:443 HTTP/1.1\r\nHost: ads.example.com:443\r\n\r\n");
        assert!(connect.is_tunnel_request());
        assert!(connect.is_upgrade());

        let h2c = complete(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        );
        assert!(h2c.is_upgrade());
        assert!(!h2c.is_tunnel_request());

        let websocket = complete(
            b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n",
        );
        assert!(websocket.is_upgrade());
    }

    #[test]
    fn body_framing_is_read_faithfully() {
        assert_eq!(
            complete(b"POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: 0\r\n\r\n").body_kind(),
            BodyKind::Length(0)
        );
        assert_eq!(
            complete(
                b"POST /a HTTP/1.1\r\nHost: x.example\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .body_kind(),
            BodyKind::Chunked
        );
        // Contradictory framing is a smuggling shape: the head is refused and relayed verbatim.
        assert_eq!(
            parse(
                b"POST /a HTTP/1.1\r\nHost: x.example\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
                DEFAULT_HEAD_LIMIT
            )
            .0,
            ParseResult::Unusable
        );
        assert_eq!(
            parse(
                b"POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                DEFAULT_HEAD_LIMIT
            )
            .0,
            ParseResult::Unusable
        );
        // Two identical lengths are legal and mean one length.
        let same = parse(
            b"POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
            DEFAULT_HEAD_LIMIT,
        );
        assert_eq!(same.0, ParseResult::Complete);
        assert_eq!(same.1.expect("request").body_kind(), BodyKind::Length(5));
    }

    #[test]
    fn content_length_must_be_plain_decimal() {
        // Rust's `parse` accepts `+5`; a server would not, and the two sides disagreeing about the
        // body length is a smuggling primitive (review item 7).
        for bad in ["+5", "-5", " 5x", "0x5", "5.0", "٥"] {
            let head = format!("POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: {bad}\r\n\r\n");
            assert_eq!(
                parse(head.as_bytes(), DEFAULT_HEAD_LIMIT).0,
                ParseResult::Unusable,
                "Content-Length: {bad} must not parse"
            );
        }
        // The legal spellings, leading zeros included, still work.
        for (raw, want) in [("0", 0usize), ("42", 42), ("0042", 42)] {
            let head = format!("POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: {raw}\r\n\r\n");
            let (result, request) = parse(head.as_bytes(), DEFAULT_HEAD_LIMIT);
            assert_eq!(result, ParseResult::Complete, "Content-Length: {raw}");
            assert_eq!(request.expect("request").body_kind(), BodyKind::Length(want));
        }
    }

    #[test]
    fn a_non_http_version_is_rejected_at_the_first_newline() {
        // Review item 5: these used to sit in `Incomplete` until the budget ran out, which hung the
        // client, while M2a relayed them verbatim after one segment.
        for line in [
            &b"get key\r\n"[..],       // memcached text protocol
            &b"GET /\r\n"[..],          // HTTP/0.9
            &b"GET / HTTP/2.0\r\n"[..], // an h2c-ish line that is not HTTP/1.x
            &b"GET / HTTP/9.9\r\n"[..],
        ] {
            let (result, request) = parse(line, DEFAULT_HEAD_LIMIT);
            assert_eq!(
                result,
                ParseResult::NotHttp,
                "{} must be recognised as not-HTTP at its first newline",
                String::from_utf8_lossy(line)
            );
            assert!(request.is_none());
        }
    }

    #[test]
    fn a_lf_only_request_head_is_parsed() {
        // A client that ends lines with a bare `\n` is not speaking HTTP/1.1 correctly, but the
        // request line is still unambiguous, so the connection is not held open waiting for `\r\n\r\n`.
        let (result, request) = parse(b"GET /a HTTP/1.1\nHost: x.example\n\n", DEFAULT_HEAD_LIMIT);
        // The head terminator is still required, so this stays incomplete — but the *version* was
        // recognised, which is what keeps it from being rejected as another protocol.
        assert_eq!(result, ParseResult::Incomplete);
        assert!(request.is_none());
    }

    #[test]
    fn expect_continue_is_recognised() {
        let request = complete(
            b"POST /upload HTTP/1.1\r\nHost: x.example\r\nContent-Length: 9\r\n\
              Expect: 100-continue\r\n\r\n",
        );
        assert!(request.expect_continue);
        assert!(
            request.must_close_when_answered(),
            "a blocked `Expect` request must close: its body may never be sent"
        );

        // Case-insensitive, and absent otherwise.
        let request = complete(
            b"POST /u HTTP/1.1\r\nHost: x.example\r\nExpect: 100-Continue\r\n\r\n",
        );
        assert!(request.expect_continue);
        let request = complete(b"GET /u HTTP/1.1\r\nHost: x.example\r\n\r\n");
        assert!(!request.expect_continue);
    }

    #[test]
    fn only_requests_with_bodies_or_expect_must_close_when_answered() {
        // The whole point of the distinction: a bodiless GET keeps its connection, so a page's six
        // keep-alive connections are not churned by every blocked ad.
        assert!(!complete(b"GET /a HTTP/1.1\r\nHost: x.example\r\n\r\n").must_close_when_answered());
        assert!(complete(b"POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: 1\r\n\r\n")
            .must_close_when_answered());
        assert!(complete(b"POST /a HTTP/1.1\r\nHost: x.example\r\nTransfer-Encoding: chunked\r\n\r\n")
            .must_close_when_answered());
        // `Content-Length: 0` is no body at all.
        assert!(!complete(b"POST /a HTTP/1.1\r\nHost: x.example\r\nContent-Length: 0\r\n\r\n")
            .must_close_when_answered());
    }

    #[test]
    fn a_request_without_an_authority_is_not_parsed() {
        // HTTP/1.0 without `Host`: there is no URL to match, so the relay takes over.
        assert_eq!(
            parse(b"GET /a HTTP/1.0\r\n\r\n", DEFAULT_HEAD_LIMIT).0,
            ParseResult::NotHttp
        );
    }

    #[test]
    fn malformed_header_lines_do_not_fail_the_request() {
        let request = complete(
            b"GET /ok HTTP/1.1\r\nHost: ok.example.com\r\nthis line has no colon\r\n\r\n",
        );
        assert_eq!(request.url, "http://ok.example.com/ok");
    }

    #[test]
    fn referers_that_carry_no_site_are_dropped() {
        assert_eq!(absolute_referer("https://a.example/path"), Some("https://a.example/path".to_string()));
        assert_eq!(absolute_referer("  HTTP://A.EXAMPLE/x "), Some("HTTP://A.EXAMPLE/x".to_string()));
        assert_eq!(absolute_referer(""), None);
        assert_eq!(absolute_referer("about:blank"), None);
        assert_eq!(absolute_referer("file:///sdcard/page.html"), None);
        assert_eq!(absolute_referer("chrome-extension://abc/page.html"), None);
    }

    #[test]
    fn hostnames_are_normalised() {
        assert_eq!(hostname_of("ADS.Example.COM"), "ads.example.com");
        assert_eq!(hostname_of("ads.example.com:8080"), "ads.example.com");
        assert_eq!(hostname_of("[::1]:8080"), "::1");
        assert_eq!(hostname_of("[::1]"), "::1");
        // Not a port: left alone.
        assert_eq!(hostname_of("weird:host"), "weird:host");
    }

    #[test]
    fn options_star_and_lowercase_methods_are_accepted() {
        let request = complete(b"options * HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(request.method, "OPTIONS");
        assert_eq!(request.url, "http://example.com/");
    }
    #[test]
    fn the_scheme_decides_the_matched_url() {
        // A decrypted connection speaks HTTPS, and the engine has to see that: `$https` and every
        // path-level rule are anchored on the absolute URL. This is the bug the first device test of
        // M3a found — a decrypted request judged as `http://…` missed a path rule entirely.
        let head = b"GET /img/logo.png HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        let (result, request) = parse_with_scheme(head, DEFAULT_HEAD_LIMIT, Scheme::Https);
        assert_eq!(result, ParseResult::Complete);
        assert_eq!(
            request.expect("request").url,
            "https://www.example.com/img/logo.png"
        );

        // The same bytes on a plaintext connection are still http.
        let (_, request) = parse(head, DEFAULT_HEAD_LIMIT);
        assert_eq!(
            request.expect("request").url,
            "http://www.example.com/img/logo.png"
        );
    }

    #[test]
    fn the_default_port_follows_the_scheme() {
        // `:443` on an HTTPS connection is the default and must be stripped, or `||host^` would miss;
        // on an HTTP connection `:443` is not the default and has to stay.
        let head = b"GET /a HTTP/1.1\r\nHost: www.example.com:443\r\n\r\n";
        let (_, request) = parse_with_scheme(head, DEFAULT_HEAD_LIMIT, Scheme::Https);
        assert_eq!(request.expect("request").url, "https://www.example.com/a");

        let head = b"GET /a HTTP/1.1\r\nHost: www.example.com:80\r\n\r\n";
        let (_, request) = parse_with_scheme(head, DEFAULT_HEAD_LIMIT, Scheme::Https);
        assert_eq!(
            request.expect("request").url,
            "https://www.example.com:80/a",
            "`:80` is not the default port of https"
        );
    }

    #[test]
    fn an_absolute_form_target_takes_the_connections_scheme() {
        // A proxy-style absolute target can claim `http://`; on a TLS connection the transport wins,
        // because that is the scheme the client is actually speaking.
        let head = b"GET http://cdn.example.com/a.js HTTP/1.1\r\nHost: cdn.example.com\r\n\r\n";
        let (_, request) = parse_with_scheme(head, DEFAULT_HEAD_LIMIT, Scheme::Https);
        assert_eq!(
            request.expect("request").url,
            "https://cdn.example.com/a.js"
        );
    }
}
