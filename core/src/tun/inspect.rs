//! Connection inspection: what domain is this TCP connection for?
//!
//! Two protocols are understood, because they are the ones whose first client bytes carry the
//! hostname in the clear:
//!
//! - TLS: the `server_name` extension of the ClientHello (RFC 6066). This is the same signal
//!   `tls.client_hello` / SNI-based filtering uses everywhere, and it survives ECH only because the
//!   DNS layer strips the `ech` SvcParam (see `dns::ech`) — a client that got a usable ECHConfig
//!   would hide the name.
//! - HTTP/1.x: the `Host` header of the request line block.
//!
//! Everything else (HTTP/2 prior knowledge, SMTP, SSH, ...) returns `Unknown` and is forwarded
//! verbatim: guessing is worse than passing through.
//!
//! The parsers are incremental: a ClientHello split across two TCP segments must still be read, so
//! `NeedMore` says how many bytes would settle the question.

use crate::http::head;

/// Result of inspecting the buffered head of a client→server stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniff {
    /// A hostname was extracted.
    Host(String),
    /// The protocol was recognised but carries no hostname (e.g. a TLS ClientHello without SNI,
    /// or an HTTP request without a `Host` header). Forward it unchanged.
    NoHost,
    /// More bytes are needed; the buffer should be extended up to the hint (never beyond the
    /// caller's own limit) before deciding again.
    NeedMore { hint: usize },
    /// Not a protocol whose first bytes name a host. Forward unchanged.
    Unknown,
    /// The bytes claim to be TLS/HTTP but do not parse. Forward unchanged (a broken client is not
    /// our business), rather than blocking on a guess.
    Malformed,
}

/// Bytes of TLS record header.
const TLS_RECORD_HEADER: usize = 5;
/// Handshake content type.
const TLS_HANDSHAKE: u8 = 0x16;
/// `client_hello` handshake message type.
const TLS_CLIENT_HELLO: u8 = 0x01;
/// Extension id of `server_name`.
const EXT_SERVER_NAME: u16 = 0;
/// `host_name` name type inside the server_name extension.
const SNI_HOST_NAME: u8 = 0;

/// True if the buffer starts like a TLS handshake record (used to decide whether to keep buffering).
pub fn looks_like_tls(buf: &[u8]) -> bool {
    buf.first() == Some(&TLS_HANDSHAKE)
}

/// What protocol a client→server stream looks like, from its first bytes.
///
/// Used by the forwarding layer to choose a relay: plaintext HTTP gets the per-request filter
/// pipeline (`crate::http::relay`), TLS gets the hostname check plus a verbatim copy, and anything
/// else is copied through untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// A TLS record (the handshake is handled by the SNI path).
    Tls,
    /// HTTP/1.x, or a prefix short enough that it could still become a request.
    Http,
    /// Anything else: a server-first greeting, a binary protocol, an HTTP/2 preface.
    Other,
}

/// Classify the buffered head. `buf` may be empty (nothing arrived before the sniff deadline).
pub fn protocol(buf: &[u8]) -> Protocol {
    if looks_like_tls(buf) {
        return Protocol::Tls;
    }
    if head::looks_like_request(buf) {
        return Protocol::Http;
    }
    Protocol::Other
}

/// Parse the head of a client→server stream.
///
/// `complete_hello_limit` is the caller's buffering budget: a ClientHello larger than it is treated
/// as `Malformed` so a hostile peer cannot make us buffer without bound.
pub fn sniff(buf: &[u8], complete_hello_limit: usize) -> Sniff {
    if buf.is_empty() {
        return Sniff::NeedMore { hint: 1 };
    }
    match buf[0] {
        TLS_HANDSHAKE => parse_client_hello(buf, complete_hello_limit),
        _ => parse_http_host(buf),
    }
}

/// Parse a TLS ClientHello out of `buf` (which may contain more than the ClientHello).
///
/// Handles GREASE values (they are simply skipped like any other unknown value), an arbitrary number
/// of extensions, a ClientHello split across TCP segments (`NeedMore`), and a ClientHello without
/// SNI (`NoHost`).
pub fn parse_client_hello(buf: &[u8], limit: usize) -> Sniff {
    if buf.len() < TLS_RECORD_HEADER {
        return Sniff::NeedMore {
            hint: TLS_RECORD_HEADER,
        };
    }
    if buf[0] != TLS_HANDSHAKE {
        return Sniff::Unknown;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if record_len == 0 {
        return Sniff::Malformed;
    }
    let record_end = TLS_RECORD_HEADER + record_len;
    if record_len > limit {
        return Sniff::Malformed;
    }
    if buf.len() < record_end {
        return Sniff::NeedMore { hint: record_end };
    }
    let record = &buf[TLS_RECORD_HEADER..record_end];
    if record.len() < 4 || record[0] != TLS_CLIENT_HELLO {
        // A different handshake message (e.g. a resumed session's ClientHello is still type 1;
        // anything else means we are not looking at a fresh client hello).
        return Sniff::NoHost;
    }
    let body_len = usize::from(record[1]) << 16 | usize::from(record[2]) << 8 | usize::from(record[3]);
    if body_len > limit {
        return Sniff::Malformed;
    }
    if record.len() - 4 < body_len {
        // The handshake message spills into the next record (rare, but legal). Ask for it.
        return Sniff::NeedMore {
            hint: TLS_RECORD_HEADER + 4 + body_len,
        };
    }
    let body = &record[4..4 + body_len];
    parse_client_hello_body(body)
}

fn parse_client_hello_body(body: &[u8]) -> Sniff {
    let mut cursor = 0usize;
    // client_version(2) + random(32)
    if body.len() < 34 {
        return Sniff::Malformed;
    }
    cursor += 34;
    // legacy_session_id
    let Some(session_id_len) = body.get(cursor).copied() else {
        return Sniff::Malformed;
    };
    cursor += 1 + usize::from(session_id_len);
    // cipher_suites
    let Some(cipher_len) = read_u16(body, cursor) else {
        return Sniff::Malformed;
    };
    cursor += 2 + usize::from(cipher_len);
    // legacy_compression_methods
    let Some(compression_len) = body.get(cursor).copied() else {
        return Sniff::Malformed;
    };
    cursor += 1 + usize::from(compression_len);
    // extensions (optional in SSLv3-era hellos)
    if cursor == body.len() {
        return Sniff::NoHost;
    }
    let Some(extensions_len) = read_u16(body, cursor) else {
        return Sniff::Malformed;
    };
    cursor += 2;
    let extensions_end = match cursor.checked_add(usize::from(extensions_len)) {
        Some(end) if end <= body.len() => end,
        _ => return Sniff::Malformed,
    };

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
        cursor += 4;
        let ext_end = match cursor.checked_add(ext_len) {
            Some(end) if end <= extensions_end => end,
            _ => return Sniff::Malformed,
        };
        if ext_type == EXT_SERVER_NAME {
            return match parse_sni(&body[cursor..ext_end]) {
                Some(name) => Sniff::Host(name),
                None => Sniff::NoHost,
            };
        }
        // GREASE extension types (0x?a?a with both bytes equal) land here and are skipped like any
        // other unknown extension.
        cursor = ext_end;
    }
    Sniff::NoHost
}

fn parse_sni(extension: &[u8]) -> Option<String> {
    let list_len = usize::from(read_u16(extension, 0)?);
    let mut cursor = 2usize;
    let list_end = (cursor + list_len).min(extension.len());
    while cursor + 3 <= list_end {
        let name_type = extension[cursor];
        let name_len = usize::from(read_u16(extension, cursor + 1)?);
        cursor += 3;
        let end = cursor.checked_add(name_len)?;
        if end > list_end {
            return None;
        }
        if name_type == SNI_HOST_NAME {
            let name = std::str::from_utf8(&extension[cursor..end]).ok()?;
            let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() {
                return None;
            }
            return Some(name);
        }
        cursor = end;
    }
    None
}

fn read_u16(buf: &[u8], pos: usize) -> Option<u16> {
    let hi = *buf.get(pos)?;
    let lo = *buf.get(pos + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Extension id of `application_layer_protocol_negotiation` (RFC 7301).
const EXT_ALPN: u16 = 16;

/// What the MITM layer needs out of one ClientHello.
///
/// Collected in a single walk because the alternative — asking [`sniff`] for the SNI and then
/// walking the extensions again for the ALPN list — parses the same bytes twice on the one path
/// where latency is most visible (the first thing a page load does).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HelloInfo {
    /// The SNI, normalised (lowercase, no trailing dot), when the client sent one.
    pub server_name: Option<String>,
    /// Offered ALPN protocols in the client's preference order. Empty when the client offered none.
    pub alpn: Vec<Vec<u8>>,
    /// Number of bytes of the input the ClientHello occupied, so the caller can hand the rest on.
    pub hello_len: usize,
}

/// Parse a ClientHello for the SNI and ALPN list.
///
/// Returns `None` when the buffer is not (yet) a complete ClientHello — a caller that has to decide
/// now treats that as "no name, no ALPN" and falls back to HTTP/1.1 or refuses to decrypt, rather
/// than blocking on bytes that may never arrive.
pub fn client_hello_info(buf: &[u8]) -> Option<HelloInfo> {
    if buf.len() < TLS_RECORD_HEADER || buf[0] != TLS_HANDSHAKE {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    let record_end = TLS_RECORD_HEADER + record_len;
    if record_len == 0 || buf.len() < record_end {
        return None;
    }
    let record = &buf[TLS_RECORD_HEADER..record_end];
    if record.len() < 4 || record[0] != TLS_CLIENT_HELLO {
        return None;
    }
    let body_len =
        usize::from(record[1]) << 16 | usize::from(record[2]) << 8 | usize::from(record[3]);
    if record.len() - 4 < body_len {
        return None;
    }
    let body = &record[4..4 + body_len];

    let mut info = HelloInfo {
        hello_len: record_end,
        ..HelloInfo::default()
    };
    let mut cursor = 34usize; // legacy_version + random
    if body.len() < cursor {
        return None;
    }
    let session_id_len = usize::from(*body.get(cursor)?);
    cursor += 1 + session_id_len;
    let cipher_len = usize::from(read_u16(body, cursor)?);
    cursor += 2 + cipher_len;
    let compression_len = usize::from(*body.get(cursor)?);
    cursor += 1 + compression_len;
    if cursor == body.len() {
        // No extensions: legal, and means no SNI and no ALPN.
        return Some(info);
    }
    let extensions_len = usize::from(read_u16(body, cursor)?);
    cursor += 2;
    let extensions_end = cursor.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
        let ext_len = usize::from(u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]));
        cursor += 4;
        let ext_end = cursor.checked_add(ext_len)?;
        if ext_end > extensions_end {
            return None;
        }
        let extension = &body[cursor..ext_end];
        match ext_type {
            EXT_SERVER_NAME => info.server_name = parse_sni(extension),
            EXT_ALPN => info.alpn = parse_alpn(extension),
            _ => {}
        }
        cursor = ext_end;
    }
    Some(info)
}

/// Parse the ALPN extension: `ProtocolNameList` of `ProtocolName`s (RFC 7301 §3.1).
fn parse_alpn(extension: &[u8]) -> Vec<Vec<u8>> {
    let Some(list_len) = read_u16(extension, 0) else {
        return Vec::new();
    };
    let mut cursor = 2usize;
    let list_end = (cursor + usize::from(list_len)).min(extension.len());
    let mut out = Vec::new();
    while cursor < list_end {
        let Some(len) = extension.get(cursor).copied() else {
            break;
        };
        cursor += 1;
        let end = cursor + usize::from(len);
        if end > list_end {
            break;
        }
        out.push(extension[cursor..end].to_vec());
        cursor = end;
    }
    out
}

/// The ALPN list of a ClientHello, for callers that only need that.
pub fn client_hello_alpn(buf: &[u8]) -> Option<Vec<Vec<u8>>> {
    client_hello_info(buf).map(|info| info.alpn)
}

/// The bytes that can end an HTTP/1.x request head.
const HTTP_HEADER_END: &[u8] = b"\r\n\r\n";

/// Parse the `Host` header out of an HTTP/1.x request head.
///
/// Returns `NeedMore` while the head is incomplete, so a request sent in several segments is still
/// readable. Anything that does not start with a known method token is `Unknown` (and forwarded
/// immediately, without waiting for a timeout).
pub fn parse_http_host(buf: &[u8]) -> Sniff {
    const METHODS: [&[u8]; 9] = [
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"CONNECT ", b"OPTIONS ", b"TRACE ", b"PATCH ",
    ];
    if buf.len() < 4 {
        return if METHODS.iter().any(|method| method.starts_with(buf)) {
            Sniff::NeedMore { hint: 4 }
        } else {
            Sniff::Unknown
        };
    }
    if !METHODS.iter().any(|method| buf.starts_with(method)) {
        return Sniff::Unknown;
    }
    let head_end = match find(buf, HTTP_HEADER_END) {
        Some(idx) => idx,
        None => {
            return Sniff::NeedMore {
                hint: buf.len() + 1,
            }
        }
    };
    let head = &buf[..head_end];
    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // `slice::split_once` with a predicate is unstable, so the colon is found by hand.
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"host") {
            let host = String::from_utf8_lossy(value).trim().to_ascii_lowercase();
            // Strip a port: `example.com:8080` is the same site as `example.com`.
            let host = strip_port(&host);
            if host.is_empty() {
                return Sniff::NoHost;
            }
            return Sniff::Host(host);
        }
    }
    Sniff::NoHost
}

fn strip_port(host: &str) -> String {
    if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal: `[::1]:443`.
        if let Some((inner, tail)) = rest.split_once(']') {
            return if tail.is_empty() || tail.starts_with(':') {
                inner.to_string()
            } else {
                host.to_string()
            };
        }
        return host.to_string();
    }
    match host.rsplit_once(':') {
        Some((head, port)) if !head.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            head.to_string()
        }
        _ => host.to_string(),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a ClientHello with the given extensions, GREASE values sprinkled in when asked.
    fn client_hello(server_name: Option<&str>, grease: bool, extra_extensions: bool) -> Vec<u8> {
        client_hello_with_alpn(server_name, grease, extra_extensions, &[])
    }

    /// Same, with an ALPN extension appended (empty slice = no ALPN extension at all).
    fn client_hello_with_alpn(
        server_name: Option<&str>,
        grease: bool,
        extra_extensions: bool,
        alpn: &[&[u8]],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(32); // session id length
        body.extend_from_slice(&[0x22; 32]);

        let mut ciphers = Vec::new();
        if grease {
            ciphers.extend_from_slice(&[0x0a, 0x0a]); // GREASE
        }
        ciphers.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f]);
        body.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
        body.extend_from_slice(&ciphers);

        body.push(1); // one compression method
        body.push(0); // null

        let mut extensions = Vec::new();
        if grease {
            // A GREASE extension whose contents we must skip entirely.
            extensions.extend_from_slice(&[0x1a, 0x1a, 0x00, 0x03, 0x01, 0x02, 0x03]);
        }
        if extra_extensions {
            // supported_versions
            extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
            // signature_algorithms with a long body
            extensions.extend_from_slice(&[0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]);
            // key_share with an opaque blob
            extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x05, 0x00, 0x03, 0x00, 0x1d, 0x00]);
        }
        if let Some(name) = server_name {
            let mut sni = Vec::new();
            sni.extend_from_slice(&[0x00]); // host_name type
            sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sni.extend_from_slice(name.as_bytes());
            let mut list = Vec::new();
            list.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            list.extend_from_slice(&sni);
            extensions.extend_from_slice(&0u16.to_be_bytes()); // server_name
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for protocol in alpn {
                list.push(protocol.len() as u8);
                list.extend_from_slice(protocol);
            }
            extensions.extend_from_slice(&16u16.to_be_bytes()); // application_layer_protocol_negotiation
            extensions.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        if grease {
            // Trailing GREASE extension.
            extensions.extend_from_slice(&[0xfa, 0xfa, 0x00, 0x00]);
        }
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(TLS_CLIENT_HELLO);
        let len = body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(TLS_HANDSHAKE);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_sni() {
        let hello = client_hello(Some("ads.example.com"), false, false);
        assert_eq!(sniff(&hello, 4096), Sniff::Host("ads.example.com".to_string()));
    }

    #[test]
    fn tolerates_grease_and_many_extensions() {
        let hello = client_hello(Some("Www.Baidu.COM"), true, true);
        assert_eq!(sniff(&hello, 4096), Sniff::Host("www.baidu.com".to_string()));
    }

    #[test]
    fn reports_no_sni() {
        let hello = client_hello(None, true, true);
        assert_eq!(sniff(&hello, 4096), Sniff::NoHost);
    }

    #[test]
    fn asks_for_more_when_split_across_tcp_segments() {
        let hello = client_hello(Some("split.example.com"), true, false);
        // Split inside the extensions block: the answer must be "need more", plus the full length.
        for split in [3, 5, 20, hello.len() / 2, hello.len() - 1] {
            let head = &hello[..split];
            match sniff(head, 4096) {
                Sniff::NeedMore { hint } => {
                    assert!(hint > split, "hint {hint} must ask for more than {split}");
                }
                other => panic!("split at {split} gave {other:?}"),
            }
            // Feeding the rest completes the parse, exactly as the TCP forwarder does.
            assert_eq!(
                sniff(&hello, 4096),
                Sniff::Host("split.example.com".to_string())
            );
        }
    }

    #[test]
    fn refuses_oversized_hellos() {
        // A ClientHello bigger than the buffering budget must be refused outright: a peer that
        // declares a huge record must not be able to make us buffer without bound.
        let hello = client_hello(Some("huge.example.com"), true, true);
        assert!(
            hello.len() > 40,
            "the fixture must be large enough for the budget to bite"
        );
        assert_eq!(sniff(&hello, 40), Sniff::Malformed);
        // Exactly the budget is still fine, so a legitimate hello at the limit is not blocked.
        assert!(matches!(
            sniff(&hello, hello.len()),
            Sniff::Host(_) | Sniff::NeedMore { .. }
        ));
    }

    #[test]
    fn extracts_http_host() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: ads.example.com:8080\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(
            sniff(request, 4096),
            Sniff::Host("ads.example.com".to_string())
        );
        let request = b"POST /a HTTP/1.0\r\nhost:EXAMPLE.com\r\n\r\n";
        assert_eq!(sniff(request, 4096), Sniff::Host("example.com".to_string()));
    }

    #[test]
    fn http_without_host_and_split_heads() {
        let head = b"GET / HTTP/1.1\r\nAccept: */*\r\n";
        assert!(matches!(sniff(head, 4096), Sniff::NeedMore { .. }));
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", 4096),
            Sniff::NoHost
        );
        // A CONNECT tunnel names its target in the request line, not in Host; that form is left
        // alone (proxy semantics) rather than guessed at.
        assert_eq!(
            sniff(b"CONNECT x:443 HTTP/1.1\r\n\r\n", 4096),
            Sniff::NoHost
        );
    }

    #[test]
    fn unknown_protocols_are_forwarded_immediately() {
        // Server-first protocols: SSH banner, SMTP, and raw binary.
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.6\r\n", 4096), Sniff::Unknown);
        assert_eq!(sniff(b"220 mail.example.com ESMTP\r\n", 4096), Sniff::Unknown);
        assert_eq!(sniff(&[0x00, 0x01, 0x02, 0x03], 4096), Sniff::Unknown);
        assert_eq!(sniff(b"", 4096), Sniff::NeedMore { hint: 1 });
        // A TLS record that is not a ClientHello (e.g. an Alert).
        let alert = [TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        assert_eq!(sniff(&alert, 4096), Sniff::NoHost);
    }

    #[test]
    fn malformed_tls_is_not_a_hostname() {
        // Record header claims far more than we are willing to buffer.
        let mut hello = client_hello(Some("x.example"), false, false);
        hello[3] = 0xff;
        hello[4] = 0xff;
        assert_eq!(sniff(&hello, 4096), Sniff::Malformed);
        // Truncated body inside a complete record.
        let mut broken = client_hello(Some("x.example"), false, false);
        let len = broken.len();
        broken.truncate(9 + 4 + 10);
        assert!(matches!(
            sniff(&broken, 4096),
            Sniff::NeedMore { .. } | Sniff::Malformed
        ));
        assert!(len > broken.len());
    }

    #[test]
    fn the_hello_info_carries_sni_and_alpn_in_one_walk() {
        let hello = client_hello_with_alpn(
            Some("www.Example.COM"),
            true,
            true,
            &[b"h2", b"http/1.1"],
        );
        let info = client_hello_info(&hello).expect("complete hello");
        assert_eq!(info.server_name.as_deref(), Some("www.example.com"));
        assert_eq!(
            info.alpn,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "the client's order must be preserved"
        );
        assert_eq!(info.hello_len, hello.len());

        // No ALPN extension at all: empty list, not an error.
        let info = client_hello_info(&client_hello(Some("a.example"), false, false)).expect("hello");
        assert_eq!(info.server_name.as_deref(), Some("a.example"));
        assert!(info.alpn.is_empty());

        // No SNI: the name is absent, the ALPN list still comes out.
        let info =
            client_hello_info(&client_hello_with_alpn(None, false, true, &[b"h2"])).expect("hello");
        assert_eq!(info.server_name, None);
        assert_eq!(info.alpn, vec![b"h2".to_vec()]);
    }

    #[test]
    fn an_incomplete_or_foreign_hello_yields_no_info() {
        let hello = client_hello_with_alpn(Some("a.example"), false, false, &[b"h2"]);
        for split in [0, 1, 4, hello.len() / 2, hello.len() - 1] {
            assert_eq!(
                client_hello_info(&hello[..split]),
                None,
                "a split at {split} is not a usable hello yet"
            );
        }
        assert_eq!(client_hello_info(b""), None);
        assert_eq!(client_hello_info(b"GET / HTTP/1.1\r\n"), None);
        // Bytes after the record (a following record) are not part of this hello.
        let mut with_tail = hello.clone();
        with_tail.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]);
        let info = client_hello_info(&with_tail).expect("hello");
        assert_eq!(info.hello_len, hello.len());
    }

    #[test]
    fn a_client_offering_no_alpn_is_reported_as_such() {
        assert_eq!(
            client_hello_alpn(&client_hello(Some("a.example"), false, false)),
            Some(Vec::new())
        );
        assert_eq!(
            client_hello_alpn(&client_hello_with_alpn(
                Some("a.example"),
                false,
                false,
                &[b"h2"]
            )),
            Some(vec![b"h2".to_vec()])
        );
        assert_eq!(client_hello_alpn(b"not tls"), None);
    }
}
