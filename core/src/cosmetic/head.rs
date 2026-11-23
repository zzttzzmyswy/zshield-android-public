//! Parsing and rewriting of an origin's response head for cosmetic injection.
//!
//! Injection changes the body's length, so three headers can no longer be true once a document is
//! rewritten: `Content-Length` (the length changed), `Content-Encoding` (the body is now identity),
//! and `Transfer-Encoding` (chunking is re-done locally). `Content-Security-Policy` has to be
//! *extended*, never replaced — see [`crate::cosmetic::csp`].
//!
//! Everything here works on the original bytes: a head that is not rewritten is not re-rendered, and
//! header lines that this module does not own are copied verbatim (order, casing and their own CRLF
//! included), so an origin's own framing stays trustworthy.

/// Longest response head this module will buffer while looking for the terminator.
///
/// The same order as [`crate::http::rewrite::MAX_HEAD_BYTES`]: a head larger than this is not
/// something a real origin sends, and the caller passes it through unmodified rather than buffering
/// without bound.
pub const MAX_HEAD_BYTES: usize = 32 * 1024;

/// The fields of a response head that decide whether a document can be injected into.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    /// `Content-Type`, lowercased, parameters included (`text/html; charset=utf-8`).
    pub content_type: Option<String>,
    /// `Content-Encoding`, lowercased and trimmed (`gzip`, `br`, ...).
    pub content_encoding: Option<String>,
    /// `Content-Length`, when it is a plain decimal number.
    pub content_length: Option<u64>,
    /// True when the origin framed the body with `Transfer-Encoding: chunked`.
    pub chunked: bool,
    /// Every `Content-Security-Policy` policy, in the order they arrived.
    ///
    /// Several policies are enforced as their intersection, so each one has to authorize an injected
    /// inline `<script>`/`<style>` on its own terms. A single header line carrying several
    /// comma-separated policies contributes one entry each, because that is how the client enforces them.
    pub csp: Vec<String>,
    /// True when the response asked for `Content-Disposition: attachment`.
    pub attachment: bool,
    /// The HTTP version of the status line, as `major * 10 + minor` (`11` for HTTP/1.1, `10` for 1.0).
    ///
    /// A rewritten body has no `Content-Length`, so it needs *some* framing. HTTP/1.1 has chunked;
    /// HTTP/1.0 does not, and a client speaking 1.0 would read the chunk-size lines as body bytes. Those
    /// responses are therefore rewritten with no framing at all and the connection closed to mark the end.
    pub version: u8,
}

impl ResponseHead {
    /// True when the response is a 200 HTML document this core may rewrite.
    pub fn is_injectable_document(&self) -> bool {
        if self.status != 200 {
            return false;
        }
        let Some(content_type) = self.content_type.as_deref() else {
            return false;
        };
        // A download is not a document the user reads in the browser: injecting into it would put our
        // markup inside a file the user then opens on their own terms, and some clients sniff the type
        // again on save. Its body is not ours to change.
        if self.attachment {
            return false;
        }
        let media = content_type.split(';').next().unwrap_or("").trim();
        // `application/xhtml+xml` is a document too, and a `<style>`/`<script>` in it is CSS/JS in
        // the XHTML namespace — which is what the injected markup declares.
        media == "text/html" || media == "application/xhtml+xml"
    }

    /// The framing a rewritten body must use for this response.
    ///
    /// HTTP/1.1 gets chunked. HTTP/1.0 has no chunked coding, so the body is written unframed and the
    /// connection is closed at the end (which is what tells a 1.0 client where it ends).
    pub fn out_framing(&self) -> OutFraming {
        if self.version >= 11 {
            OutFraming::Chunked
        } else {
            OutFraming::Unframed
        }
    }

    /// The body coding, or `None` when this core cannot decode it (and must therefore not inject).
    ///
    /// `identity` and no coding at all are the same thing. `gzip` and `x-gzip` are decoded; `br`,
    /// `zstd` and `deflate` are not, because no document request is ever offered them (see
    /// `docs/EFFECTIVENESS.md`) and decoding them would mean another dependency in the APK.
    pub fn coding(&self) -> Option<Coding> {
        match self.content_encoding.as_deref().map(str::trim) {
            None | Some("") | Some("identity") => Some(Coding::Identity),
            Some("gzip") | Some("x-gzip") => Some(Coding::Gzip),
            Some(_) => None,
        }
    }
}

/// How the origin encoded the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coding {
    Identity,
    Gzip,
}

/// Where the head terminator ends, or `None` while it has not arrived.
pub fn head_end(head: &[u8]) -> Option<usize> {
    head.windows(4).position(|window| window == b"\r\n\r\n").map(|index| index + 4)
}

/// Parse a complete response head (terminator included).
pub fn parse(head: &[u8]) -> Option<ResponseHead> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let status_line = lines.next()?;
    let status = parse_status(status_line)?;
    let version = parse_version(status_line).unwrap_or(11);
    let mut parsed = ResponseHead {
        status,
        version,
        ..ResponseHead::default()
    };
    for line in lines {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = std::str::from_utf8(&line[colon + 1..]).ok()?.trim();
        if name.eq_ignore_ascii_case(b"content-type") {
            parsed.content_type = Some(value.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            parsed.content_encoding = Some(value.to_ascii_lowercase());
        } else if name.eq_ignore_ascii_case(b"content-length") {
            parsed.content_length = value.parse::<u64>().ok();
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            parsed.chunked = value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"));
        } else if name.eq_ignore_ascii_case(b"content-disposition") {
            // Only the `attachment` disposition type stops injection; `inline` and the unset case do
            // not, and a disposition with parameters (`attachment; filename="x.html"`) still does.
            parsed.attachment = value
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("attachment");
        } else if name.eq_ignore_ascii_case(b"content-security-policy") {
            // One header line may carry several comma-separated policies; each is enforced on its own,
            // so each is kept on its own.
            parsed
                .csp
                .extend(crate::cosmetic::csp::split_policies(value));
        }
    }
    Some(parsed)
}

/// The HTTP version of a status line, as `major * 10 + minor`.
fn parse_version(line: &[u8]) -> Option<u8> {
    let version = line.split(|byte| *byte == b' ').next()?;
    let rest = version.strip_prefix(b"HTTP/")?;
    let dot = rest.iter().position(|byte| *byte == b'.')?;
    let major = std::str::from_utf8(&rest[..dot]).ok()?.parse::<u8>().ok()?;
    let minor = std::str::from_utf8(&rest[dot + 1..]).ok()?.parse::<u8>().ok()?;
    Some(major.saturating_mul(10).saturating_add(minor))
}

fn parse_status(line: &[u8]) -> Option<u16> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.splitn(3, |byte| *byte == b' ');
    let version = parts.next()?;
    if !version.starts_with(b"HTTP/") {
        return None;
    }
    let code = parts.next()?.trim_ascii();
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(code).ok()?.parse().ok()
}

/// How the rewritten body will reach the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutFraming {
    /// HTTP/1.1: chunked, so the length never has to be known in advance.
    Chunked,
    /// HTTP/2: no length at all, the stream's END_STREAM is the end.
    Unframed,
}

/// Rewrite the head for an injected document.
///
/// `csp` holds the replacement `Content-Security-Policy` values (one per original header line, in
/// the same order). The original lines are dropped; the replacements take their place at the position
/// of the first one, so the head keeps its shape.
pub fn rewrite(
    head: &[u8],
    framing: OutFraming,
    csp: &[String],
    drop: &[String],
) -> Option<Vec<u8>> {
    let end = head_end(head)?;
    // The status line and every header line, each with its own CRLF; the blank line that terminates
    // the head is kept aside and appended at the end. Splitting this way is what keeps the last
    // header's CRLF with the line it belongs to.
    let (head_part, terminator) = head.split_at(end - 2);
    let mut out = Vec::with_capacity(head.len() + 64);
    let mut csp_written = false;
    let mut first = true;
    for line in head_part.split_inclusive(|byte| *byte == b'\n') {
        if first {
            first = false;
            out.extend_from_slice(line);
            continue;
        }
        if line == b"\r\n" || line == b"\n" {
            continue;
        }
        let bare = line.strip_suffix(b"\r\n").or_else(|| line.strip_suffix(b"\n")).unwrap_or(line);
        let Some(colon) = bare.iter().position(|byte| *byte == b':') else {
            out.extend_from_slice(line);
            continue;
        };
        let name = &bare[..colon];
        // The three headers that stopped being true. `Content-Encoding` is dropped even when the body
        // was identity, because a head that says `identity` is unusual and a client cannot act on it.
        if name.eq_ignore_ascii_case(b"content-length")
            || name.eq_ignore_ascii_case(b"content-encoding")
            || name.eq_ignore_ascii_case(b"transfer-encoding")
        {
            continue;
        }
        // `$removeheader`: named by the filter, matched case-insensitively like any header.
        if drop.iter().any(|dropped| name.eq_ignore_ascii_case(dropped.as_bytes())) {
            continue;
        }
        if name.eq_ignore_ascii_case(b"content-security-policy") {
            if !csp_written {
                csp_written = true;
                for policy in csp {
                    out.extend_from_slice(b"Content-Security-Policy: ");
                    out.extend_from_slice(policy.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
            continue;
        }
        out.extend_from_slice(line);
    }
    if !csp_written {
        for policy in csp {
            out.extend_from_slice(b"Content-Security-Policy: ");
            out.extend_from_slice(policy.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    if framing == OutFraming::Chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    // `terminator` is the empty line that ends the head (`\r\n`), so it is appended once.
    out.extend_from_slice(terminator);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTML_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                               Content-Length: 1234\r\nContent-Encoding: gzip\r\n\
                               Cache-Control: no-store\r\n\r\n";

    #[test]
    fn an_html_document_is_recognised_whatever_its_charset() {
        for content_type in [
            "text/html",
            "text/html; charset=utf-8",
            "TEXT/HTML;CHARSET=UTF-8",
            "application/xhtml+xml",
            "application/xhtml+xml; charset=utf-8",
        ] {
            let head = format!("HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n");
            let parsed = parse(head.as_bytes()).expect("head");
            assert!(parsed.is_injectable_document(), "{content_type}");
        }
    }

    #[test]
    fn everything_that_is_not_a_200_html_document_is_not_injectable() {
        // Non-200.
        assert!(!parse(b"HTTP/1.1 304 Not Modified\r\nContent-Type: text/html\r\n\r\n")
            .expect("head")
            .is_injectable_document());
        assert!(!parse(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n")
            .expect("head")
            .is_injectable_document());
        // Not a document.
        assert!(!parse(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
            .expect("head")
            .is_injectable_document());
        // No content type at all: a body whose meaning is unknown is not ours to rewrite.
        assert!(!parse(b"HTTP/1.1 200 OK\r\n\r\n")
            .expect("head")
            .is_injectable_document());
    }

    #[test]
    fn the_body_coding_is_read_and_only_gzip_is_decodable() {
        let parsed = parse(HTML_HEAD).expect("head");
        assert_eq!(parsed.coding(), Some(Coding::Gzip));
        assert_eq!(parsed.content_length, Some(1234));
        assert!(!parsed.chunked);

        let identity = parse(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n").expect("head");
        assert_eq!(identity.coding(), Some(Coding::Identity));
        assert_eq!(identity.content_length, None);

        for coding in ["br", "zstd", "deflate"] {
            let head = format!("HTTP/1.1 200 OK\r\nContent-Encoding: {coding}\r\n\r\n");
            assert_eq!(parse(head.as_bytes()).expect("head").coding(), None, "{coding}");
        }
        // A coding list is not something this core produces, and `gzip, gzip` is not `gzip`.
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip, gzip\r\n\r\n")
                .expect("head")
                .coding(),
            None
        );
    }

    #[test]
    fn several_csp_headers_are_all_kept() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\
                     Content-Security-Policy: script-src 'self'\r\n\r\n";
        let parsed = parse(head).expect("head");
        assert_eq!(
            parsed.csp,
            vec![
                "default-src 'self'".to_string(),
                "script-src 'self'".to_string()
            ]
        );
    }

    #[test]
    fn chunked_framing_is_detected() {
        assert!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .expect("head")
            .chunked);
        assert!(parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
            .expect("head")
            .chunked);
        assert!(!parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n")
            .expect("head")
            .chunked);
    }

    #[test]
    fn the_rewritten_head_drops_the_framing_headers_and_adds_chunked() {
        let csp = vec!["script-src 'self' 'nonce-abc'".to_string()];
        let rewritten = rewrite(HTML_HEAD, OutFraming::Chunked, &csp, &[]).expect("rewrite");
        let text = String::from_utf8(rewritten).expect("utf8");
        assert!(!text.to_ascii_lowercase().contains("content-length"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("content-encoding"), "{text}");
        assert!(text.contains("Transfer-Encoding: chunked\r\n"), "{text}");
        assert!(text.contains("Content-Type: text/html; charset=utf-8\r\n"), "{text}");
        assert!(text.contains("Cache-Control: no-store\r\n"), "untouched headers stay");
        assert!(text.contains("Content-Security-Policy: script-src 'self' 'nonce-abc'\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "{text:?}");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn an_unframed_rewrite_adds_no_chunking() {
        let rewritten = rewrite(HTML_HEAD, OutFraming::Unframed, &[], &[]).expect("rewrite");
        let text = String::from_utf8(rewritten).expect("utf8");
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("content-length"), "{text}");
    }

    #[test]
    fn existing_csp_lines_are_replaced_in_place_and_not_duplicated() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self'\r\n\
                     X-Keep: 1\r\nContent-Security-Policy: img-src *\r\n\r\n";
        let csp = vec![
            "default-src 'self' 'nonce-1'".to_string(),
            "img-src * 'nonce-2'".to_string(),
        ];
        let text = String::from_utf8(rewrite(head, OutFraming::Unframed, &csp, &[]).expect("rewrite"))
            .expect("utf8");
        assert_eq!(text.matches("Content-Security-Policy:").count(), 2, "{text}");
        assert!(text.contains("Content-Security-Policy: default-src 'self' 'nonce-1'\r\n"));
        assert!(text.contains("Content-Security-Policy: img-src * 'nonce-2'\r\n"));
        assert!(text.contains("X-Keep: 1\r\n"));
    }

    #[test]
    fn a_head_without_its_terminator_is_not_rewritten() {
        assert_eq!(rewrite(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n", OutFraming::Chunked, &[], &[]), None);
    }

    #[test]
    fn the_head_terminator_is_found_with_its_own_length() {
        assert_eq!(head_end(b"HTTP/1.1 200 OK\r\n\r\n"), Some(19));
        assert_eq!(head_end(b"HTTP/1.1 200 OK\r\n"), None);
    }
}
