//! The responses this core synthesizes for a blocked request (task card §3).
//!
//! | Situation | Response |
//! |---|---|
//! | `document` (top-level navigation) | `403` with a minimal inline plain-text explanation |
//! | `subdocument` (iframe / frame / embed) | `200` with an empty `text/html` document |
//! | any other subresource | `204 No Content`, empty |
//! | adblock named a `$redirect` substitute | `200` with that resource's MIME type and body |
//!
//! Three constraints shape these:
//!
//! - **Self-contained.** The blocked document page has no external reference of any kind (no CSS, no
//!   font, no link). A blocked page that loads resources would be a filter that generates its own
//!   traffic, and it would also make the block visible in a network log as more requests.
//! - **Correct framing.** Every response carries an exact `Content-Length`, so a client can find the
//!   next response on a keep-alive connection without guessing, and the navigation case carries
//!   `Cache-Control: no-store` so a reload re-decides. The connection stays open: closing it per
//!   blocked request would turn every filtered page into a burst of reconnects.
//! - **`HEAD` gets the headers.** A `HEAD` must not carry a body, and its `Content-Length` must
//!   describe what a `GET` would have returned (`RFC 9110` §9.3.2), so the body is omitted but the
//!   length is not.

use crate::http::decision::RedirectBody;
use crate::http::resource::RequestKind;

/// A fully rendered HTTP/1.x response, ready to write to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    /// `Cache-Control: no-store`, used for the blocked-navigation page so a reload re-decides.
    pub no_store: bool,
    /// `Location`, for the `$removeparam` redirect (see [`rewritten`]).
    ///
    /// A field on this struct rather than a fifth response type because both relays already carry
    /// `HttpResponse` into their own header writers, and the HTTP/2 side has to emit the same header
    /// from the same source or the two protocols would disagree about what a rewritten URL looks like.
    pub location: Option<String>,
    /// Add `Connection: close` and end the connection after this response.
    ///
    /// Set when the blocked request carried a body or `Expect: 100-continue` (review item 4): the
    /// relay would otherwise have to read and discard that body, which deadlocks against a client
    /// waiting for `100 Continue` and against one that stops sending once it has the final response.
    /// Closing is what RFC 9112 §9.6 prescribes for a server that answers before reading the body.
    pub close: bool,
}

impl HttpResponse {
    /// Serialize to bytes. `head_only` omits the body but keeps its `Content-Length`.
    pub fn render(&self, head_only: bool) -> Vec<u8> {
        let mut head = String::with_capacity(160);
        head.push_str("HTTP/1.1 ");
        head.push_str(&self.status.to_string());
        head.push(' ');
        head.push_str(self.reason);
        head.push_str("\r\n");
        if let Some(location) = self.location.as_deref() {
            head.push_str("Location: ");
            head.push_str(&escape_header_value(location));
            head.push_str("\r\n");
        }
        head.push_str("Content-Type: ");
        head.push_str(self.content_type);
        head.push_str("\r\n");
        head.push_str("Content-Length: ");
        head.push_str(&self.body.len().to_string());
        head.push_str("\r\n");
        if self.no_store {
            head.push_str("Cache-Control: no-store\r\n");
        }
        if self.close {
            head.push_str("Connection: close\r\n");
        }
        head.push_str("\r\n");
        let mut out = head.into_bytes();
        if !head_only {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// The response for a blocked request that the engine did not redirect.
///
/// One function for both relays (`http::relay`, `https::h2`) so the shape cannot drift between the
/// plaintext and the decrypted path — the two carry the same decision type and must answer it the same
/// way.
pub fn blocked(kind: RequestKind, url: &str) -> HttpResponse {
    match kind {
        RequestKind::Document => blocked_page(url),
        RequestKind::Subdocument => blocked_subdocument(),
        _ => blocked_subresource(),
    }
}

/// The blocked **subdocument** response: `200` with an empty HTML document.
///
/// # Why this is not the explanation page
///
/// The `403` page is right for a top-level navigation: the user asked for that address and nothing
/// else is on screen, so telling them what happened is the useful answer. An iframe is the opposite
/// situation — the user never asked for it, it is a box *inside* a page they did want, and a `403`
/// explanation renders as a block of text in that box. So the frame is answered with a document that
/// renders as nothing at all.
///
/// An empty `200 text/html` rather than a `204`: a `204` has no body and no content type, so a browser
/// keeps rendering whatever the frame had (in practice a broken-image placeholder or, for a frame,
/// nothing that measures as empty), which is what made the element-hiding case 7 fail. A real, empty
/// HTML document replaces the frame's contents, which is what "blocked" has to look like from the
/// element's own point of view.
///
/// The body is deliberately empty and not a stub: any visible text would be the same problem in
/// smaller type.
pub fn blocked_subdocument() -> HttpResponse {
    HttpResponse {
        status: 200,
        reason: "OK",
        content_type: "text/html; charset=utf-8",
        body: Vec::new(),
        // Not stored: a blocked frame must be re-decided on the next load, like the document page.
        no_store: true,
        location: None,
        close: false,
    }
}

/// The blocked-navigation page.
///
/// Deliberately tiny and plain: a heading, one sentence, and the target URL in a `<pre>` so a user
/// who hits it can see what was blocked. No stylesheet, no script, no image, no link (task card §3).
const BLOCKED_PAGE_PREFIX: &str = "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>已被 ZShield 拦截</title></head><body>\
<h1>已被 ZShield 拦截</h1>\
<p>该请求命中了一条过滤规则，净盾没有把它发送到网络。</p>\
<p>如需放行，请把下面的地址加入自定义放行规则：</p><pre>";
const BLOCKED_PAGE_SUFFIX: &str = "</pre></body></html>\n";

/// The `document` response: `403` plus a minimal explanation.
pub fn blocked_page(url: &str) -> HttpResponse {

    let mut body = String::with_capacity(BLOCKED_PAGE_PREFIX.len() + url.len() + BLOCKED_PAGE_SUFFIX.len());
    body.push_str(BLOCKED_PAGE_PREFIX);
    // The URL is client-controlled, so it is HTML-escaped: a blocked page must not be a way to
    // inject markup into the browser.
    escape_html_into(url, &mut body);
    body.push_str(BLOCKED_PAGE_SUFFIX);
    HttpResponse {
        status: 403,
        reason: "Forbidden",
        content_type: "text/html; charset=utf-8",
        body: body.into_bytes(),
        no_store: true,
        location: None,
        close: false,
    }
}

/// The subresource response: `204`, no body, no content type worth stating.
pub fn blocked_subresource() -> HttpResponse {
    HttpResponse {
        status: 204,
        reason: "No Content",
        content_type: "text/plain; charset=utf-8",
        body: Vec::new(),
        no_store: false,
        location: None,
        close: false,
    }
}

/// The `$redirect` response: `200` with the substitute resource's type and bytes.
pub fn redirected(redirect: &RedirectBody) -> HttpResponse {
    HttpResponse {
        status: 200,
        reason: "OK",
        // The MIME type is owned by the parsed `data:` URL, so this is leaked once per response.
        // `RedirectBody` is built from a `data:` URL whose prefix is one of a fixed set, but a list
        // could name any string; leaking a few bytes per blocked request is not acceptable, so the
        // type is mapped into a static one below and anything else becomes octet-stream.
        content_type: static_mime(&redirect.mime),
        // A substitute is cacheable: it is a constant, and re-fetching it per page load would only
        // cost the client a round trip.
        no_store: false,
        body: redirect.body.clone(),
        location: None,
        close: false,
    }
}

/// The `302` a request whose URL an `$removeparam` rule rewrote is answered with.
///
/// Only a **document navigation** is redirected (`http::rewrite`'s module note has the reasoning, and
/// `docs/DESIGN.md` fixes it): the URL is in the address bar, so the browser has to be told. A
/// subresource is rewritten **in place** instead, because changing what the origin receives is the whole
/// job there and a redirect would alter the request's observable shape for no filtering benefit — and
/// would break `fetch(…, {redirect: 'error' | 'manual'})`.
///
/// `Cache-Control: no-store` keeps a rewritten URL from being cached in place of the real one.
///
/// One constructor for both relays (`http::relay`, `https::h2`) so the plaintext and the decrypted path
/// cannot answer the same decision differently.
pub fn rewritten_navigation(location: &str) -> HttpResponse {
    HttpResponse {
        status: 302,
        reason: "Found",
        content_type: "text/plain; charset=utf-8",
        body: Vec::new(),
        no_store: true,
        location: Some(location.to_string()),
        close: false,
    }
}

/// Percent-encode everything that cannot appear in a header value.
///
/// Encoding rather than stripping, for the same reason `http::rewrite::escape_header_value` does: a
/// stripped byte would silently point the client at a *different* URL than the rule produced, while
/// `%0D` keeps the URL meaning exactly what it says and cannot split the header.
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

/// Map a MIME type onto a `'static` spelling, so the response struct owns no allocation for it.
///
/// The set is exactly what the built-in resources use plus `application/octet-stream` for anything
/// else. Values outside the set are still served, just with the generic type — the body is what the
/// page asked for, and refusing to serve it would defeat the purpose of the substitute.
fn static_mime(mime: &str) -> &'static str {
    match mime {
        "application/javascript" | "text/javascript" => "application/javascript",
        "text/css" => "text/css",
        "text/plain" => "text/plain; charset=utf-8",
        "application/json" => "application/json",
        "image/gif" => "image/gif",
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "audio/mp3" | "audio/mpeg" => "audio/mpeg",
        "video/mp4" => "video/mp4",
        "text/html" => "text/html; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Append `text` with `&`, `<`, `>` and `"` escaped. Only the four characters that can break out of
/// text or an attribute are escaped; the page has no attributes with a URL value.
fn escape_html_into(text: &str, out: &mut String) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect(mime: &str, body: &[u8]) -> RedirectBody {
        RedirectBody {
            mime: mime.to_string(),
            body: body.to_vec(),
            data_url: format!("data:{mime};base64,"),
        }
    }

    #[test]
    fn the_blocked_page_is_self_contained() {
        let response = blocked_page("http://ads.example.com/some/page?a=1&b=2");
        assert_eq!(response.status, 403);
        let html = String::from_utf8(response.body.clone()).expect("utf-8");
        assert!(html.contains("已被 ZShield 拦截"));
        assert!(
            html.contains("http://ads.example.com/some/page?a=1&amp;b=2"),
            "the URL must be shown, escaped: {html}"
        );
        // No external reference of any kind: this page must not generate traffic.
        for forbidden in ["http://", "https://", "src=", "href=", "@import", "url(", ".css", ".js"] {
            // The escaped URL is the one exception (it is text, not a reference).
            let references = html.matches(forbidden).count();
            let allowed = if forbidden.starts_with("http") { 1 } else { 0 };
            assert!(
                references <= allowed,
                "{forbidden} appears {references} times in the blocked page: {html}"
            );
        }
    }

    #[test]
    fn the_blocked_page_escapes_markup_from_the_url() {
        let response = blocked_page("http://x.example/\"<script>alert(1)</script>");
        let html = String::from_utf8(response.body).expect("utf-8");
        assert!(!html.contains("<script>"), "the URL must not inject markup");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&quot;"));
    }

    #[test]
    fn a_blocked_subdocument_is_an_empty_200_document() {
        // Review item 6: a `403` explanation renders inside the ad iframe's box, which is a visible
        // defect of its own. The frame gets an empty HTML document instead, so it renders as nothing.
        let response = blocked_subdocument();
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "text/html; charset=utf-8");
        assert!(response.body.is_empty());
        assert!(response.no_store, "a blocked frame must be re-decided on the next load");
        let rendered = String::from_utf8(response.render(false)).expect("utf-8");
        assert!(rendered.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(rendered.contains("Content-Length: 0\r\n"));
        assert!(rendered.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_blocked_response_follows_the_request_kind() {
        // One chooser for both relays, so the plaintext and decrypted paths cannot drift apart.
        let document = blocked(RequestKind::Document, "https://ads.example/page");
        assert_eq!(document.status, 403, "the top-level page keeps its explanation");

        let subdocument = blocked(RequestKind::Subdocument, "https://ads.example/frame");
        assert_eq!(subdocument.status, 200);
        assert!(subdocument.body.is_empty());
        assert_eq!(subdocument.content_type, "text/html; charset=utf-8");

        for kind in [
            RequestKind::Image,
            RequestKind::Script,
            RequestKind::Stylesheet,
            RequestKind::Font,
            RequestKind::Xhr,
            RequestKind::Media,
        ] {
            let response = blocked(kind, "https://ads.example/x");
            assert_eq!(response.status, 204, "{kind:?} must stay a 204");
            assert!(response.body.is_empty());
        }
    }

    #[test]
    fn a_blocked_subresource_is_an_empty_204() {
        let response = blocked_subresource();
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
        let rendered = String::from_utf8(response.render(false)).expect("utf-8");
        assert!(rendered.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert!(rendered.contains("Content-Length: 0\r\n"));
        assert!(rendered.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_redirect_carries_its_own_type_and_body() {
        let response = redirected(&redirect("application/javascript", b"void 0;"));
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/javascript");
        assert_eq!(response.body, b"void 0;");
        let rendered = String::from_utf8(response.render(false)).expect("utf-8");
        assert!(rendered.contains("Content-Length: 7\r\n"));
        assert!(rendered.ends_with("void 0;"));
    }

    #[test]
    fn head_only_keeps_the_content_length() {
        let response = blocked_page("http://ads.example.com/x");
        let expected_len = response.body.len();
        let rendered = String::from_utf8(response.render(true)).expect("utf-8");
        assert!(rendered.contains(&format!("Content-Length: {expected_len}\r\n")));
        assert!(
            rendered.ends_with("\r\n\r\n"),
            "a HEAD response must carry no body"
        );

        let subresource = blocked_subresource();
        assert_eq!(subresource.render(true), subresource.render(false), "204 has no body either way");
    }

    #[test]
    fn responses_do_not_close_the_connection() {
        // A blocked request must not tear down a keep-alive connection: a page multiplexed over six
        // connections would otherwise reconnect six times per blocked ad.
        for response in [
            blocked_page("http://x.example/"),
            blocked_subresource(),
            redirected(&redirect("text/css", b"")),
        ] {
            let rendered = String::from_utf8(response.render(false)).expect("utf-8");
            assert!(
                !rendered.contains("Connection: close"),
                "a synthesized response must keep the connection usable: {rendered}"
            );
        }
    }

    #[test]
    fn every_response_states_an_exact_content_length() {
        // Without an exact length a client cannot find the next response on a keep-alive connection.
        for response in [
            blocked_page("http://x.example/"),
            blocked_subresource(),
            redirected(&redirect("text/css", b"a{b:c}")),
        ] {
            let rendered = String::from_utf8(response.render(false)).expect("utf-8");
            let expected = format!("Content-Length: {}\r\n", response.body.len());
            assert!(rendered.contains(&expected), "{rendered}");
        }
    }

    #[test]
    fn the_blocked_page_is_not_cached() {
        // A cached block would survive a rule change and keep a page broken after the user allowed
        // it, so the navigation page is explicitly not storable.
        let rendered = String::from_utf8(blocked_page("http://x.example/").render(false)).expect("utf-8");
        assert!(rendered.contains("Cache-Control: no-store\r\n"));
    }

    #[test]
    fn unknown_mime_types_degrade_to_octet_stream() {
        assert_eq!(static_mime("application/javascript"), "application/javascript");
        assert_eq!(static_mime("text/javascript"), "application/javascript");
        assert_eq!(static_mime("image/gif"), "image/gif");
        assert_eq!(static_mime("application/x-shockwave-flash"), "application/octet-stream");
        assert_eq!(static_mime(""), "application/octet-stream");
    }

    #[test]
    fn the_rendered_head_is_well_formed() {
        let rendered = String::from_utf8(blocked_subresource().render(false)).expect("utf-8");
        let (head, rest) = rendered.split_once("\r\n\r\n").expect("head terminator");
        assert!(rest.is_empty());
        for line in head.split("\r\n").skip(1) {
            assert!(line.contains(": "), "bad header line {line:?}");
        }
    }
}
