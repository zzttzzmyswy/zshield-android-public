//! Request-type inference: what kind of resource is this request for?
//!
//! adblock rules are type-scoped (`$script`, `$image`, `$document`, ...), so the type has to be
//! inferred from the request itself. There are two signals, and they are not equal:
//!
//! 1. **`Sec-Fetch-Dest`** (Fetch Metadata, `draft-ietf-httpbis-fetch`). It is set by the browser and
//!    says exactly what the resource is for, so it wins whenever it is present and known.
//! 2. **`Accept`**. Only a fallback: `Accept` describes what the client will *do* with the answer,
//!    not what the element is, and many clients send `*/*` for everything.
//!
//! With neither, [`RequestKind::Other`] is returned rather than a guess. Guessing `document` would
//! let `$document` rules block ordinary subresources; guessing `subdocument` would miss them the
//! other way. `$script`-style rules are much more common than type-agnostic ones, so a wrong guess
//! is worse than no guess — adblock-rust matches type-agnostic rules against `Other` exactly as
//! against any other type.
//!
//! Deliberately *not* used: the URL's file extension. `ads.js` in a URL says nothing about what the
//! server returns, and lists rely on the type being the real one.

use crate::http::head::HttpRequest;

/// Resource type of one request, mirroring the adblock resource types this core can determine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Top-level navigation.
    Document,
    /// Frame navigation.
    Subdocument,
    Script,
    Stylesheet,
    Image,
    /// Audio or video element/stream.
    Media,
    Font,
    /// `fetch()` / `XMLHttpRequest`.
    Xhr,
    /// `WebSocket` handshake.
    Websocket,
    /// `ping` / `sendBeacon`.
    Ping,
    /// Plugin/embed content (`<object>`, `<embed>`).
    Object,
    /// Anything not identified above, including requests with no hint at all.
    Other,
}

impl RequestKind {
    /// The spelling adblock-rust's `Request::preparsed` understands.
    pub fn as_str(self) -> &'static str {
        match self {
            RequestKind::Document => "document",
            RequestKind::Subdocument => "subdocument",
            RequestKind::Script => "script",
            RequestKind::Stylesheet => "stylesheet",
            RequestKind::Image => "image",
            RequestKind::Media => "media",
            RequestKind::Font => "font",
            RequestKind::Xhr => "xmlhttprequest",
            RequestKind::Websocket => "websocket",
            RequestKind::Ping => "ping",
            RequestKind::Object => "object",
            RequestKind::Other => "other",
        }
    }

    /// True for the kinds whose blocked body is an HTML page rather than an empty response.
    ///
    /// A navigation has to render something; a subresource's caller only looks at the status, its
    /// headers and (for a redirect substitute) the body.
    pub fn is_navigation(self) -> bool {
        matches!(self, RequestKind::Document | RequestKind::Subdocument)
    }

    /// Map a `Sec-Fetch-Dest` value. `None` when the value is unknown to this table.
    pub fn from_fetch_dest(dest: &str) -> Option<Self> {
        let kind = match dest.trim().to_ascii_lowercase().as_str() {
            "document" => RequestKind::Document,
            "iframe" | "frame" | "embed" | "subdocument" => RequestKind::Subdocument,
            "script" | "worker" | "sharedworker" | "serviceworker" => RequestKind::Script,
            "style" | "stylesheet" => RequestKind::Stylesheet,
            "image" => RequestKind::Image,
            "video" | "audio" | "track" => RequestKind::Media,
            "font" => RequestKind::Font,
            "empty" => RequestKind::Xhr,
            "object" => RequestKind::Object,
            "report" => RequestKind::Ping,
            // `manifest` is fetched like an XHR by every browser that supports it.
            "manifest" => RequestKind::Xhr,
            // Known-but-irrelevant destinations: the request is still a subresource, we just have
            // no sharper type for it.
            "fencedframe" | "audio-worklet" | "paintworklet" => RequestKind::Other,
            _ => return None,
        };
        Some(kind)
    }

    /// Map an `Accept` header value. Only used when `Sec-Fetch-Dest` is absent.
    pub fn from_accept(accept: &str) -> Option<Self> {
        let accept = accept.to_ascii_lowercase();
        // Ordered by specificity: the first matching family wins. `*/*` alone says nothing.
        if accept.contains("text/event-stream") {
            // An `EventSource` is an XHR-shaped long-lived request.
            return Some(RequestKind::Xhr);
        }
        if accept.contains("text/html") || accept.contains("application/xhtml+xml") {
            return Some(RequestKind::Document);
        }
        if accept.contains("text/css") {
            return Some(RequestKind::Stylesheet);
        }
        if accept.contains("image/") {
            return Some(RequestKind::Image);
        }
        if accept.contains("video/") || accept.contains("audio/") {
            return Some(RequestKind::Media);
        }
        if accept.contains("font/") || accept.contains("application/font") {
            return Some(RequestKind::Font);
        }
        if accept.contains("javascript") || accept.contains("ecmascript") {
            return Some(RequestKind::Script);
        }
        None
    }
}

/// Infer the request type for `request`.
///
/// `CONNECT` is a tunnel, not a resource; it is reported as [`RequestKind::Other`] and the relay
/// never asks for a decision on it in the first place.
pub fn infer(request: &HttpRequest) -> RequestKind {
    if let Some(dest) = request.fetch_dest.as_deref() {
        if let Some(kind) = RequestKind::from_fetch_dest(dest) {
            return kind;
        }
        // An unknown `Sec-Fetch-Dest` still means "a browser told us what this is"; falling through
        // to `Accept` on a value we do not know would only replace it with a weaker signal.
        return RequestKind::Other;
    }
    if let Some(accept) = request.accept.as_deref() {
        if let Some(kind) = RequestKind::from_accept(accept) {
            return kind;
        }
    }
    RequestKind::Other
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(fetch_dest: Option<&str>, accept: Option<&str>) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            target: "/x".to_string(),
            version: crate::http::head::Version::Http11,
            url: "http://example.com/x".to_string(),
            host: "example.com".to_string(),
            hostname: "example.com".to_string(),
            referer: None,
            fetch_dest: fetch_dest.map(str::to_string),
            fetch_site: None,
            fetch_user: None,
            accept: accept.map(str::to_string),
            content_length: None,
            chunked: false,
            upgrade: false,
            expect_continue: false,
            head_len: 0,
        }
    }

    #[test]
    fn the_fetch_dest_table_is_complete() {
        let cases = [
            ("document", RequestKind::Document),
            ("iframe", RequestKind::Subdocument),
            ("frame", RequestKind::Subdocument),
            ("embed", RequestKind::Subdocument),
            ("script", RequestKind::Script),
            ("worker", RequestKind::Script),
            ("serviceworker", RequestKind::Script),
            ("style", RequestKind::Stylesheet),
            ("image", RequestKind::Image),
            ("video", RequestKind::Media),
            ("audio", RequestKind::Media),
            ("track", RequestKind::Media),
            ("font", RequestKind::Font),
            ("empty", RequestKind::Xhr),
            ("object", RequestKind::Object),
            ("report", RequestKind::Ping),
            ("manifest", RequestKind::Xhr),
            ("fencedframe", RequestKind::Other),
        ];
        for (dest, expected) in cases {
            assert_eq!(
                RequestKind::from_fetch_dest(dest),
                Some(expected),
                "Sec-Fetch-Dest: {dest}"
            );
        }
        assert_eq!(RequestKind::from_fetch_dest("nonsense"), None);
        // Case and padding are the client's business, not the table's.
        assert_eq!(
            RequestKind::from_fetch_dest("  SCRIPT "),
            Some(RequestKind::Script)
        );
    }

    #[test]
    fn the_accept_fallback_table_is_ordered_by_specificity() {
        assert_eq!(
            RequestKind::from_accept("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            Some(RequestKind::Document)
        );
        assert_eq!(
            RequestKind::from_accept("text/css,*/*;q=0.1"),
            Some(RequestKind::Stylesheet)
        );
        assert_eq!(
            RequestKind::from_accept("image/avif,image/webp,image/*,*/*;q=0.8"),
            Some(RequestKind::Image)
        );
        assert_eq!(
            RequestKind::from_accept("video/webm,video/ogg,*/*;q=0.9"),
            Some(RequestKind::Media)
        );
        assert_eq!(
            RequestKind::from_accept("font/woff2,*/*;q=0.1"),
            Some(RequestKind::Font)
        );
        assert_eq!(
            RequestKind::from_accept("text/javascript, application/javascript"),
            Some(RequestKind::Script)
        );
        assert_eq!(
            RequestKind::from_accept("text/event-stream"),
            Some(RequestKind::Xhr)
        );
        // `*/*` says nothing.
        assert_eq!(RequestKind::from_accept("*/*"), None);
        assert_eq!(RequestKind::from_accept("application/json"), None);
    }

    #[test]
    fn fetch_dest_wins_over_accept() {
        // A `fetch()` of an HTML-ish URL: `Sec-Fetch-Dest: empty` is authoritative.
        assert_eq!(
            infer(&request(Some("empty"), Some("text/html"))),
            RequestKind::Xhr
        );
        // A script element whose `Accept` looks like a document.
        assert_eq!(
            infer(&request(Some("script"), Some("text/html"))),
            RequestKind::Script
        );
    }

    #[test]
    fn accept_is_used_only_without_a_fetch_dest() {
        assert_eq!(
            infer(&request(None, Some("text/css"))),
            RequestKind::Stylesheet
        );
        assert_eq!(infer(&request(None, Some("image/png"))), RequestKind::Image);
    }

    #[test]
    fn no_hint_at_all_is_other_not_a_guess() {
        assert_eq!(infer(&request(None, None)), RequestKind::Other);
        assert_eq!(infer(&request(None, Some("*/*"))), RequestKind::Other);
        // An unrecognised-but-present `Sec-Fetch-Dest` does not fall back to `Accept`.
        assert_eq!(
            infer(&request(Some("mystery"), Some("text/html"))),
            RequestKind::Other
        );
    }

    #[test]
    fn only_navigations_get_an_html_body() {
        assert!(RequestKind::Document.is_navigation());
        assert!(RequestKind::Subdocument.is_navigation());
        for kind in [
            RequestKind::Script,
            RequestKind::Stylesheet,
            RequestKind::Image,
            RequestKind::Media,
            RequestKind::Font,
            RequestKind::Xhr,
            RequestKind::Websocket,
            RequestKind::Ping,
            RequestKind::Object,
            RequestKind::Other,
        ] {
            assert!(!kind.is_navigation(), "{kind:?}");
        }
    }

    #[test]
    fn wire_spellings_match_adblock() {
        // These are the strings `Request::preparsed` maps through `cpt_match_type`.
        for (kind, expected) in [
            (RequestKind::Document, "document"),
            (RequestKind::Subdocument, "subdocument"),
            (RequestKind::Script, "script"),
            (RequestKind::Stylesheet, "stylesheet"),
            (RequestKind::Image, "image"),
            (RequestKind::Media, "media"),
            (RequestKind::Font, "font"),
            (RequestKind::Xhr, "xmlhttprequest"),
            (RequestKind::Websocket, "websocket"),
            (RequestKind::Ping, "ping"),
            (RequestKind::Object, "object"),
            (RequestKind::Other, "other"),
        ] {
            assert_eq!(kind.as_str(), expected);
        }
    }
}
