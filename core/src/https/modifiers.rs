//! The rule modifiers that only make sense once a request has been decrypted (task card §3).
//!
//! `adblock-rust` resolves `$csp` internally and `$redirect` through `http::decision`. `$removeheader` it
//! does not implement at all, and `$removeparam` it implements only partially — and even the part it does
//! implement cannot be composed with the rest, for the reason [`removeparam_url`] sets out. Both are
//! therefore decided here.
//!
//! | Modifier | Where it is applied |
//! |---|---|
//! | `$removeparam` | the whole family evaluated by [`crate::https::extras::RemoveParamRules`]; subresource rewritten in place, navigation via a `302` |
//! | `$removeheader` | request head and response head (this module) |
//! | `$csp` | `Content-Security-Policy` appended to a document response |
//! | `$redirect` | `http::decision` (the substitute body is served locally) |
//!
//! # How `$removeheader` is evaluated without forking the engine
//!
//! Every line carrying `$removeheader=<name>` is re-parsed with the option **removed** — so
//! `||a.example^$removeheader=refresh,script` becomes `||a.example^$script` — and the resulting
//! rules are compiled into one small `adblock::Engine` per distinct header name. A request then asks
//! that engine whether it matches, which is the engine's own `should_block()` answer.
//!
//! That is deliberate: reimplementing the pattern/domain/type matcher here would drift from the
//! engine's semantics the first time either side changes, and `$removeheader` rules in real lists
//! carry `$domain=`, content types and exceptions exactly like blocking rules do. The per-header
//! engine keeps the grouping because a *set* of rules sharing one header name can be answered with
//! one query, and a request that matches any of them loses that header.
//!
//! Memory is not a concern: the subset is a handful of rules per list, against the tens of
//! thousands the main engine holds.

use std::collections::BTreeMap;

use std::sync::Arc;

use crate::http::decision::HttpFilter;
use crate::http::head::HttpRequest;
use crate::http::resource::RequestKind;

/// The modifier that adblock-rust does not implement, and that this module therefore evaluates.
pub const UNSUPPORTED_MODIFIER: &str = "removeheader";

/// One `$removeheader` rule that parsed successfully, kept for the delivery note and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveHeaderRule {
    /// The rule's own text, as it appeared in the list.
    pub text: String,
    /// The header name to drop, lowercased.
    pub header: String,
    /// The rule with `$removeheader=...` removed, which is what the engine parses.
    pub stripped: String,
}

/// A rule that named `$removeheader` but could not be turned into something the engine accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRule {
    pub text: String,
    pub reason: String,
}

/// The `$removeheader` rule set.
#[derive(Default)]
pub struct RemoveHeaderRules {
    rules: Vec<RemoveHeaderRule>,
    rejected: Vec<RejectedRule>,
    /// One engine per header name, built lazily from `rules`.
    engines: BTreeMap<String, adblock::Engine>,
}

impl std::fmt::Debug for RemoveHeaderRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoveHeaderRules")
            .field("rules", &self.rules.len())
            .field("headers", &self.header_names())
            .field("rejected", &self.rejected.len())
            .finish()
    }
}

impl RemoveHeaderRules {
    /// Extract every `$removeheader` rule from one list body.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
                continue;
            }
            let Some((header, stripped)) = strip_removeheader(trimmed) else {
                continue;
            };
            if header.is_empty() {
                self.rejected.push(RejectedRule {
                    text: trimmed.to_string(),
                    reason: "empty header name".to_string(),
                });
                continue;
            }
            if stripped.is_empty() {
                self.rejected.push(RejectedRule {
                    text: trimmed.to_string(),
                    reason: "the rule carries no pattern once $removeheader is removed".to_string(),
                });
                continue;
            }
            self.rules.push(RemoveHeaderRule {
                text: trimmed.to_string(),
                header: header.to_ascii_lowercase(),
                stripped,
            });
        }
        // The engines are derived state; rebuild them so a second `add_list` call cannot leave a
        // stale one in place.
        self.engines.clear();
    }

    /// Compile the per-header engines. Called once after all lists are loaded.
    pub fn build(&mut self) {
        self.engines.clear();
        let mut grouped: BTreeMap<String, adblock::lists::FilterSet> = BTreeMap::new();
        for rule in &self.rules {
            let set = grouped
                .entry(rule.header.clone())
                .or_insert_with(|| adblock::lists::FilterSet::new(false));
            set.add_filter_list(
                rule.stripped.clone(),
                adblock::lists::ParseOptions::default(),
            );
        }
        for (header, set) in grouped {
            self.engines
                .insert(header, adblock::Engine::new_with_filter_set(set));
        }
    }

    /// Header names to drop for this request, sorted and deduplicated.
    pub fn headers_to_remove(&self, request: &HttpRequest, kind: RequestKind) -> Vec<String> {
        if self.engines.is_empty() {
            return Vec::new();
        }
        let adblock_request = crate::http::decision::to_adblock_request(request, kind);
        let mut out = Vec::new();
        for (header, engine) in &self.engines {
            if engine.check_network_request(&adblock_request).should_block() {
                out.push(header.clone());
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[RemoveHeaderRule] {
        &self.rules
    }

    pub fn rejected(&self) -> &[RejectedRule] {
        &self.rejected
    }

    /// Distinct header names in force.
    pub fn header_names(&self) -> Vec<&str> {
        self.engines.keys().map(String::as_str).collect()
    }
}

/// Split a `$removeheader` rule into `(header name, rule text with the option removed)`.
///
/// Returns `None` when the line does not carry `$removeheader` at all, which is the common case and
/// has to stay cheap: it is one `split_once` and a scan of the options.
fn strip_removeheader(line: &str) -> Option<(String, String)> {
    let (pattern, options) = line.split_once('$')?;
    let mut header: Option<String> = None;
    let mut kept: Vec<&str> = Vec::new();
    for option in options.split(',') {
        let option = option.trim();
        if option.is_empty() {
            continue;
        }
        if let Some(value) = option.strip_prefix("removeheader=") {
            header = Some(value.trim().to_string());
        } else if option == "removeheader" {
            header = Some(String::new());
        } else {
            kept.push(option);
        }
    }
    let header = header?;
    let stripped = if kept.is_empty() {
        pattern.to_string()
    } else {
        format!("{pattern}${}", kept.join(","))
    };
    Some((header, stripped))
}

/// The [`ModifierSource`] a decrypted connection uses.
///
/// Wraps the two halves — the adblock engine's own modifiers (`$removeparam`, `$csp`) and the
/// `$removeheader` rules the engine does not implement — behind the one trait the HTTP/1.1 relay and
/// the HTTP/2 relay both call.
#[derive(Debug)]
pub struct HttpsModifiers {
    filter: Arc<HttpFilter>,
    removeheader: Arc<RemoveHeaderRules>,
}

impl HttpsModifiers {
    /// `extras` is accepted for call-site symmetry and **ignored**: see [`Self::extras_arc`].
    pub fn new(
        filter: Arc<HttpFilter>,
        removeheader: Arc<RemoveHeaderRules>,
        extras: Arc<crate::https::extras::ExtraModifiers>,
    ) -> Self {
        let _ = extras;
        Self {
            filter,
            removeheader,
        }
    }

    /// The `$removeheader` rules in force, so a caller can report them.
    pub fn removeheader(&self) -> &RemoveHeaderRules {
        &self.removeheader
    }

    /// The rule set in force, read from the filter **on every call**.
    ///
    /// # Why this is not a field
    ///
    /// A stored `Arc<ExtraModifiers>` is a **snapshot** taken when the HTTPS pipeline was built, and
    /// `HttpFilter::replace_extras` — which a compile runs after every list or user-rule edit — only
    /// updates the filter. The decrypted path therefore kept answering from the rule set the tunnel
    /// started with. Measured on device: the compile logged 198 `removeparam` rules while decrypted
    /// requests were decided by 178, i.e. every rule the user had just added was invisible over HTTPS
    /// — and HTTPS is the only path the test pages use. Anything reached through here has to read the
    /// live set.
    fn extras_arc(&self) -> Arc<crate::https::extras::ExtraModifiers> {
        self.filter.extras()
    }
}

#[allow(unused_imports)]
use crate::http::rewrite::ModifierSource as _;

impl crate::http::rewrite::ModifierSource for HttpsModifiers {
    fn edits(
        &self,
        request: &HttpRequest,
        kind: RequestKind,
    ) -> Option<crate::http::rewrite::Edits> {
        let (decision, rewritten_url, csp) =
            crate::http::decision::decide_full(&self.filter.engine(), request, kind);
        // A blocked request never reaches the network, so rewriting its URL or annotating its
        // response would be work with no effect — and the block path owns the response.
        if decision.block {
            return None;
        }
        let headers = self.removeheader.headers_to_remove(request, kind);
        let extras = self.extras_arc();
        let url = removeparam_url(&extras, request, kind, rewritten_url.as_deref());
        let mut edits = crate::http::rewrite::Edits {
            url,
            drop_request_headers: headers.clone(),
            drop_response_headers: headers,
            csp,
        };
        if edits.is_empty() {
            return None;
        }
        // A rewrite that changed the host is not something any of these modifiers means; forwarding
        // it would turn the request into a proxy request for another site.
        if let Some(url) = edits.url.as_deref() {
            if !crate::http::rewrite::same_authority(request, url) {
                edits.url = None;
            }
        }
        if edits.is_empty() {
            None
        } else {
            Some(edits)
        }
    }
}

/// Everything one HTTPS request needs, in one engine query plus one `$removeheader` query per
/// header name.
///
/// The HTTP/2 leg uses this directly (it builds its own frames, so it cannot use the HTTP/1.1
/// rewriter); the HTTP/1.1 leg goes through [`HttpsModifiers`] and
/// [`crate::http::relay`], which is what keeps the two protocols deciding identically.
pub fn evaluate(
    filter: &HttpFilter,
    removeheader: &RemoveHeaderRules,
    request: &HttpRequest,
    kind: RequestKind,
) -> (crate::http::decision::FilterDecision, crate::http::rewrite::Edits) {
    let (decision, rewritten_url, csp) = crate::http::decision::decide_full(&filter.engine(), request, kind);
    let mut edits = crate::http::rewrite::Edits::default();
    if !decision.block {
        edits.url = removeparam_url(
            &filter.extras(),
            request,
            kind,
            rewritten_url.as_deref(),
        );
        edits.csp = csp;
        let headers = removeheader.headers_to_remove(request, kind);
        edits.drop_request_headers = headers.clone();
        edits.drop_response_headers = headers;
    }
    (decision, edits)
}

/// The URL `$removeparam` leaves for this request, or `None` when it leaves it alone.
///
/// # Why the rule set decides, not the engine's output
///
/// `adblock-rust` applies the `$removeparam` forms its parser accepts and hands back a finished URL. That
/// URL cannot be the basis for this modifier, because it does not say **which** rule removed **which**
/// parameter occurrence: repairing it therefore had to guess from parameter *names*, which cannot tell a
/// typed rule from an untyped one on the same name, a value-sensitive regex from a name rule, or a rule
/// whose `$domain=` does not match from one whose does. The second review reproduced five wrong answers
/// that all came from exactly that guessing.
///
/// [`crate::https::extras::RemoveParamRules::rewrite`] therefore evaluates the whole family from the
/// request's own URL and the complete set of rules in force, and its answer is the one used here. The
/// engine's `rewritten_url` is consulted in exactly one situation — when this core holds **no**
/// `$removeparam` rule at all, i.e. there is nothing to evaluate (the artifact set did not load, or a
/// caller built the filter without one). Then the engine's own answer is forwarded untouched rather than
/// dropped, which keeps a degraded artifact set filtering instead of silently doing nothing.
fn removeparam_url(
    extras: &crate::https::extras::ExtraModifiers,
    request: &HttpRequest,
    kind: RequestKind,
    engine_url: Option<&str>,
) -> Option<String> {
    let rules = &extras.removeparam;
    if !rules.is_empty() {
        return rules.rewrite(request, kind);
    }
    engine_url
        .map(str::to_string)
        .filter(|url| url != &request.url)
}

/// Parse the `$removeheader` rules out of a set of list bodies and compile them.
pub fn collect_removeheader<'a>(lists: impl IntoIterator<Item = &'a str>) -> RemoveHeaderRules {
    let mut rules = RemoveHeaderRules::default();
    for text in lists {
        rules.add_list(text);
    }
    rules.build();
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::head::Version;

    fn request(url: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
        let parsed = adblock::url_parser::parse_url(url).expect("test URL");
        // The production request model always carries a lowercased hostname (`head::hostname_of`),
        // and the engine's matcher is case-sensitive on it, so the fixture does the same.
        let hostname = parsed.hostname().to_ascii_lowercase();
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: Version::Http11,
            url: parsed.url.clone(),
            host: hostname.clone(),
            hostname,
            referer: referer.map(str::to_string),
            fetch_dest: Some(kind.as_str().to_string()),
            fetch_site: None,
            fetch_user: None,
            accept: None,
            content_length: None,
            chunked: false,
            upgrade: false,
            expect_continue: false,
            head_len: 0,
        }
    }

    fn filter(rules: &str) -> HttpFilter {
        let mut set = adblock::lists::FilterSet::new(true);
        set.add_filter_list(rules.to_string(), adblock::lists::ParseOptions::default());
        HttpFilter::new(adblock::Engine::new_with_filter_set(set))
    }

    fn removeheader(rules: &str) -> RemoveHeaderRules {
        collect_removeheader([rules])
    }

    #[test]
    fn the_option_is_stripped_and_the_rest_of_the_rule_survives() {
        assert_eq!(
            strip_removeheader("||a.example^$removeheader=refresh"),
            Some(("refresh".to_string(), "||a.example^".to_string()))
        );
        assert_eq!(
            strip_removeheader("||a.example^$removeheader=set-cookie,script"),
            Some(("set-cookie".to_string(), "||a.example^$script".to_string()))
        );
        assert_eq!(
            strip_removeheader("||a.example^$script,removeheader=x-test"),
            Some(("x-test".to_string(), "||a.example^$script".to_string()))
        );
        assert_eq!(
            strip_removeheader("||a.example^$removeheader=refresh,domain=site.example"),
            Some((
                "refresh".to_string(),
                "||a.example^$domain=site.example".to_string()
            ))
        );
        // A line without the option is not ours.
        assert_eq!(strip_removeheader("||a.example^$script"), None);
        assert_eq!(strip_removeheader("||a.example^"), None);
        // `$removeheader` with no value names no header.
        assert_eq!(
            strip_removeheader("||a.example^$removeheader"),
            Some((String::new(), "||a.example^".to_string()))
        );
    }

    #[test]
    fn removeheader_rules_are_matched_per_host() {
        let rules = removeheader(
            "! comment\n\
             ||ads.example.com^$removeheader=refresh\n\
             ||tracker.example^$removeheader=Set-Cookie\n",
        );
        assert_eq!(rules.len(), 2, "rejected: {:?}", rules.rejected());
        assert!(rules.rejected().is_empty());
        assert_eq!(rules.header_names(), vec!["refresh", "set-cookie"]);

        let headers = rules.headers_to_remove(
            &request(
                "https://ads.example.com/x.js",
                Some("https://site.example/"),
                RequestKind::Script,
            ),
            RequestKind::Script,
        );
        assert_eq!(headers, vec!["refresh".to_string()]);

        // Case is normalised on the rule side; host matching is the engine's.
        let headers = rules.headers_to_remove(
            &request(
                "https://TRACKER.example/p.gif",
                Some("https://site.example/"),
                RequestKind::Image,
            ),
            RequestKind::Image,
        );
        assert_eq!(headers, vec!["set-cookie".to_string()]);

        assert!(rules
            .headers_to_remove(
                &request(
                    "https://other.example/x",
                    Some("https://site.example/"),
                    RequestKind::Script
                ),
                RequestKind::Script
            )
            .is_empty());
    }

    #[test]
    fn removeheader_honours_content_type_and_domain_options() {
        // The point of routing through the engine: `$script`, `$subdocument` and `$domain=` keep
        // their meaning, so the header is only dropped where the list author said.
        let rules = removeheader(
            "||api.example^$removeheader=refresh,script\n\
             ||api.example^$removeheader=x-frame-options,subdocument\n\
             ||api.example^$removeheader=x-powered-by,domain=site.example\n",
        );
        assert_eq!(rules.len(), 3, "{:?}", rules.rejected());

        // A request that matches several rules loses every one of those headers: the type option
        // narrows a rule, it does not exclude the others.
        let script = request(
            "https://api.example/a.js",
            Some("https://site.example/"),
            RequestKind::Script,
        );
        assert_eq!(
            rules.headers_to_remove(&script, RequestKind::Script),
            vec!["refresh".to_string(), "x-powered-by".to_string()]
        );

        // A `$subdocument` rule and an unscoped-`$domain=` rule both apply to a frame from that
        // site; the type option narrows a rule, it does not exclude the others.
        let frame = request(
            "https://api.example/frame",
            Some("https://site.example/"),
            RequestKind::Subdocument,
        );
        assert_eq!(
            rules.headers_to_remove(&frame, RequestKind::Subdocument),
            vec!["x-frame-options".to_string(), "x-powered-by".to_string()]
        );

        // The `$domain=` rule only fires from that site.
        let from_site = request(
            "https://api.example/x",
            Some("https://site.example/page"),
            RequestKind::Xhr,
        );
        assert_eq!(
            rules.headers_to_remove(&from_site, RequestKind::Xhr),
            vec!["x-powered-by".to_string()]
        );
        let from_elsewhere = request(
            "https://api.example/x",
            Some("https://other.example/page"),
            RequestKind::Xhr,
        );
        assert!(
            rules
                .headers_to_remove(&from_elsewhere, RequestKind::Xhr)
                .is_empty(),
            "a `$domain=` scoped rule must not fire on another source"
        );
        // ... and not without a source either (same first-party rule as `http::decision`).
        let no_source = request("https://api.example/x", None, RequestKind::Xhr);
        assert!(rules
            .headers_to_remove(&no_source, RequestKind::Xhr)
            .is_empty());
    }

    #[test]
    fn an_exception_cancels_a_removeheader_rule() {
        // `@@` has to work the same way it does for a block, because that is how a list author
        // disables a rule they shipped earlier.
        let rules = removeheader(
            "||a.example^$removeheader=refresh\n@@||a.example/keep^$removeheader=refresh\n",
        );
        assert_eq!(rules.len(), 2);
        let blocked = request(
            "https://a.example/x",
            Some("https://site.example/"),
            RequestKind::Document,
        );
        assert_eq!(
            rules.headers_to_remove(&blocked, RequestKind::Document),
            vec!["refresh".to_string()]
        );
        let excepted = request(
            "https://a.example/keep/page",
            Some("https://site.example/"),
            RequestKind::Document,
        );
        assert!(
            rules
                .headers_to_remove(&excepted, RequestKind::Document)
                .is_empty(),
            "the `@@` exception must cancel the removal"
        );
    }

    #[test]
    fn an_empty_removeheader_value_is_reported() {
        let rules = removeheader("||a.example^$removeheader=\n||b.example^$removeheader\n");
        assert_eq!(rules.len(), 0);
        assert_eq!(rules.rejected().len(), 2);
        assert_eq!(rules.rejected()[0].reason, "empty header name");
    }

    #[test]
    fn a_rule_that_names_only_the_option_is_reported() {
        let rules = removeheader("$removeheader=refresh\n");
        assert_eq!(rules.len(), 0);
        assert_eq!(rules.rejected().len(), 1);
        assert!(rules.rejected()[0].reason.contains("no pattern"));
    }

    #[test]
    fn a_document_request_gets_a_csp_and_a_rewritten_url() {
        let filter = filter(
            "||site.example^$csp=script-src 'none'\n\
             ||site.example^$removeparam=utm_source\n",
        );
        let rules = RemoveHeaderRules::default();
        let target = request(
            "https://site.example/page?utm_source=x&keep=1",
            Some("https://site.example/"),
            RequestKind::Document,
        );
        let (decision, edits) = evaluate(&filter, &rules, &target, RequestKind::Document);
        assert!(!decision.block);
        assert_eq!(
            edits.url.as_deref(),
            Some("https://site.example/page?keep=1")
        );
        assert_eq!(edits.csp.as_deref(), Some("script-src 'none'"));
    }

    #[test]
    fn a_request_with_no_matching_parameter_is_not_rewritten() {
        // The distinction matters: a rewrite that changes nothing would turn a subresource into a
        // pointless extra request.
        let filter = filter("||site.example^$removeparam=utm_source\n");
        let rules = RemoveHeaderRules::default();
        let target = request(
            "https://site.example/page?keep=1",
            Some("https://site.example/"),
            RequestKind::Document,
        );
        let (_, edits) = evaluate(&filter, &rules, &target, RequestKind::Document);
        assert_eq!(edits.url, None);
        assert!(edits.is_empty());
    }

    #[test]
    fn a_blocked_request_gets_no_modifiers() {
        // Blocking wins: there is no URL to rewrite and no response to annotate.
        let filter = filter("||ads.example.com^$script\n||ads.example.com^$csp=script-src 'none'\n");
        let rules = removeheader("||ads.example.com^$removeheader=refresh\n");
        let target = request(
            "https://ads.example.com/x.js",
            Some("https://site.example/"),
            RequestKind::Script,
        );
        let (decision, edits) = evaluate(&filter, &rules, &target, RequestKind::Script);
        assert!(decision.block);
        assert!(edits.is_empty(), "{edits:?}");
    }

    #[test]
    fn a_redirect_substitute_still_carries_its_body() {
        // `$redirect` is decided in `http::decision`; make sure routing through `evaluate` keeps it.
        let filter = filter("||ads.example.com/banner.js$script,redirect=noopjs\n");
        let rules = RemoveHeaderRules::default();
        let target = request(
            "https://ads.example.com/banner.js",
            Some("https://site.example/"),
            RequestKind::Script,
        );
        let (decision, _) = evaluate(&filter, &rules, &target, RequestKind::Script);
        assert!(decision.block);
        assert!(decision.serves_redirect());
    }

    #[test]
    fn the_rule_set_is_shared_by_both_directions() {
        // A single `$removeheader` entry has to reach the request *and* the response: a list author
        // writing `set-cookie` means the response, `cookie` the request, and the rule text does not
        // distinguish them.
        let filter = filter("");
        let rules = removeheader("||a.example^$removeheader=x-test\n");
        let target = request(
            "https://a.example/x",
            Some("https://site.example/"),
            RequestKind::Document,
        );
        let (_, edits) = evaluate(&filter, &rules, &target, RequestKind::Document);
        assert_eq!(edits.drop_request_headers, vec!["x-test".to_string()]);
        assert_eq!(edits.drop_response_headers, vec!["x-test".to_string()]);
    }

    #[test]
    fn collecting_from_several_lists_keeps_every_rule() {
        let rules = collect_removeheader([
            "||a.example^$removeheader=refresh\n",
            "! nothing here\n||b.example^$removeheader=server\n",
        ]);
        assert_eq!(rules.len(), 2);
        assert!(!rules.is_empty());
        assert_eq!(rules.header_names(), vec!["refresh", "server"]);
        // The rule text is kept so the delivery note can name what a list asked for.
        assert!(rules.rules()[0].text.contains("removeheader"));
    }

    #[test]
    fn a_filter_with_no_rules_never_asks_for_a_removal() {
        let rules = RemoveHeaderRules::default();
        assert!(rules.is_empty());
        assert!(rules
            .headers_to_remove(
                &request(
                    "https://a.example/x",
                    Some("https://site.example/"),
                    RequestKind::Document
                ),
                RequestKind::Document
            )
            .is_empty());
    }

    #[test]
    fn rebuilding_after_more_lists_does_not_keep_stale_engines() {
        let mut rules = RemoveHeaderRules::default();
        rules.add_list("||a.example^$removeheader=refresh\n");
        rules.build();
        assert_eq!(rules.header_names(), vec!["refresh"]);
        rules.add_list("||b.example^$removeheader=server\n");
        rules.build();
        assert_eq!(rules.header_names(), vec!["refresh", "server"]);
    }
}

#[cfg(test)]
mod reload_tests {
    use super::*;
    use crate::http::head::{HttpRequest, Version};
    use crate::http::rewrite::ModifierSource;

    fn request(url: &str) -> HttpRequest {
        let parsed = adblock::url_parser::parse_url(url).expect("test URL");
        let hostname = parsed.hostname().to_ascii_lowercase();
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: Version::Http11,
            url: parsed.url.clone(),
            host: hostname.clone(),
            hostname,
            referer: Some("https://page.example/".to_string()),
            fetch_dest: Some("empty".to_string()),
            fetch_site: None,
            fetch_user: None,
            accept: None,
            content_length: None,
            chunked: false,
            upgrade: false,
            expect_continue: false,
            head_len: 0,
        }
    }

    #[test]
    fn a_hot_reload_reaches_the_decrypted_path() {
        // The bug this pins: `HttpsModifiers` used to hold its own `Arc<ExtraModifiers>`, taken when the
        // HTTPS pipeline was built. `HttpFilter::replace_extras` (what a compile does after every list
        // edit) updated the filter and left this path on the old rule set, so a rule the user had just
        // added was invisible over HTTPS — measured on device as "compile says 198 rules, decrypted
        // requests decide by 178".
        // The engine holds the *stripped* form of every rule (the `$removeparam` option removed):
        // `RemoveParamRules::rewrite` asks whether any of the family applies before doing any work, and
        // `edits` only consults that matcher when the engine produced no rewrite of its own. A rule set
        // with no `$removeparam` at all therefore exercises exactly the "engine silent, core decides"
        // path this test is about.
        let mut set = adblock::lists::FilterSet::new(false);
        // A `$removeparam` rule whose *form* the engine parses: it rewrites, so the engine is never a
        // blocker here, which is the situation the HTTPS path has to survive.
        set.add_filter_list(
            "||shop.example^$xmlhttprequest,removeparam=other".to_string(),
            adblock::lists::ParseOptions::default(),
        );
        let filter = Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set)));
        let modifiers = HttpsModifiers::new(
            Arc::clone(&filter),
            Arc::new(collect_removeheader(std::iter::empty())),
            Arc::clone(&filter.extras_arc()),
        );

        let target = request("https://shop.example/p?utm_source=x&keep=1");
        let kind = RequestKind::Xhr;
        assert!(
            modifiers.edits(&target, kind).is_none(),
            "no rule is in force yet, so nothing may be rewritten"
        );

        // A compile lands a new rule set.
        filter.replace_extras(Arc::new(crate::https::extras::collect([
            "||shop.example^$xmlhttprequest,removeparam=/^utm_/",
        ])));
        let edits = modifiers.edits(&target, kind).expect("an edit after the reload");
        assert_eq!(
            edits.url.as_deref(),
            Some("https://shop.example/p?keep=1"),
            "the decrypted path must see the rule set the compile just installed"
        );
    }
}
