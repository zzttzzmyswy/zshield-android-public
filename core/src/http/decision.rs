//! The filter decision for one request, and the engine handle that produces it.
//!
//! [`FilterDecision`] is the whole output of the filtering decision: whether to block, whether
//! adblock named a `$redirect` substitute, whether an `$important` rule matched, and which rules
//! fired. The relay in [`crate::http::relay`] never looks at adblock-rust types — that keeps the
//! decision testable on its own and keeps M3 (HTTPS) able to reuse it verbatim.
//!
//! # First-party default
//!
//! adblock-rust's own `Request::new` derives third-partiness from the source URL and treats an
//! unparseable source as **third-party**. That is the wrong default here: a request with no
//! `Referer` is the *first* request of a navigation, not a cross-site one, and `$third-party` rules
//! are common enough that the difference matters (task card §2: 来源缺失时按首方请求处理). The
//! request is therefore built through `Request::preparsed`, which states the party explicitly.
//!
//! # Rule attribution
//!
//! `matched_rule` / `exception_rule` come from adblock-rust's debug information, which is only
//! recorded when the engine artifact is compiled with `debug = true` (`CompileRequest::debugRules`).
//! It is off by default because it roughly doubles `engine.bin` and the engine's resident memory —
//! the numbers are in `docs/PERF.md`, and when it is off these fields are simply `None` rather than
//! guessed at.

use std::sync::{Arc, RwLock};

use adblock::request::Request;

use crate::http::head::HttpRequest;
use crate::http::resource::{self, RequestKind};
use crate::http::resources;

/// A `$redirect` substitute the caller should serve instead of blocking outright.
///
/// adblock-rust hands back a `data:` URL; the relay needs the decoded bytes plus the MIME type to
/// build a real response, so the parsing happens once here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectBody {
    /// MIME type from the `data:` URL, e.g. `application/javascript`.
    pub mime: String,
    /// Decoded body; empty for the `noop` resources.
    pub body: Vec<u8>,
    /// The `data:` URL adblock-rust produced, for the request log.
    pub data_url: String,
}

impl RedirectBody {
    /// Parse the `data:[<mime>][;base64],<data>` form adblock-rust produces.
    ///
    /// Returns `None` for anything unexpected, in which case the request is blocked normally rather
    /// than served a body we could not interpret.
    pub fn from_data_url(data_url: &str) -> Option<Self> {
        let rest = data_url.strip_prefix("data:")?;
        let (meta, payload) = rest.split_once(',')?;
        let (mime, is_base64) = match meta.strip_suffix(";base64") {
            Some(mime) => (mime, true),
            None => (meta, false),
        };
        // `;charset=...` and friends: the MIME type is the first parameter.
        let mime = mime.split(';').next().unwrap_or("").trim();
        if mime.is_empty() {
            return None;
        }
        let body = if is_base64 {
            resources::base64_decode(payload)?
        } else {
            // Percent-encoded, non-base64 data URLs are legal but not something adblock-rust emits
            // for a resource; refuse rather than serve a body that might be mangled.
            return None;
        };
        if body.len() > MAX_REDIRECT_BODY {
            return None;
        }
        Some(Self {
            mime: mime.to_string(),
            body,
            data_url: data_url.to_string(),
        })
    }
}

/// Largest redirect body served. Every built-in resource is far below this; the bound only exists so
/// a filter list cannot make the tunnel hold an arbitrary blob.
const MAX_REDIRECT_BODY: usize = 64 * 1024;

/// What to do with one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterDecision {
    /// The request must not reach the network.
    pub block: bool,
    /// A built-in substitute to serve instead (`$redirect`), when one was named.
    pub redirect: Option<RedirectBody>,
    /// An `$important` rule matched, so exceptions do not apply.
    pub important: bool,
    /// The blocking rule, when the engine carries rule text (see the module docs).
    pub matched_rule: Option<String>,
    /// The exception rule that cancelled a block, when there was one.
    pub exception_rule: Option<String>,
}

impl FilterDecision {
    /// True when the request is blocked *and* a substitute should be served.
    pub fn serves_redirect(&self) -> bool {
        self.block && self.redirect.is_some()
    }
}

/// The runtime rule engine for plaintext HTTP, swappable while the tunnel runs.
///
/// Mirrors the DNS side (`dns::engine::Engine::filter`): the `RwLock` is only ever taken to clone an
/// `Arc`, so a reload cannot make one request be judged by two rule sets.
pub struct HttpFilter {
    engine: RwLock<Arc<adblock::Engine>>,
    /// The modifiers the pinned engine refuses, evaluated by this core
    /// ([`crate::https::extras`]). Empty until a caller installs them, which is why every accessor
    /// tolerates the empty set.
    extras: RwLock<Arc<crate::https::extras::ExtraModifiers>>,
}

impl std::fmt::Debug for HttpFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpFilter").finish_non_exhaustive()
    }
}

impl HttpFilter {
    /// Wrap an engine, registering the built-in `$redirect` substitutes.
    ///
    /// Without the resources a `$redirect=noopjs` rule would silently become a plain block (the
    /// engine logs and drops the redirect), which is why they are registered here rather than by the
    /// caller.
    pub fn new(mut engine: adblock::Engine) -> Self {
        engine.use_resources(resources::builtin_resources());
        Self {
            engine: RwLock::new(Arc::new(engine)),
            extras: RwLock::new(Arc::new(crate::https::extras::ExtraModifiers::default())),
        }
    }

    /// Wrap an engine that already has its resources registered.
    pub fn from_engine(engine: Arc<adblock::Engine>) -> Self {
        Self {
            engine: RwLock::new(engine),
            extras: RwLock::new(Arc::new(crate::https::extras::ExtraModifiers::default())),
        }
    }

    /// Attach the rules this core evaluates itself.
    ///
    /// Done after construction because the rules are compiled from the same list text the engine was,
    /// and a caller that has no artifacts (the tests, the plaintext-only path) must still be able to
    /// build a working filter.
    pub fn with_extras(self, extras: Arc<crate::https::extras::ExtraModifiers>) -> Self {
        self.replace_extras(extras);
        self
    }

    /// The `$popup`/`$denyallow`/`$removeparam` rules in force.
    pub fn extras(&self) -> Arc<crate::https::extras::ExtraModifiers> {
        Arc::clone(&self.extras.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// A handle to the same rule set, for the pipeline that wraps this filter.
    pub fn extras_arc(&self) -> Arc<crate::https::extras::ExtraModifiers> {
        self.extras()
    }

    /// Swap the self-evaluated rule sets, keeping the engine in force.
    ///
    /// `RwLock` for the same reason the engine uses one: a request in flight keeps the `Arc` it started
    /// with, so it is judged by exactly one rule set rather than by half of each.
    pub fn replace_extras(&self, extras: Arc<crate::https::extras::ExtraModifiers>) {
        let mut guard = self.extras.write().unwrap_or_else(|e| e.into_inner());
        *guard = extras;
    }

    /// The full decision for one request, including the modifiers this core evaluates.
    ///
    /// This is the entry point the relays use. The free [`decide_full`] function answers only what the
    /// engine knows, which is what its own tests want; everything that decides a real request goes
    /// through here so `$popup` and `$denyallow` cannot be forgotten at one call site.
    pub fn decide_full(
        &self,
        request: &HttpRequest,
        kind: RequestKind,
    ) -> (FilterDecision, Option<String>, Option<String>) {
        let (mut decision, rewritten_url, csp) = decide_full(&self.engine(), request, kind);
        let extras = self.extras();
        // The engine's own answer already encodes the general precedence: `@@` cancels a block unless
        // the block came from an `$important` rule (`important_beats_an_exception`). The modifiers
        // below add blocks the engine's parser dropped, so each of them has to answer the same
        // question instead of re-deciding it: `decision.exception_rule` is "the engine found an `@@`
        // that wins here", and an `$important` block is never cancelled by anything.
        //
        // The engine only reports an exception when one of *its* rules blocked, so the first extra
        // block this core is about to add has to ask for one explicitly
        // ([`engine_exception_for`]); `None` here means "not looked up yet".
        let engine = self.engine();
        let mut exception: Option<EngineException> = None;
        // The `@@` rule that covers this request, looked up once and only if an extra block is about to
        // be added. `None` means "no exception wins", which is also the `$important` answer.
        macro_rules! winning_exception {
            () => {{
                if decision.exception_rule.is_some() {
                    true
                } else {
                    if exception.is_none() {
                        exception = Some(engine_exception_for(&engine, request, kind));
                    }
                    let found = exception.clone().unwrap_or_default();
                    if found.matched {
                        decision.exception_rule = Some(
                            found
                                .rule
                                .clone()
                                .unwrap_or_else(|| "engine exception".to_string()),
                        );
                    }
                    found.matched
                }
            }};
        }

        // `$domain=example.*`: the engine parses the option and then compares it against hashes an
        // entity can never produce, so the rule matches nothing (`https::entity_domains`). Both halves
        // are decided there — blocking inside the named entity, forwarding outside it.
        //
        // The exception half runs first, and separately from the blocking half: a list usually writes
        // the block without a `$domain=` (`||ads.example^$script`) and the exception *with* one, so the
        // exception has to be able to cancel a block the main engine made. Folding the two into one
        // verdict would let the exception be dropped whenever this family had nothing of its own to
        // block. It answers to the same precedence as the engine's `@@`, so it cannot touch an
        // `$important` block.
        // Both halves of the entity family come from one pass: asking `exempts` and `verdict`
        // separately would walk the candidates and run the engine queries twice per request.
        let entity = extras.entity_domain.evaluate(request, kind);
        let entity_exempt = !decision.important && entity.exempts;
        if entity_exempt && decision.block {
            decision.block = false;
            decision.matched_rule = None;
            decision.exception_rule = Some("$domain=entity".to_string());
        }

        // `$denyallow`: the whole rule is dropped by the engine's parser, so both halves live here —
        // blocking when the stripped rule matches, forwarding when the host is on its allowlist.
        if let Some(block) = extras.denyallow.verdict(request, kind) {
            if block {
                // An `@@` rule is what a list author writes to say "this one is wanted", and it is more
                // specific than the broad rule this block comes from — whether it came from the engine
                // ([`winning_exception!`]) or from the entity family (`entity_exempt`).
                //
                // `entity_exempt` has to be asked separately: `decision.exception_rule` is only written
                // above when there was a block to cancel, so when the engine blocked nothing an entity
                // exception leaves that field `None` while still meaning "this request is allowed". A
                // denyallow block added on top of it would be a false positive, and the list author's
                // exception would be silently ignored.
                if !decision.block
                    && !decision.important
                    && !entity_exempt
                    && !winning_exception!()
                {
                    decision.block = true;
                    decision.matched_rule = Some("$denyallow".to_string());
                }
            } else if decision.block && !decision.important {
                // The exemption is the reason, and the log should say so rather than show a block that
                // did not happen. An `$important` block is not exemptable, by this or any rule.
                decision.block = false;
                decision.matched_rule = None;
                decision.exception_rule = Some("$denyallow".to_string());
            }
        }

        // The blocking half of an entity rule. It is a block like any other, so an exception the
        // engine found (or the one just applied above) keeps winning — that is what `@@` means — while
        // an `$important` block stands on its own.
        if !decision.block
            && !decision.important
            && !entity_exempt
            && !winning_exception!()
            && entity.blocks
        {
            decision.block = true;
            decision.matched_rule = Some("$domain=entity".to_string());
        }

        // `$popup` forbids a navigation the user did not ask for. It is an *additional* block, applied
        // last so that nothing above can cancel it: an `@@` rule for the same URL says the resource is
        // wanted, not that the popup was, and no exception is consulted for it.
        if !decision.block && extras.popup.blocks(request, kind) {
            decision.block = true;
            decision.matched_rule = Some("$popup".to_string());
        }
        (decision, rewritten_url, csp)
    }

    /// The engine currently in force. One snapshot per request, like the DNS filter.
    pub fn engine(&self) -> Arc<adblock::Engine> {
        Arc::clone(&self.engine.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Hot-replace the engine. In-flight decisions keep the `Arc` they started with.
    pub fn replace(&self, engine: adblock::Engine) {
        let mut engine = engine;
        engine.use_resources(resources::builtin_resources());
        let mut guard = self.engine.write().unwrap_or_else(|e| e.into_inner());
        *guard = Arc::new(engine);
    }

    /// Decide one request against the engine currently in force.
    pub fn decide(&self, request: &HttpRequest) -> FilterDecision {
        let kind = resource::infer(request);
        self.decide_full(request, kind).0
    }

    /// The whole answer for one request, with an explicitly chosen resource type.
    pub fn decide_typed(&self, request: &HttpRequest, kind: RequestKind) -> FilterDecision {
        self.decide_full(request, kind).0
    }

    /// The cosmetic plan for one document, against the engine currently in force.
    pub fn cosmetic_plan(&self, request: &HttpRequest) -> crate::cosmetic::Plan {
        cosmetic_plan_with(
            &self.engine(),
            request,
            &self.extras().global_unhide,
        )
    }

    /// The same plan for an engine snapshot the caller already holds.
    pub fn cosmetic_plan_with(
        &self,
        engine: &Arc<adblock::Engine>,
        request: &HttpRequest,
    ) -> crate::cosmetic::Plan {
        cosmetic_plan(engine, request)
    }
}

/// Decide one request against a specific engine.
///
/// Kept free-standing so tests (and M3) can drive a bare `adblock::Engine`.
pub fn decide(engine: &adblock::Engine, request: &HttpRequest) -> FilterDecision {
    let kind = resource::infer(request);
    decide_typed(engine, request, kind)
}

/// Decide one request with an explicitly chosen resource type.
pub fn decide_typed(
    engine: &adblock::Engine,
    request: &HttpRequest,
    kind: RequestKind,
) -> FilterDecision {
    decide_full(engine, request, kind).0
}

/// The whole answer of one engine query: the decision, the `$removeparam` rewrite and the `$csp`
/// directive.
///
/// Returned together because they come from one `check_network_request` / `get_csp_directives` pair
/// and a caller that needs two of the three (M3's HTTPS path needs all three) must not pay for the
/// query twice. [`decide_typed`] is the M2b-shaped view of the same result.
pub fn decide_full(
    engine: &adblock::Engine,
    request: &HttpRequest,
    kind: RequestKind,
) -> (FilterDecision, Option<String>, Option<String>) {
    let adblock_request = to_adblock_request(request, kind);
    let result = engine.check_network_request(&adblock_request);

    let block = result.should_block();
    // `$redirect-rule` produces a substitute that only applies *if* another rule blocks the request
    // (uBO semantics); adblock-rust returns the redirect either way, so it is gated on the block here.
    let redirect = if block {
        result
            .redirect
            .as_deref()
            .and_then(RedirectBody::from_data_url)
    } else {
        None
    };
    // A rewrite only means something for a forwarded request: a blocked one never reaches the
    // network, and `$csp` only applies to a response we are relaying.
    let (rewritten_url, csp) = if block {
        (None, None)
    } else {
        (
            result.rewritten_url.clone(),
            engine.get_csp_directives(&adblock_request),
        )
    };

    let decision = FilterDecision {
        block,
        redirect,
        important: result.important,
        matched_rule: result.filter.and_then(|info| info.raw_line),
        exception_rule: result.exception.and_then(|info| info.raw_line),
    };
    (decision, rewritten_url, csp)
}

/// What the engine's `@@` rules say about a request this core is about to block.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EngineException {
    /// An exception rule matched, so the request must be forwarded.
    pub matched: bool,
    /// The rule text, when the engine was compiled with debug information.
    pub rule: Option<String>,
}

/// The `@@` rule that would cancel a block on this request, if any.
///
/// The engine only looks for exceptions when it found a blocking rule of its own
/// (`Blocker::check_parameterised`: "if no other rule matches, only check exceptions if forced to"),
/// and it is not told about the blocks this core adds afterwards — a `$domain=entity` or `$denyallow`
/// rule is one the engine's parser dropped entirely.
///
/// So the question "does a list explicitly allow this request" has to be asked separately once this
/// core is about to block, which is what `force_check_exceptions` is for. `$important` needs no such
/// call: an `$important` match is never subject to an exception.
///
/// [`EngineException::matched`] is deliberately separate from [`EngineException::rule`]: production
/// engines are compiled without debug information (see the module docs), so the rule text is `None`
/// while the match is real. Deciding on the text would silently disable every exception.
fn engine_exception_for(
    engine: &adblock::Engine,
    request: &HttpRequest,
    kind: RequestKind,
) -> EngineException {
    let adblock_request = to_adblock_request(request, kind);
    // `previously_matched_rule = true`: the caller is about to add a block, so the engine must skip its
    // own blocking rules (they have already been consulted) and go straight to the exceptions.
    let result = engine.check_network_request_subset(&adblock_request, true, true);
    match result.exception {
        Some(info) => EngineException {
            matched: true,
            rule: info.raw_line,
        },
        None => EngineException::default(),
    }
}

/// The cosmetic work one document needs, from the engine in force.
///
/// Called only for a request that is going to be forwarded as a document: `url_cosmetic_resources` walks
/// the hostname-keyed cosmetic rules, which is wasted work for a subresource that has no body this code
/// can inject into.
///
/// Returns an empty [`crate::cosmetic::Plan`] when the engine has nothing for the page, which the caller
/// uses as "leave this response alone".
pub fn cosmetic_plan(engine: &Arc<adblock::Engine>, request: &HttpRequest) -> crate::cosmetic::Plan {
    cosmetic_plan_with(
        engine,
        request,
        &Arc::new(crate::cosmetic::unhide::GlobalUnhides::default()),
    )
}

/// [`cosmetic_plan`] with the global-unhide rules in force.
///
/// The rules are passed in rather than read from a global because they come from the same artifact set
/// the engine does (`extras.txt`), and a plan must describe exactly one rule set — the one the network
/// decision for this request also used.
///
/// The `Arc` is shared, not copied: the plan outlives the decision that built it (it is handed to the
/// rewriter) and a clone per document would duplicate the whole rule list per page load.
pub fn cosmetic_plan_with(
    engine: &Arc<adblock::Engine>,
    request: &HttpRequest,
    global_unhides: &Arc<crate::cosmetic::unhide::GlobalUnhides>,
) -> crate::cosmetic::Plan {
    let resources = engine.url_cosmetic_resources(&request.url);
    // The procedural channel is screened here, once per document, rather than in the rewriter: the
    // screening needs the selector grammar, the rewriter needs nothing but the result, and a rule the
    // screen drops must not consume any of the document's body budget.
    let validator = crate::cosmetic::validate::shared();
    let check = |selector: &str| validator.check(selector);
    let screen = crate::cosmetic::ProceduralScreen { validate: &check };
    let procedures = screen.apply(&resources.procedural_actions);
    crate::cosmetic::Plan {
        hide_selectors: resources.hide_selectors.into_iter().collect(),
        exceptions: resources.exceptions,
        global_unhides: Arc::clone(global_unhides),
        injected_script: resources.injected_script,
        procedural: procedures.rules,
        procedural_dropped: procedures.dropped,
        generichide: resources.generichide,
        // `Arc`, not a clone: the engine holds tens of thousands of rules and a per-document copy would
        // be both slow and unbounded in memory. The snapshot is the same one the decision used, so a
        // hot reload cannot make the generic query run against different rules than the network check.
        engine: Some(Arc::clone(engine)),
        drop_response_headers: Vec::new(),
        extra_csp: None,
    }
}

/// Build the adblock-rust request for `request`, stating first-/third-partiness explicitly.
pub fn to_adblock_request(request: &HttpRequest, kind: RequestKind) -> Request {
    let (source_hostname, third_party) = source_of(request);
    Request::preparsed(
        &request.url,
        &request.hostname,
        &source_hostname,
        kind.as_str(),
        third_party,
        &request.method.to_ascii_lowercase(),
    )
}

/// The source hostname and whether the request is third-party.
///
/// A missing or unusable `Referer` means first-party: we do not know the request came from another
/// site, and assuming it did would let `$third-party` rules break first-party requests.
fn source_of(request: &HttpRequest) -> (String, bool) {
    let Some(referer) = request.referer.as_deref() else {
        return (String::new(), false);
    };
    let Some(source) = adblock::url_parser::parse_url(referer) else {
        return (String::new(), false);
    };
    // First-/third-party is decided on the registrable domain (eTLD+1), so
    // `news.example.com` → `cdn.example.com` is first-party while `other.example` is not.
    let third_party = match adblock::url_parser::parse_url(&request.url) {
        Some(target) => target.domain() != source.domain(),
        // The target URL always parses (it was built from a parsed request); treating an
        // unexpected failure as first-party keeps the decision conservative.
        None => false,
    };
    (source.hostname().to_string(), third_party)
}

/// Whether `request` came from another site, for the request log.
///
/// Same rule the decision uses: first-party when no usable source is known.
pub fn is_third_party(request: &HttpRequest) -> bool {
    source_of(request).1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::head::Version;

    fn request(url: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
        let parsed = adblock::url_parser::parse_url(url).expect("test URL");
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: Version::Http11,
            url: parsed.url.clone(),
            host: parsed.hostname().to_string(),
            hostname: parsed.hostname().to_string(),
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

    fn engine(rules: &str) -> adblock::Engine {
        adblock::Engine::new_with_filter_set({
            let mut set = adblock::lists::FilterSet::new(false);
            set.add_filter_list(rules.to_string(), adblock::lists::ParseOptions::default());
            set
        })
    }

    /// An engine that records rule text, so `matched_rule` can be asserted.
    fn debug_engine(rules: &str) -> adblock::Engine {
        let mut set = adblock::lists::FilterSet::new(true);
        set.add_filter_list(rules.to_string(), adblock::lists::ParseOptions::default());
        adblock::Engine::new_with_filter_set(set)
    }

    #[test]
    fn a_script_rule_blocks_a_matching_request() {
        let engine = engine("||ads.example.com^$script\n");
        let blocked = decide(
            &engine,
            &request("http://ads.example.com/banner.js", Some("http://site.example/"), RequestKind::Script),
        );
        assert!(blocked.block);
        assert!(!blocked.important);
        let allowed = decide(
            &engine,
            &request("http://ads.example.com/pixel.gif", Some("http://site.example/"), RequestKind::Image),
            );
        assert!(!allowed.block, "`$script` must not block an image");
    }

    #[test]
    fn third_party_rules_need_a_source_and_do_not_fire_without_one() {
        let engine = engine("||cdn.example.com^$third-party\n");
        // No referer: first-party, so the rule must not fire (task card §2).
        assert!(
            !decide(&engine, &request("http://cdn.example.com/a.js", None, RequestKind::Script)).block,
            "a request without a source must be treated as first-party"
        );
        // Same site: first-party.
        assert!(
            !decide(
                &engine,
                &request(
                    "http://cdn.example.com/a.js",
                    Some("http://www.example.com/page"),
                    RequestKind::Script
                )
            )
            .block,
            "a subdomain of the same registrable domain is first-party"
        );
        // Different site: third-party, blocked.
        assert!(
            decide(
                &engine,
                &request(
                    "http://cdn.example.com/a.js",
                    Some("http://other.example/page"),
                    RequestKind::Script
                )
            )
            .block,
            "a request from another site is third-party"
        );
    }

    #[test]
    fn a_domain_scoped_rule_needs_a_matching_referer() {
        let engine = engine("||track.example.com^$domain=shop.example\n");
        assert!(
            decide(
                &engine,
                &request(
                    "http://track.example.com/t.gif",
                    Some("http://shop.example/item"),
                    RequestKind::Image
                )
            )
            .block
        );
        assert!(
            !decide(
                &engine,
                &request(
                    "http://track.example.com/t.gif",
                    Some("http://news.example/item"),
                    RequestKind::Image
                )
            )
            .block,
            "`$domain=` must not fire on an unrelated source"
        );
        assert!(
            !decide(
                &engine,
                &request("http://track.example.com/t.gif", None, RequestKind::Image)
            )
            .block,
            "`$domain=` must not fire without a source"
        );
    }

    #[test]
    fn exceptions_cancel_a_block_and_are_reported() {
        let engine = debug_engine("||ads.example.com^$script\n@@||ads.example.com/allowed.js$script\n");
        let cancelled = decide(
            &engine,
            &request(
                "http://ads.example.com/allowed.js",
                Some("http://site.example/"),
                RequestKind::Script,
            ),
        );
        assert!(!cancelled.block);
        assert!(
            cancelled
                .exception_rule
                .as_deref()
                .unwrap_or_default()
                .contains("@@"),
            "the exception rule must be reported: {:?}",
            cancelled.exception_rule
        );
    }

    #[test]
    fn important_beats_an_exception() {
        let engine = engine("||ads.example.com^$important\n@@||ads.example.com^\n");
        let decision = decide(
            &engine,
            &request("http://ads.example.com/x.js", Some("http://site.example/"), RequestKind::Script),
        );
        assert!(decision.block, "`$important` must not be cancelled by `@@`");
        assert!(decision.important);
    }

    #[test]
    fn rule_text_is_reported_only_when_the_engine_carries_it() {
        let plain = engine("||ads.example.com^$script\n");
        let decision = decide(
            &plain,
            &request("http://ads.example.com/x.js", Some("http://site.example/"), RequestKind::Script),
        );
        assert!(decision.block);
        assert_eq!(
            decision.matched_rule, None,
            "an engine built without debug information cannot attribute the rule, and inventing one would be worse"
        );

        let with_debug = debug_engine("||ads.example.com^$script\n");
        let decision = decide(
            &with_debug,
            &request("http://ads.example.com/x.js", Some("http://site.example/"), RequestKind::Script),
        );
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("||ads.example.com^$script")
        );
    }

    #[test]
    fn redirect_resources_are_served_from_the_builtin_set() {
        let filter = HttpFilter::new(engine(
            "||ads.example.com/banner.js$script,redirect=noopjs\n",
        ));
        let decision = filter.decide(&request(
            "http://ads.example.com/banner.js",
            Some("http://site.example/"),
            RequestKind::Script,
        ));
        assert!(decision.block);
        assert!(decision.serves_redirect(), "a `$redirect` rule must yield a body");
        let redirect = decision.redirect.expect("redirect");
        assert_eq!(redirect.mime, "application/javascript");
        assert!(redirect.data_url.starts_with("data:application/javascript;base64,"));

        // An image substitute really is a GIF.
        let filter = HttpFilter::new(engine(
            "||ads.example.com/pixel.gif$image,redirect=1x1.gif\n",
        ));
        let decision = filter.decide(&request(
            "http://ads.example.com/pixel.gif",
            Some("http://site.example/"),
            RequestKind::Image,
        ));
        let redirect = decision.redirect.expect("redirect");
        assert_eq!(redirect.mime, "image/gif");
        assert_eq!(&redirect.body[..6], b"GIF89a");
    }

    #[test]
    fn an_unknown_redirect_resource_falls_back_to_a_plain_block() {
        // A list naming a resource we do not ship: adblock-rust drops the redirect, and the request
        // is still blocked. Serving nothing is better than serving a 404-looking empty body.
        let filter = HttpFilter::new(engine(
            "||ads.example.com/x.js$script,redirect=does-not-exist\n",
        ));
        let decision = filter.decide(&request(
            "http://ads.example.com/x.js",
            Some("http://site.example/"),
            RequestKind::Script,
        ));
        assert!(decision.block);
        assert_eq!(decision.redirect, None);
    }

    #[test]
    fn a_redirect_rule_alone_does_not_block() {
        // `redirect-rule` only substitutes when something else blocks; the request must still be
        // allowed through, otherwise we would be breaking sites the list never asked us to break.
        let filter = HttpFilter::new(engine(
            "||ads.example.com/x.js$script,redirect-rule=noopjs\n",
        ));
        let decision = filter.decide(&request(
            "http://ads.example.com/x.js",
            Some("http://site.example/"),
            RequestKind::Script,
        ));
        assert!(!decision.block);
        assert_eq!(decision.redirect, None);
    }

    #[test]
    fn a_redirect_without_a_rule_that_blocks_is_not_served() {
        // `$redirect` implies blocking in uBO; make sure the block is reported so the relay responds
        // instead of forwarding.
        let filter = HttpFilter::new(engine(
            "||ads.example.com/x.js$script,redirect=noopjs\n",
        ));
        let decision = filter.decide(&request(
            "http://ads.example.com/x.js",
            Some("http://site.example/"),
            RequestKind::Script,
        ));
        assert!(decision.block, "`$redirect` implies a block");
        assert!(decision.serves_redirect());
    }

    #[test]
    fn the_engine_can_be_hot_replaced() {
        let filter = HttpFilter::new(engine("||old.example.com^$script\n"));
        let target = request(
            "http://new.example.com/a.js",
            Some("http://site.example/"),
            RequestKind::Script,
        );
        assert!(!filter.decide(&target).block);

        filter.replace(engine("||new.example.com^$script\n"));
        assert!(
            filter.decide(&target).block,
            "the new rules must be in force after a replace"
        );
        // An `Arc` taken before the swap keeps the rules it started with.
        let snapshot = filter.engine();
        filter.replace(engine("||other.example.com^$script\n"));
        assert!(decide(&snapshot, &target).block);
        assert!(!decide(&filter.engine(), &target).block);
    }

    #[test]
    fn redirect_data_urls_are_parsed_defensively() {
        let body = RedirectBody::from_data_url("data:text/plain;base64,aGVsbG8=").expect("parse");
        assert_eq!(body.mime, "text/plain");
        assert_eq!(body.body, b"hello");
        assert_eq!(body.data_url, "data:text/plain;base64,aGVsbG8=");

        // A charset parameter is not part of the MIME type.
        assert_eq!(
            RedirectBody::from_data_url("data:text/css;charset=utf-8;base64,YQ==")
                .expect("parse")
                .mime,
            "text/css"
        );
        // Empty payloads are legal (the noop resources are empty).
        assert_eq!(
            RedirectBody::from_data_url("data:text/css;base64,")
                .expect("parse")
                .body,
            Vec::<u8>::new()
        );
        // Garbage is refused instead of served.
        assert_eq!(RedirectBody::from_data_url("not a data url"), None);
        assert_eq!(RedirectBody::from_data_url("data:"), None);
        assert_eq!(RedirectBody::from_data_url("data:;base64,YQ=="), None);
        assert_eq!(RedirectBody::from_data_url("data:text/plain,hello"), None);
        assert_eq!(RedirectBody::from_data_url("data:text/plain;base64,!!!!"), None);
    }

    #[test]
    fn an_oversized_redirect_body_is_refused() {
        let mut url = String::from("data:text/plain;base64,");
        url.push_str(&"A".repeat((MAX_REDIRECT_BODY + 8) * 4 / 3 + 8));
        assert_eq!(RedirectBody::from_data_url(&url), None);
    }

    #[test]
    fn request_types_come_from_the_request_not_the_url() {
        // The same URL, judged as a script and as an image.
        let engine = engine("||ads.example.com/pic.gif$image\n");
        let url = "http://ads.example.com/pic.gif";
        assert!(decide(&engine, &request(url, Some("http://site.example/"), RequestKind::Image)).block);
        assert!(!decide(&engine, &request(url, Some("http://site.example/"), RequestKind::Script)).block);
    }

    // -----------------------------------------------------------------------------------------
    // The modifiers this core evaluates itself (M5b §3/§5/§6)
    // -----------------------------------------------------------------------------------------

    fn filter_with(engine_rules: &str, list_text: &str) -> HttpFilter {
        HttpFilter::new(engine(engine_rules))
            .with_extras(Arc::new(crate::https::extras::collect([list_text])))
    }

    /// A navigation carrying the three Fetch Metadata headers a browser sends.
    fn fetch_navigation(url: &str, referer: &str, site: &str, user: Option<&str>) -> HttpRequest {
        let mut request = request(url, Some(referer), RequestKind::Document);
        request.fetch_dest = Some("document".to_string());
        request.fetch_site = Some(site.to_string());
        request.fetch_user = user.map(str::to_string);
        request
    }

    #[test]
    fn a_popup_rule_blocks_the_three_header_combination_and_nothing_else() {
        // The acceptance criterion asked for three combinations. They are the three ways a browser
        // describes the same navigation, and only one of them is a popup:
        //   1. cross-site + document + no user activation  -> popup, blocked
        //   2. cross-site + document + `Sec-Fetch-User: ?1` -> the user clicked, forwarded
        //   3. same-origin + document                       -> ordinary browsing, forwarded
        let filter = filter_with("", "||ad.example^$popup\n");
        let popup = fetch_navigation("https://ad.example/landing", "https://site.example/", "cross-site", None);
        assert!(filter.decide_typed(&popup, RequestKind::Document).block);
        assert_eq!(
            filter
                .decide_typed(&popup, RequestKind::Document)
                .matched_rule
                .as_deref(),
            Some("$popup"),
            "the log must say the popup rule fired, not some other block"
        );

        let clicked = fetch_navigation(
            "https://ad.example/landing",
            "https://site.example/",
            "cross-site",
            Some("?1"),
        );
        assert!(!filter.decide_typed(&clicked, RequestKind::Document).block);

        let same_site = fetch_navigation(
            "https://ad.example/landing",
            "https://ad.example/",
            "same-origin",
            None,
        );
        assert!(!filter.decide_typed(&same_site, RequestKind::Document).block);

        // A client that sends no Fetch Metadata at all is not guessed at: every navigation such a
        // client makes would otherwise be at risk.
        let bare = request("https://ad.example/landing", None, RequestKind::Document);
        assert!(!filter.decide_typed(&bare, RequestKind::Document).block);
    }

    #[test]
    fn a_popup_rule_does_not_affect_a_subresource_on_the_same_host() {
        let filter = filter_with("", "*$popup,domain=site.example\n");
        let script = request("https://ad.example/x.js", Some("https://site.example/"), RequestKind::Script);
        assert!(!filter.decide_typed(&script, RequestKind::Script).block);
    }

    #[test]
    fn denyallow_exempts_the_named_host_from_the_rule_it_sits_on() {
        // The rule is a broad `*$script,domain=site.example`: everything is blocked, except the CDN
        // the site needs. The exemption must not be global — the same CDN from another source is not
        // exempt, and a different host from the same source is still blocked.
        let list = "*$script,denyallow=cdn.good.example,domain=site.example\n";
        let filter = filter_with(list, list);
        let cdn = request("https://cdn.good.example/lib.js", Some("https://site.example/"), RequestKind::Script);
        let decision = filter.decide_typed(&cdn, RequestKind::Script);
        assert!(!decision.block, "the denyallow host must be forwarded");
        // No engine rule ever matched (the whole line is one the engine refuses), so nothing was
        // exempted — the request simply was never blocked. The verdict alone is `Some(false)`.
        assert!(filter
            .extras()
            .denyallow
            .exempts(&cdn, RequestKind::Script));

        let elsewhere = request("https://evil.example/lib.js", Some("https://site.example/"), RequestKind::Script);
        assert!(
            filter.decide_typed(&elsewhere, RequestKind::Script).block,
            "a host that is not on the denyallow list is still blocked"
        );

        let other_source = request("https://cdn.good.example/lib.js", Some("https://other.example/"), RequestKind::Script);
        assert!(
            !filter.decide_typed(&other_source, RequestKind::Script).block,
            "the rule never applied from another source, so there is nothing to exempt"
        );
    }

    #[test]
    fn an_entity_domain_option_blocks_where_the_engine_cannot() {
        // The element-hiding page's case 6, verbatim. The engine parses `domain=testcases.agrd.*` and
        // then compares it against request hashes an entity can never produce, so the line matches
        // nothing; this core evaluates the entity half itself (`https::entity_domains`).
        let list = "||*/tld-test-files/$image,domain=testcases.agrd.*|pages.*\n";
        let filter = filter_with("", list);

        let image = request(
            "https://testcases.agrd.dev/Filters/element-hiding-rules/tld-test-files/adguard.png",
            Some("https://testcases.agrd.dev/Filters/element-hiding-rules/test-element-hiding-rules.html"),
            RequestKind::Image,
        );
        let decision = filter.decide_typed(&image, RequestKind::Image);
        assert!(
            decision.block,
            "an entity-scoped rule must block inside its entity: {decision:?}"
        );
        assert_eq!(decision.matched_rule.as_deref(), Some("$domain=entity"));

        // Another site's image is not in scope.
        let elsewhere = request(
            "https://other.example/tld-test-files/adguard.png",
            Some("https://other.example/page.html"),
            RequestKind::Image,
        );
        assert!(!filter.decide_typed(&elsewhere, RequestKind::Image).block);

        // And a request with no source at all is never put in an entity's scope.
        let no_referer = request(
            "https://testcases.agrd.dev/Filters/element-hiding-rules/tld-test-files/adguard.png",
            None,
            RequestKind::Image,
        );
        assert!(!filter.decide_typed(&no_referer, RequestKind::Image).block);
    }

    #[test]
    fn an_entity_block_respects_an_engine_exception() {
        // Review item 1. Entity rules never fired before this iteration, so `decision.block` was the
        // only thing to set; now that they do, an `@@` rule has to be able to stop one. Without this,
        // `||cdn.example/*$domain=foo.*` would block a host a list explicitly allows.
        let filter = filter_with(
            "@@||cdn.example^\n",
            "||cdn.example/*$image,domain=example.*\n",
        );
        let allowed = request(
            "https://cdn.example/logo.png",
            Some("https://example.com/page"),
            RequestKind::Image,
        );
        let decision = filter.decide_typed(&allowed, RequestKind::Image);
        assert!(!decision.block, "an `@@` rule must stop an entity block: {decision:?}");
        assert!(
            decision.exception_rule.is_some(),
            "the reason must be reported: {decision:?}"
        );

        // Same shape on an engine that carries rule text, so the attribution can be asserted too. A
        // production engine has no debug information and reports the match without its text — which is
        // why the decision keys on the match, not on the text.
        let filter = HttpFilter::new(debug_engine("@@||cdn.example^\n"))
            .with_extras(Arc::new(crate::https::extras::collect([
                "||cdn.example/*$image,domain=example.*\n",
            ])));
        let decision = filter.decide_typed(&allowed, RequestKind::Image);
        assert!(!decision.block);
        assert_eq!(
            decision.exception_rule.as_deref(),
            Some("@@||cdn.example^"),
            "{decision:?}"
        );

        // And the same request with no exception rule still blocks, so the test is not passing
        // because the rule matched nothing at all.
        let filter = filter_with("", "||cdn.example/*$image,domain=example.*\n");
        assert!(filter.decide_typed(&allowed, RequestKind::Image).block);
    }

    #[test]
    fn an_entity_exception_cannot_cancel_an_important_block() {
        // Review item 2. `$important` is the list author's "nothing may unblock this", and the engine
        // applies that to its own `@@` (`important_beats_an_exception`). The entity family is decided
        // here, so it has to apply the same rule.
        let filter = filter_with(
            "||ads.example^$important\n",
            "@@||ads.example^$script,domain=example.*\n",
        );
        let inside = request(
            "https://ads.example/x.js",
            Some("https://example.com/"),
            RequestKind::Script,
        );
        let decision = filter.decide_typed(&inside, RequestKind::Script);
        assert!(decision.block, "`$important` must survive an entity exception: {decision:?}");
        assert!(decision.important);
    }

    #[test]
    fn an_entity_block_does_not_override_an_important_rule_s_own_exception_logic() {
        // The other direction of item 2: an `$important` block that the engine applied is not a state
        // the entity family may add to or clear. Here the entity rule would block as well, and the
        // reported rule must stay the engine's `$important` one rather than being relabelled.
        let filter = filter_with(
            "||ads.example^$important\n",
            "||ads.example/*$script,domain=example.*\n",
        );
        let decision = filter.decide_typed(
            &request(
                "https://ads.example/x.js",
                Some("https://example.com/"),
                RequestKind::Script,
            ),
            RequestKind::Script,
        );
        assert!(decision.block);
        assert!(decision.important);
    }

    #[test]
    fn an_entity_block_applies_when_the_engine_saw_nothing() {
        // The plain case the family exists for: the engine drops the `$domain=` entity entry, so only
        // this core can block. It must still do so with no exception anywhere in sight.
        let filter = filter_with("", "||ads.example/*$script,domain=example.*\n");
        let decision = filter.decide_typed(
            &request(
                "https://ads.example/x.js",
                Some("https://example.com/"),
                RequestKind::Script,
            ),
            RequestKind::Script,
        );
        assert!(decision.block, "{decision:?}");
        assert_eq!(decision.matched_rule.as_deref(), Some("$domain=entity"));
    }

    #[test]
    fn denyallow_cannot_cancel_an_important_block() {
        // Review item 2, the `$denyallow` half: its exemption branch had the same gap.
        let list = "*$script,denyallow=cdn.good.example,domain=site.example\n";
        let filter = filter_with("||cdn.good.example^$important\n", list);
        let cdn = request(
            "https://cdn.good.example/lib.js",
            Some("https://site.example/"),
            RequestKind::Script,
        );
        let decision = filter.decide_typed(&cdn, RequestKind::Script);
        assert!(
            decision.block,
            "an `$important` block must not be exemptable by `$denyallow`: {decision:?}"
        );
        assert!(decision.important);
    }

    #[test]
    fn an_entity_exception_stops_a_denyallow_block_the_engine_never_made() {
        // Found in review of `2502f6f`: the `$denyallow` blocking branch asked `winning_exception!()`,
        // which reads `decision.exception_rule` — but that field is only written when there was an
        // existing block to cancel. With the engine blocking nothing, an entity `@@` rule left it
        // `None`, so `$denyallow` blocked a request the list explicitly allows.
        let filter = filter_with(
            "",
            "@@||ads.example^$script,domain=example.*\n\
             *$script,denyallow=cdn.good.example,domain=example.com\n",
        );
        let allowed = request(
            "https://ads.example/x.js",
            Some("https://example.com/"),
            RequestKind::Script,
        );
        let decision = filter.decide_typed(&allowed, RequestKind::Script);
        assert!(
            !decision.block,
            "an entity `@@` rule must stop a `$denyallow` block: {decision:?}"
        );

        // The exception's scope still holds: with the `$denyallow` rule narrowed to a source the
        // entity does not cover, nothing exempts it and the block stands. This keeps the test from
        // passing merely because the `$denyallow` rule matched nothing.
        let control = filter_with(
            "",
            "@@||ads.example^$script,domain=example.*\n\
             *$script,denyallow=cdn.good.example,domain=site.example\n",
        );
        let outside = request(
            "https://ads.example/x.js",
            Some("https://site.example/"),
            RequestKind::Script,
        );
        assert!(
            control.decide_typed(&outside, RequestKind::Script).block,
            "outside the entity scope the `$denyallow` rule must still block"
        );
    }

    #[test]
    fn popup_is_not_cancelled_by_a_document_exception() {
        // Review item 2, the `$popup` half: an `@@…$document` rule says the resource is wanted, not
        // that the user asked for the navigation.
        let list = "||ad.example^$popup\n";
        let filter = filter_with("@@||ad.example^$document\n", list);
        let popup = fetch_navigation("https://ad.example/landing", "https://site.example/", "cross-site", None);
        let decision = filter.decide_typed(&popup, RequestKind::Document);
        assert!(
            decision.block,
            "`$popup` is an additional block and must survive `@@…$document`: {decision:?}"
        );
        assert_eq!(decision.matched_rule.as_deref(), Some("$popup"));
    }

    #[test]
    fn an_entity_domain_exception_puts_the_request_back_in_scope() {
        // The engine blocks every site; the `@@` line's `$domain=testcases.agrd.*` narrows that
        // exception to one entity. The engine cannot express the entity half, so without
        // `https::entity_domains` the exception would never fire and the block would stand.
        let filter = filter_with(
            "||ads.example^$script\n",
            "@@||ads.example^$script,domain=testcases.agrd.*\n",
        );
        let inside = request(
            "https://ads.example/lib.js",
            Some("https://testcases.agrd.dev/"),
            RequestKind::Script,
        );
        let decision = filter.decide_typed(&inside, RequestKind::Script);
        assert!(!decision.block, "the entity exception must unblock: {decision:?}");
        assert_eq!(decision.exception_rule.as_deref(), Some("$domain=entity"));

        // The same request from another site keeps the engine's block: the exception's `$domain=` is
        // the whole of its scope, so outside it nothing changed.
        let outside = request(
            "https://ads.example/lib.js",
            Some("https://other.example/"),
            RequestKind::Script,
        );
        assert!(
            filter.decide_typed(&outside, RequestKind::Script).block,
            "an entity exception must not exempt other sites"
        );
    }

    #[test]
    fn a_regex_removeparam_rewrites_the_url_the_engine_leaves_alone() {
        // `$removeparam=/regex/` is a form the engine refuses, so `decide_full` returns no
        // `rewritten_url`. The extra modifier is what turns tracking parameters into a clean URL.
        let list = "||shop.example^$removeparam=/^utm_/\n";
        let filter = filter_with(list, list);
        let target = request(
            "https://shop.example/p?utm_source=x&utm_medium=y&keep=1",
            None,
            RequestKind::Document,
        );
        let (decision, rewritten, _) = filter.decide_full(&target, RequestKind::Document);
        assert!(!decision.block);
        assert_eq!(rewritten, None, "the engine knows nothing about this form");

        let edits = crate::http::rewrite::ModifierSource::edits(
            &crate::https::modifiers::HttpsModifiers::new(
                Arc::new(filter_with(list, list)),
                Arc::new(crate::https::modifiers::collect_removeheader(std::iter::empty())),
                Arc::new(crate::https::extras::collect([list])),
            ),
            &target,
            RequestKind::Document,
        )
        .expect("an edit");
        assert_eq!(
            edits.url.as_deref(),
            Some("https://shop.example/p?keep=1")
        );
    }

    #[test]
    fn a_plain_removeparam_is_evaluated_by_the_extras_so_the_engine_does_not_double_apply_it() {
        // The plain form parses in the engine, and the engine still reports its own rewrite — but the
        // *modifier* is decided by `https::extras`, because a finished URL cannot say which rule removed
        // which occurrence. Both must reach the same URL here: two implementations disagreeing would be
        // the bug this pins.
        let list = "||shop.example^$removeparam=utm_source\n";
        let extras = crate::https::extras::collect([list]);
        assert_eq!(extras.removeparam.len(), 1, "the family holds every rule it evaluates");
        let filter = filter_with(list, list);
        let target = request("https://shop.example/p?utm_source=x&keep=1", None, RequestKind::Document);
        let (_, rewritten, _) = filter.decide_full(&target, RequestKind::Document);
        assert_eq!(
            rewritten.as_deref(),
            Some("https://shop.example/p?keep=1"),
            "the engine's own `$removeparam` must keep working"
        );
        assert_eq!(
            extras.removeparam.rewrite(&target, RequestKind::Document).as_deref(),
            Some("https://shop.example/p?keep=1"),
            "and the evaluator must agree with it"
        );
    }
}

#[cfg(test)]
mod subdocument_semantics {
    use super::*;
    use crate::http::head::{HttpRequest, Version};

    fn request(url: &str, dest: &str, referer: Option<&str>) -> HttpRequest {
        let parsed = adblock::url_parser::parse_url(url).expect("test URL");
        let hostname = parsed.hostname().to_ascii_lowercase();
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: Version::Http11,
            url: parsed.url.clone(),
            host: hostname.clone(),
            hostname,
            referer: referer.map(str::to_string),
            fetch_dest: Some(dest.to_string()),
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
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list(rules.to_string(), adblock::lists::ParseOptions::default());
        HttpFilter::new(adblock::Engine::new_with_filter_set(set))
    }

    /// A rule that names only a frame navigation, the way the official test list writes it.
    const FRAME_RULE: &str = "||*/frame.html^$subdocument,domain=page.example";

    #[test]
    fn a_subdocument_rule_matches_a_frame_navigation() {
        let filter = filter(FRAME_RULE);
        let frame = request("https://ads.example/frame.html", "iframe", Some("https://page.example/"));
        assert!(
            filter.decide_typed(&frame, resource::infer(&frame)).block,
            "a `$subdocument` rule is about the frame document request itself"
        );
    }

    #[test]
    fn a_subdocument_rule_does_not_match_a_subresource_inside_the_frame() {
        // AdGuard's definition: `$subdocument` "corresponds to requests for built-in pages — HTML tags
        // `frame` and `iframe`". It says nothing about the images or scripts the frame then loads.
        // Widening it to them would block far more than any list author wrote — which is exactly what an
        // earlier revision of this iteration did by re-querying frame subresources as `subdocument`, and
        // the review rejected it.
        let filter = filter(FRAME_RULE);
        for (url, dest) in [
            ("https://ads.example/pic.png", "image"),
            ("https://ads.example/app.js", "script"),
            ("https://ads.example/api?x=1", "empty"),
            ("https://ads.example/style.css", "style"),
        ] {
            let inside = request(url, dest, Some("https://page.example/frame.html"));
            assert!(
                !filter.decide_typed(&inside, resource::infer(&inside)).block,
                "{url} ({dest}) inside a frame must not match a `$subdocument` rule"
            );
        }
    }

    #[test]
    fn a_subdocument_rule_does_not_match_the_top_frame_document() {
        let filter = filter(FRAME_RULE);
        let top = request("https://ads.example/frame.html", "document", Some("https://page.example/"));
        assert!(
            !filter.decide_typed(&top, resource::infer(&top)).block,
            "`$subdocument` is iframes, not the top-level document"
        );
    }

    #[test]
    fn the_same_url_is_judged_by_where_it_is_loaded() {
        // The point AdGuard's own page draws: one URL, two verdicts, decided purely by the request type.
        // The URL is identical, so nothing but `Sec-Fetch-Dest` separates them — which is why the type
        // has to stay the real one.
        let filter = filter(FRAME_RULE);
        let as_frame = request("https://ads.example/frame.html", "iframe", Some("https://page.example/"));
        let as_top = request("https://ads.example/frame.html", "document", Some("https://page.example/"));
        assert_eq!(as_frame.url, as_top.url);
        assert!(filter.decide_typed(&as_frame, resource::infer(&as_frame)).block);
        assert!(!filter.decide_typed(&as_top, resource::infer(&as_top)).block);
    }

    #[test]
    fn an_inverted_subdocument_rule_still_means_not_a_frame_navigation() {
        // `$~subdocument` is the negation of the type test, so it applies to what is *not* a frame
        // navigation — including a subresource inside a frame, because that subresource is not a
        // subdocument request. This is the honest reading of the modifier and needs no association table.
        let filter = filter("||ads.example^$~subdocument");
        let frame = request("https://ads.example/frame.html", "iframe", Some("https://page.example/"));
        assert!(
            !filter.decide_typed(&frame, resource::infer(&frame)).block,
            "a frame navigation must not match `$~subdocument`"
        );
        // An `image` from the frame's page is not a frame navigation either, so `$~subdocument` applies
        // to it. (A top-level *document* is not asserted here: AdGuard's "main frame bypass" means a
        // navigation the user initiated is never blocked unless `$document` is named explicitly, so that
        // case tests the bypass rather than the modifier.)
        let image = request("https://ads.example/pic.png", "image", Some("https://page.example/frame.html"));
        assert!(filter.decide_typed(&image, resource::infer(&image)).block);
    }

    #[test]
    fn a_subdocument_exception_cancels_only_the_frame_navigation() {
        let filter = filter(
            "||*/frame.html^$subdocument\n@@||*/frame.html^$subdocument,domain=page.example",
        );
        let frame = request("https://ads.example/frame.html", "iframe", Some("https://page.example/"));
        assert!(
            !filter.decide_typed(&frame, resource::infer(&frame)).block,
            "the exception unblocks the frame navigation"
        );
        let other = request("https://ads.example/frame.html", "iframe", Some("https://other.example/"));
        assert!(
            filter.decide_typed(&other, resource::infer(&other)).block,
            "and only within its `$domain`"
        );
    }
}
