//! The AdGuard/uBO modifiers the pinned `adblock` engine cannot decide on its own, evaluated by this core.
//!
//! `docs/coverage.json` (M5a) quantifies the gap: rules across the built-in catalog carry an option the
//! engine's parser rejects outright, so the whole line is dropped and nothing filters. `$removeheader`
//! was the first one fixed this way ([`crate::https::modifiers`]); this module adds the four with the
//! largest effect:
//!
//! | modifier | how its scope is decided | how its effect is decided |
//! |---|---|---|
//! | `$popup` | engine, on the rule stripped of the option | cross-site, user-untriggered top-level navigation, from `Sec-Fetch-*` |
//! | `$denyallow` | engine, per denyallow list | the request's host against the exemption list |
//! | `$removeparam` | engine, **one rule at a time** | every parameter occurrence, from the request's own URL |
//! | `#@#`/`*#@#` | — | [`crate::cosmetic::unhide`] |
//!
//! # The shared mechanism
//!
//! All four follow the pattern `$removeheader` established: **re-parse the line with the option removed
//! and let the engine match it**. Pattern syntax, `$domain=`, `$third-party`, content types and exceptions
//! then keep the meaning the list author gave them, and this module never grows a second, divergent
//! matcher.
//!
//! What the engine cannot answer is the part the option adds — *which* navigation counts as a popup,
//! *whether* the host is exempt, *which* parameter occurrences go — so that part is evaluated here, on top
//! of the engine's answer.
//!
//! # `$removeparam` is the exception, and why
//!
//! The other three ask the engine "does this rule's scope match" and then apply their own effect to the
//! answer. `$removeparam` cannot be composed that way from a URL the engine already rewrote, because a
//! finished URL does not say **which** rule removed **which** occurrence — so a repair pass has to guess
//! from parameter names, and two rules naming one parameter (a typed rule beside an untyped one) become
//! indistinguishable. It therefore asks the engine the same question **once per rule** and builds the URL
//! itself, from the request's own query; [`RemoveParamRules`] is the whole argument.
//!
//! # Why not simply fork the parser
//!
//! A fork would have to track the engine's optimiser, its token index and its `$badfilter` handling to
//! stay equivalent. Re-parsing costs one `FilterSet` build per group at compile time and is *provably* the
//! same matcher, which is the property that matters: a rule that reaches the network must be decided
//! exactly as the engine would decide it. `core/examples/removeparam_diff.rs` checks that property against
//! the real catalog — 184,650 (rule, request) pairs with no disagreement.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::http::head::HttpRequest;
use crate::http::resource::RequestKind;

// ---------------------------------------------------------------------------------------------
// Shared parsing helpers
// ---------------------------------------------------------------------------------------------

/// Split a rule line into its pattern and its options, keeping the two `@@` / `$` edges intact.
///
/// `$` cannot appear in a hostname or in a path before the options, so the first one starts them —
/// except inside a regex pattern (`/^https?:\/\/a\.com\$/`), which is why the caller is expected to
/// have refused such a line rather than this function trying to understand it.
fn split_rule(line: &str) -> Option<(bool, &str, Vec<&str>)> {
    let (exception, body) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (pattern, options) = body.split_once('$')?;
    let options: Vec<&str> = options
        .split(',')
        .map(str::trim)
        .filter(|option| !option.is_empty())
        .collect();
    Some((exception, pattern, options))
}

/// Rebuild a rule line from its pattern and the options that survived.
fn rebuild(exception: bool, pattern: &str, options: &[&str]) -> String {
    let prefix = if exception { "@@" } else { "" };
    if options.is_empty() {
        format!("{prefix}{pattern}")
    } else {
        format!("{prefix}{pattern}${}", options.join(","))
    }
}

/// The content-type modifiers AdGuard recognises, as they are spelled in a rule line.
///
/// Used to answer the one question that decides whether an untyped `$removeparam` rule may fire at all
/// (`RemoveParamRule::typed`). `$xhr` is uBO's alias for `$xmlhttprequest` and appears in real lists.
const CONTENT_TYPE_MODIFIERS: &[&str] = &[
    "document",
    "doc",
    "subdocument",
    "frame",
    "script",
    "stylesheet",
    "css",
    "image",
    "media",
    "font",
    "object",
    "other",
    "ping",
    "beacon",
    "websocket",
    "xmlhttprequest",
    "xhr",
    "webrtc",
    "object-subrequest",
    // `$all` is not a type *filter* but it is the type scope stated explicitly ("every type"), which is
    // exactly what makes a `$removeparam` rule typed: without it here, `$all,removeparam=track` would be
    // narrowed to `document` and stop matching a `fetch()` the list author meant it to cover.
    "all",
];

/// Whether any option in `options` names a content type (negated forms count: `$~image` still narrows
/// the rule to a set of types, so it is *not* the untyped form).
fn has_content_type(options: &[&str]) -> bool {
    options.iter().any(|option| {
        let bare = option.strip_prefix('~').unwrap_or(option);
        CONTENT_TYPE_MODIFIERS.contains(&bare)
    })
}

/// Whether the engine's parser accepts this line, so a rebuild can be checked before it is relied on.
fn engine_accepts(line: &str) -> bool {
    adblock::lists::parse_filter(line, false, adblock::lists::ParseOptions::default()).is_ok()
}

/// One engine per distinct stripped rule set, built lazily on first use.
///
/// A `BTreeMap` rather than a `HashMap` so iteration order — and therefore the reported order of
/// matching rules — is stable from run to run.
#[derive(Default)]
struct EngineGroup {
    /// Rules the engine will match, keyed by the text it was compiled from.
    engine: Option<adblock::Engine>,
    /// The rules that went into it, for the diagnostics and the counters.
    members: Vec<String>,
}

impl std::fmt::Debug for EngineGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineGroup")
            .field("members", &self.members.len())
            .field("built", &self.engine.is_some())
            .finish()
    }
}

/// Build one engine from a set of already-validated rule lines.
fn build_engine<'a>(rules: impl IntoIterator<Item = &'a String>) -> Option<adblock::Engine> {
    let mut set = adblock::lists::FilterSet::new(false);
    let mut any = false;
    for rule in rules {
        set.add_filter_list(rule.clone(), adblock::lists::ParseOptions::default());
        any = true;
    }
    if !any {
        return None;
    }
    Some(adblock::Engine::new_with_filter_set(set))
}

// ---------------------------------------------------------------------------------------------
// $popup
// ---------------------------------------------------------------------------------------------

/// A `$popup` rule: a navigation the list calls a popup.
///
/// # How a popup is recognised (`docs/JNI.md` §"$popup")
///
/// AdGuard and uBO both implement `$popup` on top of "a top-level navigation the user did not ask
/// for". A filter inside the TLS tunnel cannot see the window the request belongs to, but browsers
/// state the same facts in three `Sec-Fetch-*` request headers (Fetch Metadata, W3C), and all of them
/// are required together:
///
/// | header | required value | why |
/// |---|---|---|
/// | `Sec-Fetch-Dest` | `document` | a popup is a top-level navigation, not an image or a script |
/// | `Sec-Fetch-Site` | `cross-site` | a popup navigates *away* from the page that opened it |
/// | `Sec-Fetch-User` | absent (or not `?1`) | `?1` means the user activated a link or a form; a popup has no such activation |
///
/// # What it deliberately does not catch
///
/// A user tapping an ad and being taken to the advertiser's site in the *same* tab is indistinguishable
/// from a legitimate link from inside the tunnel, and blocking it would break ordinary browsing. That
/// is the误伤 risk the delivery note has to state: `$popup` can only remove navigations that opened a
/// new context, which on a mobile browser is most but not all of them — and a site that opens a
/// same-site popup (`Sec-Fetch-Site: same-origin`) is not caught at all.
///
/// A request without Fetch Metadata headers is **not** a popup. Older browsers and most in-app WebViews
/// send none of them, and guessing would put every navigation those clients make at risk.
pub fn is_popup_navigation(request: &HttpRequest, kind: RequestKind) -> bool {
    // The engine decided this is a document request; a subresource is never a popup.
    if kind != RequestKind::Document {
        return false;
    }
    let dest = request.fetch_dest.as_deref().unwrap_or_default();
    if !dest.eq_ignore_ascii_case("document") {
        return false;
    }
    if !request
        .fetch_site
        .as_deref()
        .is_some_and(|site| site.eq_ignore_ascii_case("cross-site"))
    {
        return false;
    }
    // `?1` is the user-activated form; anything else (`?0`, absent) is not user-triggered. A value of
    // `?1` is the only thing this refuses, so an unrecognised value keeps the popup verdict.
    !request
        .fetch_user
        .as_deref()
        .is_some_and(|user| user.trim() == "?1")
}

/// The `$popup` rule set.
#[derive(Default, Debug)]
pub struct PopupRules {
    lines: Vec<String>,
    rejected: Vec<(String, String)>,
    group: EngineGroup,
}

impl PopupRules {
    /// Add one list body.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('[') {
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            let Some((exception, pattern, options)) = split_rule(trimmed) else {
                continue;
            };
            if !options.contains(&"popup") {
                continue;
            }
            // `$popup` is matched as `$document`: a popup *is* a top-level navigation, and asking the
            // engine for a document match is what makes a pattern-less rule (`$popup,3p,domain=…`)
            // mean "any document request from these sites" instead of matching nothing. Without this
            // the option would be stripped to a bare pattern, and the engine would match it against
            // every resource type on the page.
            let mut kept: Vec<&str> = options
                .iter()
                .copied()
                .filter(|option| *option != "popup")
                .filter(|option| *option != "document" && *option != "doc")
                .collect();
            if !kept.contains(&"all") {
                kept.push("document");
            }
            let stripped = rebuild(exception, pattern, &kept);
            if !engine_accepts(&stripped) {
                self.rejected
                    .push((trimmed.to_string(), format!("no matchable form: {stripped}")));
                continue;
            }
            self.lines.push(trimmed.to_string());
            self.group.members.push(stripped);
        }
        // Derived state: rebuilt on `build`, never carried across an `add_list`.
        self.group.engine = None;
    }

    /// Compile the group. Called once after every list is loaded.
    pub fn build(&mut self) {
        self.group.engine = build_engine(self.group.members.iter());
    }

    /// Whether a `$popup` rule matches this navigation.
    ///
    /// The engine answers "does the rule's pattern and its other options match", and
    /// [`is_popup_navigation`] answers "is this navigation a popup at all". Both are required: a
    /// `$popup` rule only forbids *popups* on its pattern, and the same pattern reached by a normal
    /// navigation must be forwarded.
    pub fn blocks(&self, request: &HttpRequest, kind: RequestKind) -> bool {
        let Some(engine) = self.group.engine.as_ref() else {
            return false;
        };
        if !is_popup_navigation(request, kind) {
            return false;
        }
        let adblock_request = crate::http::decision::to_adblock_request(request, kind);
        engine.check_network_request(&adblock_request).should_block()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn rejected(&self) -> &[(String, String)] {
        &self.rejected
    }
}

// ---------------------------------------------------------------------------------------------
// $denyallow
// ---------------------------------------------------------------------------------------------

/// A `$denyallow` rule: "the pattern, except for requests to these hosts".
///
/// `$denyallow` is uBlock Origin's escape hatch for broad rules: `*$script,denyallow=cdn.a|cdn.b,domain=x`
/// means "block every script on x, except those served from the CDNs the site needs". The engine
/// rejects the option, so the whole 119-rule family currently filters nothing at all — the broad rule
/// that was supposed to block the rest is dropped with it.
///
/// # How it is evaluated
///
/// Same pattern as `$removeheader`: the option is removed, the rest is compiled, and the engine's own
/// answer stands **unless** the request's hostname is one the rule exempts. The exemption is a
/// subdomain match on the authority (`||`-style), which is what `denyallow` means in uBO: `a.example`
/// exempts `a.example` and `x.a.example`, never `nota.example`.
///
/// # What is different from uBO
///
/// uBO also honours a `$denyallow` list on an **exception** rule (an `@@` line, where the list turns
/// into an "allow only these hosts" allowlist). Those rules are compiled the same way here: the
/// exception's own match applies and the denyallow list narrows it. The two readings only diverge for a
/// rule that is neither broad nor an exception, which does not occur in the catalog.
#[derive(Default, Debug)]
pub struct DenyAllowRules {
    rules: Vec<DenyAllowRule>,
    rejected: Vec<(String, String)>,
    /// One engine per denyallow list, so a request is matched against each rule group that could apply
    /// instead of against every rule.
    groups: BTreeMap<String, EngineGroup>,
    /// The rules whose `$domain=` list names a given source host, keyed by the entry.
    ///
    /// A `$domain=` entry names the **source**, so a request whose referer is outside every rule's list
    /// cannot match any of them. Indexing by entry keeps that screen free: the lookup enumerates the
    /// suffixes of the referer's host. Only positive entries are indexed — an exclusion admits every
    /// source but the ones it names, so it cannot skip the query, and a rule whose `$domain=` has no
    /// positive entry goes into [`Self::always_in_scope`] instead.
    by_scope: BTreeMap<String, Vec<usize>>,
    /// Rules no `$domain=` screen can exclude: no option at all, only `,_`/`*`, or only exclusions.
    always_in_scope: Vec<usize>,
    /// The rules whose `denyallow` list names a given host, keyed by the entry.
    ///
    /// A single rule's list routinely names hundreds of hosts, so scanning every rule's list on every
    /// request is the whole cost of this family. The lookup enumerates the suffixes of the request's
    /// hostname instead (`a.b.example` → `a.b.example`, `b.example`, `example`), which is how the
    /// subdomain comparison works anyway. Built by [`build`](Self::build).
    by_allow: BTreeMap<String, Vec<usize>>,
}

/// One compiled `$denyallow` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyAllowRule {
    /// The rule as the list wrote it.
    pub text: String,
    /// The hosts this rule exempts, lowercased, as written.
    pub allow: Vec<String>,
    /// The rule with `$denyallow` removed, which is what the engine matches.
    pub stripped: String,
    /// Key into [`DenyAllowRules::groups`].
    pub group: String,
}

impl DenyAllowRules {
    /// Add one list body.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('[') {
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            let Some((exception, pattern, options)) = split_rule(trimmed) else {
                continue;
            };
            let Some(value) = options.iter().find_map(|option| option.strip_prefix("denyallow="))
            else {
                continue;
            };
            let allow: Vec<String> = value
                .split('|')
                .map(|host| host.trim().trim_start_matches('*').trim_start_matches('.'))
                .filter(|host| !host.is_empty())
                .map(str::to_ascii_lowercase)
                .collect();
            if allow.is_empty() {
                self.rejected
                    .push((trimmed.to_string(), "empty denyallow list".to_string()));
                continue;
            }
            // `,_` is uBO's "no domain constraint" placeholder and is not an option the engine knows.
            let kept: Vec<&str> = options
                .iter()
                .copied()
                .filter(|option| *option != "_" && !option.starts_with("denyallow="))
                .collect();
            let stripped = rebuild(exception, pattern, &kept);
            if !engine_accepts(&stripped) {
                self.rejected
                    .push((trimmed.to_string(), format!("no matchable form: {stripped}")));
                continue;
            }
            let group = format!("{}\u{1}{}", if exception { "@@" } else { "" }, allow.join("|"));
            self.groups
                .entry(group.clone())
                .or_default()
                .members
                .push(stripped.clone());
            // The rule's own positive `$domain=` entries, so a request from outside them can skip the
            // engine query. `$domain=` names the *source*, so these are compared against the referer.
            // `,_` is uBO's "no domain constraint" placeholder and means exactly that: no screen.
            let domain_value = options.iter().find_map(|option| option.strip_prefix("domain="));
            let positive: Vec<String> = domain_value
                .map(|value| {
                    value
                        .split('|')
                        .map(|entry| entry.trim().to_ascii_lowercase())
                        .filter(|entry| {
                            !entry.is_empty() && entry != "*" && entry != "_" && !entry.starts_with('~')
                        })
                        .collect()
                })
                .unwrap_or_default();
            let index = self.rules.len();
            match positive.is_empty() {
                // No positive entry: nothing but a negated list (or none at all), so no source can be
                // excluded by comparison.
                true => self.always_in_scope.push(index),
                false => {
                    for entry in positive {
                        self.by_scope.entry(entry).or_default().push(index);
                    }
                }
            }
            self.rules.push(DenyAllowRule {
                text: trimmed.to_string(),
                allow,
                stripped,
                group,
            });
        }
        for group in self.groups.values_mut() {
            group.engine = None;
        }
    }

    /// Compile every group. Called once after all lists are loaded.
    pub fn build(&mut self) {
        for group in self.groups.values_mut() {
            group.engine = build_engine(group.members.iter());
        }
        self.by_allow.clear();
        for (index, rule) in self.rules.iter().enumerate() {
            for entry in &rule.allow {
                self.by_allow.entry(entry.clone()).or_default().push(index);
            }
        }
    }

    /// What a `$denyallow` rule says about this request.
    ///
    /// `None` when no rule of this family matches it, `Some(true)` when it must be blocked and
    /// `Some(false)` when it must be forwarded.
    ///
    /// # Why this decides the block as well
    ///
    /// The option is one the engine's parser rejects, so the engine never sees the rule *at all* — the
    /// whole line, broad pattern included, is dropped at compile time. That means the blocking half of
    /// `*$script,denyallow=cdn.example,domain=site.example` exists only here: this method compiles the
    /// stripped form and, when it matches, blocks unless the request's host is on the allowlist. The
    /// alternative reading — "the engine blocks, this only exempts" — would filter nothing, because
    /// there is no engine rule left to block.
    pub fn verdict(&self, request: &HttpRequest, kind: RequestKind) -> Option<bool> {
        if self.groups.is_empty() {
            return None;
        }
        let host = request.hostname.to_ascii_lowercase();
        // The source, which is what a `$domain=` entry names. `None` when the request has no referer,
        // in which case a rule that names domains cannot apply (and one that names none still can).
        let source = request
            .referer
            .as_deref()
            .and_then(adblock::url_parser::parse_url)
            .map(|parsed| parsed.hostname().to_ascii_lowercase());
        // The rules the request could be in scope for at all: its source under one of their `$domain=`
        // entries, or a rule with no positive entry (which every source is in scope for). Both sides
        // are index lookups by suffix, so the family's size does not reach the per-request cost.
        let mut in_scope: Vec<usize> = self.always_in_scope.clone();
        if let Some(source) = source.as_deref() {
            for suffix in host_suffixes(source) {
                if let Some(list) = self.by_scope.get(suffix) {
                    in_scope.extend_from_slice(list);
                }
            }
        }
        in_scope.sort_unstable();
        in_scope.dedup();
        if in_scope.is_empty() {
            return None;
        }

        let adblock_request = crate::http::decision::to_adblock_request(request, kind);
        // One query per distinct group: several rules share a `denyallow` list.
        let mut queried: BTreeMap<&str, bool> = BTreeMap::new();
        // The rules whose `denyallow` list names this host are the only ones that can exempt it. The
        // lookup is by suffix, so a list's own size (hundreds of hosts) does not matter.
        let mut exempting: Vec<usize> = Vec::new();
        for suffix in host_suffixes(&host) {
            if let Some(list) = self.by_allow.get(suffix) {
                exempting.extend_from_slice(list);
            }
        }
        exempting.sort_unstable();
        exempting.dedup();
        for index in exempting {
            if in_scope.binary_search(&index).is_err() {
                continue;
            }
            let rule = &self.rules[index];
            let Some(engine) = self.groups.get(&rule.group).and_then(|group| group.engine.as_ref())
            else {
                continue;
            };
            if *queried
                .entry(rule.group.as_str())
                .or_insert_with(|| engine.check_network_request(&adblock_request).should_block())
            {
                return Some(false);
            }
        }

        // Nothing exempted it, so the question is whether any rule of this family blocks it at all —
        // including the ones whose list does not name the host.
        let mut matched = false;
        for index in in_scope {
            let rule = &self.rules[index];
            let Some(engine) = self.groups.get(&rule.group).and_then(|group| group.engine.as_ref())
            else {
                continue;
            };
            if *queried
                .entry(rule.group.as_str())
                .or_insert_with(|| engine.check_network_request(&adblock_request).should_block())
            {
                matched = true;
                break;
            }
        }
        match matched {
            true => Some(true),
            false => None,
        }
    }

    /// Whether a matching `$denyallow` rule lets this request through.
    ///
    /// Convenience over [`verdict`](Self::verdict) for the callers that only need this half.
    pub fn exempts(&self, request: &HttpRequest, kind: RequestKind) -> bool {
        self.verdict(request, kind) == Some(false)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[DenyAllowRule] {
        &self.rules
    }

    pub fn rejected(&self) -> &[(String, String)] {
        &self.rejected
    }
}

/// `host` and every suffix of it after a dot: `a.b.example` → `a.b.example`, `b.example`, `example`.
///
/// The index is keyed by the entry alone, and `example` has to be found from any host under it, so the
/// lookup enumerates the suffixes rather than trying every stored entry.
fn host_suffixes(host: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(host), |current| {
        current.find('.').map(|dot| &current[dot + 1..])
    })
}

// ---------------------------------------------------------------------------------------------
// $removeparam
// ---------------------------------------------------------------------------------------------

/// Largest number of `$removeparam` rules this core will compile.
///
/// Each one can be a user-supplied regular expression evaluated on every decrypted request's query, and
/// a pathological pattern can backtrack quadratically. The default catalog carries 2,759 rules of this
/// family, so the cap sits well above it: it never bites in practice and still bounds what a
/// subscription can make the tunnel do.
pub const MAX_REMOVEPARAM_RULES: usize = 4096;

/// Largest number of per-scope-form engines held between requests.
///
/// A rule whose pattern or options the engine has to decide is answered *for that rule alone* — "does rule
/// R apply here" — and the exact way to ask that is an engine holding nothing but R's stripped form. One
/// costs ~43 µs to build and ~24 KiB resident (measured on the host).
///
/// # What happens at the cap, precisely
///
/// When the map already holds this many entries, the **whole map is cleared** and the form being asked is
/// then inserted, so the cache restarts from one entry rather than refusing to cache anything further. Both
/// the bound and the restarting are deliberate: the bound caps the memory (~128 × 24 KiB ≈ 3 MiB), and
/// clearing wholesale is one operation instead of an eviction policy on a map that a real rule set never
/// fills — the default catalog has 339 forms but builds **15** over a realistic request stream, and reaching
/// the cap at all takes a synthetic one-form-per-request workload (see
/// `the_scope_engine_cache_is_bounded_and_shared_by_the_rule_set`).
///
/// Correctness does not depend on the cache: a form that is not cached is rebuilt for that request.
///
/// # Ownership
///
/// The map is a field of [`RemoveParamRules`], so it lives exactly as long as the rule set and is dropped
/// with it. A reload replaces the whole `Arc<ExtraModifiers>`, so a previous list's engines cannot survive
/// into the new set. It is a `Mutex` rather than a thread-local because the rule set is shared by every
/// connection's task: a per-thread cache would multiply the memory and could outlive the rule set it was
/// built from.
pub const MAX_REMOVEPARAM_SCOPE_ENGINES: usize = 128;

/// The value of one `$removeparam` option: which parameter occurrences it names.
///
/// Every form is represented here, including the plain name the engine also implements, because this
/// family decides the modifier from the request's own URL instead of repairing a URL another layer
/// already rewrote (see [`RemoveParamRules`]).
///
/// # Why the value is kept as written, not percent-decoded at compile time
///
/// AdGuard's documentation is explicit that special characters are escaped **in the rule** to match the
/// URL text: `$removeparam=%24param` removes `?$param=true`, and `%24` is *not* the same rule as
/// `param`. The query is matched as it appears on the wire, so the rule's own spelling is what is
/// compared against the wire name. Decoding at compile time would make `%24param` match a literal
/// `$param` in the URL and stop matching `%24param`, the opposite of what the list author wrote.
#[derive(Debug, Clone)]
pub enum ParamMatch {
    /// `$removeparam` with no value: the whole query.
    All,
    /// `$removeparam=name`: every occurrence of the parameter with exactly this name.
    Name(String),
    /// `$removeparam=~name`: every parameter whose name is **not** `name`.
    InvertedName(String),
    /// `$removeparam=/regex/`: every `name=value` pair the regex matches.
    Regex(Arc<regex::Regex>),
    /// `$removeparam=~/regex/`: every `name=value` pair the regex does **not** match.
    InvertedRegex(Arc<regex::Regex>),
}

impl ParamMatch {
    /// Whether this matcher names the occurrence `(name, value)`.
    ///
    /// Decided per occurrence rather than per parameter name, which is what makes
    /// `?tag=drop&tag=keep` come out of `$removeparam=/^tag=drop$/` as `?tag=keep` while
    /// `$removeparam=tag` removes both — the distinction the second review's fourth case measures.
    ///
    /// Public because the independent reference evaluator in `core/examples/removeparam_diff.rs` needs a
    /// matcher's answer to compare against the shipping one; it is the one piece of this family that is a
    /// definition rather than an optimisation.
    pub fn hits(&self, name: &str, value: &str) -> bool {
        match self {
            ParamMatch::All => true,
            ParamMatch::Name(target) => target == name,
            ParamMatch::InvertedName(target) => target != name,
            // A regex matches `name=decoded-value`, as uBO does, so a pattern written against the
            // visible value works. The name is compared as it appears on the wire and only the value is
            // decoded, which is what lets a regex see through `%5F`-style escapes without breaking
            // `$removeparam=%24param`'s deliberate wire-spelling match.
            ParamMatch::Regex(pattern) => {
                pattern.is_match(&format!("{name}={}", percent_decode(value)))
            }
            ParamMatch::InvertedRegex(pattern) => {
                !pattern.is_match(&format!("{name}={}", percent_decode(value)))
            }
        }
    }

    /// The parameter name this matcher can only ever hit, when there is exactly one.
    ///
    /// `None` for every matcher that depends on the value or inverts, which is also the set that has to
    /// be tested against each occurrence.
    fn only_name(&self) -> Option<&str> {
        match self {
            ParamMatch::Name(name) => Some(name),
            _ => None,
        }
    }
}

/// One parameter occurrence of a request URL, kept exactly as it appears on the wire.
///
/// `Some("")` and `None` are different URLs (`?a=` and `?a`), and a rewrite has to reproduce whichever
/// the site sent — as it does the percent-encoding inside both halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Param<'a> {
    name: &'a str,
    value: Option<&'a str>,
}

impl<'a> Param<'a> {
    /// The value a matcher sees: the empty string when the parameter has none.
    fn value_or_empty(&self) -> &'a str {
        self.value.unwrap_or_default()
    }
}

/// Split a query into its occurrences, left to right, preserving order and duplicates.
fn params_of(query: &str) -> Vec<Param<'_>> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((name, value)) => Param {
                name,
                value: Some(value),
            },
            None => Param {
                name: pair,
                value: None,
            },
        })
        .collect()
}

/// Split a URL into `(everything before `?`, the query, everything from `#` on)`.
///
/// `None` when the URL has no `?` at all, which is the common case and answers "nothing to prune"
/// without allocating. The fragment stays a slice of the original so a rewrite reproduces it byte for
/// byte.
fn split_query(url: &str) -> Option<(&str, &str, &str)> {
    let start = url.find('?')?;
    let end = url[start..]
        .find('#')
        .map(|offset| start + offset)
        .unwrap_or(url.len());
    Some((&url[..start], &url[start + 1..end], &url[end..]))
}

/// Rebuild a URL from its parts, dropping the `?` when nothing survives.
fn join_query(base: &str, params: &[Param<'_>], tail: &str) -> String {
    let mut out = String::with_capacity(base.len() + tail.len() + 16);
    out.push_str(base);
    if !params.is_empty() {
        out.push('?');
        for (index, param) in params.iter().enumerate() {
            if index > 0 {
                out.push('&');
            }
            out.push_str(param.name);
            if let Some(value) = param.value {
                out.push('=');
                out.push_str(value);
            }
        }
    }
    out.push_str(tail);
    out
}

/// How one rule's pattern and options constrain where it applies.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    /// `||host^` and nothing else: the request's hostname is `host` or a subdomain of it.
    ///
    /// The one shape whose match is decided by comparing hostnames, and the comparison is exactly the
    /// engine's (`a.shop.example` matches, `shop.example.evil.test` does not) — pinned against the
    /// engine by `the_host_shortcut_agrees_with_the_engine`.
    Host(String),
    /// No pattern at all: every request of the rule's type scope.
    Any,
    /// Everything else — `$domain=`, `$third-party`, a content type, a path, a wildcard, `$important`.
    /// The engine decides (through [`EngineScope`], whose screens only skip what it cannot admit).
    Engine,
}

/// One `$removeparam` rule, in the form the evaluator needs.
#[derive(Debug, Clone)]
pub struct RemoveParamRule {
    /// The rule as the list wrote it.
    pub text: String,
    /// The rule with the `$removeparam` option removed: exactly what the engine matches.
    ///
    /// For a **blocking** rule with no content-type option this also carries `$document`, because
    /// AdGuard's rule is that such a rule only matches a `document` request while the engine applies it
    /// to `document`, `subdocument` *and* `xmlhttprequest`. Writing the scope into the rule the engine
    /// matches is what makes the engine's answer the right one, instead of a correction applied to a
    /// finished URL afterwards.
    pub stripped: String,
    /// What the option asked for.
    pub value: ParamMatch,
    /// An `@@` rule: it protects the occurrences it names instead of pruning them.
    pub exception: bool,
    /// An `$important` rule: no exception can cancel it.
    pub important: bool,
    /// The rule names at least one content type (`$script`, `$xmlhttprequest`, `$~image`, `$all`, …).
    ///
    /// Load-bearing for the same AdGuard rule as `stripped`: `false` on a blocking rule means "document
    /// only".
    pub typed: bool,
    /// Where the pattern and the options allow the rule to fire.
    scope: Scope,
    /// Index into [`RemoveParamRules::scopes`] for [`Scope::Engine`] rules.
    form: Option<usize>,
    /// This core's identity for the rule, used to resolve `$badfilter`.
    ///
    /// Computed from the **whole original line** — the `removeparam` value, the content types, `$domain=`,
    /// `$important`, the `@@` edge and all — because that is what a `$badfilter` names. Resolving the
    /// disable relationship after stripping the option, as an earlier version did, made
    /// `||host^$removeparam=track` and `||host^$removeparam=other` the same text, so disabling one
    /// silently disabled the other.
    key: u64,
    /// A `…,badfilter` line: it cancels the rule whose [`Self::key`] it repeats.
    badfilter: bool,
    /// This rule is not cancelled by any `$badfilter` in force, i.e. it may be evaluated.
    ///
    /// Resolved before building any scope engine or shortcut index.
    active: bool,
}

/// The rule indices one distinct engine form decides.
///
/// Several rules share a stripped form — `||a.example^$xmlhttprequest,removeparam=x` and
/// `||a.example^$xmlhttprequest,removeparam=/^y=/` strip to the same text — so one query answers all of
/// them. The screens are stored per form rather than per rule for the same reason.
#[derive(Debug)]
struct EngineScope {
    /// The stripped form, which is also the cache key.
    stripped: String,
    /// Whether the rules here are `@@` exceptions (they share an option set, so they agree).
    exception: bool,
    /// The host the pattern can only match under, when it states one (`||host…` with no wildcard in the
    /// host part). `None` means the screen cannot rule anything out.
    host_anchor: Option<String>,
    /// The source hosts a `$domain=` list admits, when it has positive entries and none is an entity
    /// form. `None` means the list cannot screen (`~`-only, or an entity form).
    source_anchor: Option<Vec<String>>,
    /// The rules this form decides, in list order.
    rules: Vec<usize>,
}

/// The whole `$removeparam` family, evaluated per parameter occurrence from the request's own URL.
///
/// # Why the URL is built here rather than repaired afterwards
///
/// The previous version evaluated only the forms the engine's parser *refuses*, let the engine produce a
/// rewritten URL for the ones it accepts, and then tried to repair that URL — restoring parameters an
/// untyped rule should not have touched and re-adding the ones an exception protects. That is
/// unfixable in principle: a finished URL does not say **which** rule removed **which** occurrence, so
/// every repair had to guess from parameter *names*. Two rules naming the same parameter (one typed, one
/// not) were then indistinguishable, and a value-sensitive regex could not be told from a name rule at
/// all — the five failures the second review reproduced all come from that guessing.
///
/// This decides the family the way AdGuard does, from the original URL and the complete set of rules in
/// force:
///
/// 1. every rule whose scope matches the request contributes its matcher;
/// 2. an occurrence is removed when a blocking rule names it and no exception names it — unless a
///    blocking rule that names it is `$important`, which no exception can cancel;
/// 3. a blocking rule with no content-type modifier only matches a `document` request.
///
/// The scope (pattern, `$domain=`, `$third-party`, content types) stays the engine's answer, asked one
/// rule at a time — nothing here re-implements pattern matching. The only rule evaluated without the
/// engine is `||host^` with no options, where the hostname comparison *is* the whole rule.
#[derive(Default)]
pub struct RemoveParamRules {
    rules: Vec<RemoveParamRule>,
    rejected: Vec<(String, String)>,
    /// [`Scope::Host`] rules by host, for a suffix lookup on the request's hostname.
    by_host: BTreeMap<String, Vec<usize>>,
    /// Rules whose matcher can only hit one name, by that name.
    ///
    /// This is what keeps the family affordable. The default catalog has 1,006 rules indexed here (the
    /// global `$removeparam=utm_source`-style entries among them), the unscoped ones apply to *every*
    /// document, and a name lookup answers them without a query per rule. It also means a request naming no
    /// tracked parameter never reaches the engine at all.
    by_name: BTreeMap<String, Vec<usize>>,
    /// Rules that have to be tested against every occurrence: a regex, an inversion, or the bare form.
    ///
    /// Small on purpose — the default catalog has 63, and a rule with a pattern still gets its
    /// [`EngineScope`] host screen before the query.
    by_value: Vec<usize>,
    /// The distinct engine forms, in a stable order.
    scopes: Vec<EngineScope>,
    /// The engine forms a request's hostname can reach without a screen: no host anchor.
    scopes_unanchored: Vec<usize>,
    /// The engine forms by their host anchor, for a suffix lookup.
    scopes_by_host: BTreeMap<String, Vec<usize>>,
    /// One engine over the stripped form of **every** blocking rule: "does this family apply at all".
    ///
    /// This is the fast path, and it is what keeps 2,759 rules off the per-request cost: a request no
    /// `$removeparam` rule names — almost every subresource — costs one query and nothing else.
    /// Exceptions are deliberately **not** here. The engine's `@@` cancels a block inside one engine, so
    /// a gate holding both would answer "nothing matched" for a request an exception merely *narrows* —
    /// a global prune of two parameters plus an exception for one of them is exactly that shape, and the
    /// parameter the exception does not name must still go.
    gate: Option<adblock::Engine>,
    /// Per-form engines, built on first use and bounded by [`MAX_REMOVEPARAM_SCOPE_ENGINES`].
    ///
    /// A `Mutex` rather than a thread-local: the rule set is shared by every connection's task, so a
    /// per-thread cache would multiply the memory and could outlive a reload.
    cache: std::sync::Mutex<BTreeMap<String, Option<adblock::Engine>>>,
}

impl std::fmt::Debug for RemoveParamRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoveParamRules")
            .field("rules", &self.rules.len())
            .field("rejected", &self.rejected.len())
            .field("scope_forms", &self.scopes.len())
            .field("cached_engines", &self.cached_engines())
            .finish()
    }
}

impl RemoveParamRules {
    /// Add one list body.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('[') {
                continue;
            }
            if trimmed.starts_with('#') {
                continue;
            }
            let Some((exception, pattern, options)) = split_rule(trimmed) else {
                continue;
            };
            let Some(option) = options
                .iter()
                .copied()
                .find(|option| *option == "removeparam" || option.starts_with("removeparam="))
            else {
                continue;
            };
            // The cap bounds rules that will be *evaluated*, so a `$badfilter` directive does not consume
            // a slot: one cap of 4,096 must not be reachable by 4,096 directives and leave no room for
            // rules.
            if !is_badfilter_line(trimmed) && self.in_force_len() >= MAX_REMOVEPARAM_RULES {
                self.rejected
                    .push((trimmed.to_string(), "rule cap reached".to_string()));
                continue;
            }
            let value = option.strip_prefix("removeparam=").unwrap_or_default().trim();
            let Some(matcher) = compile_param_matcher(value) else {
                self.rejected.push((
                    trimmed.to_string(),
                    format!("unsupported $removeparam form: {value}"),
                ));
                continue;
            };
            let typed = has_content_type(&options);
            // Every option except the `removeparam` one is kept, `$important` included: it changes
            // nothing about *where* the rule applies, so the stripped form with it is the same match, and
            // keeping it makes the stripped text an honest key for the rule as the list wrote it.
            let kept: Vec<&str> = options
                .iter()
                .copied()
                .filter(|candidate| *candidate != option)
                .collect();
            let stripped = engine_form(exception, pattern, &kept, typed);
            if !engine_accepts(&stripped) {
                self.rejected.push((
                    trimmed.to_string(),
                    format!("no matchable form: {stripped}"),
                ));
                continue;
            }
            // The direct scopes are only taken where the *whole* rule is the host (or the absence of a
            // pattern): no options at all, so `$domain=`, `$third-party`, a content type and `$important`
            // are all excluded by construction. Everything else is the engine's answer.
            let direct = !typed && kept.is_empty();
            let scope = match (direct, plain_host_scope(pattern), pattern.is_empty()) {
                (true, Some(host), _) => Scope::Host(host.to_string()),
                (true, None, true) => Scope::Any,
                _ => Scope::Engine,
            };
            let important = kept.contains(&"important");
            let badfilter = options.contains(&"badfilter");
            self.rules.push(RemoveParamRule {
                text: trimmed.to_string(),
                stripped,
                value: matcher,
                exception,
                important,
                typed,
                scope,
                form: None,
                key: badfilter_key(trimmed),
                badfilter,
                // Provisionally in force: `add_list` sees one body at a time and a `$badfilter` may arrive
                // in a body read later, so the authoritative answer is computed in `build` across every
                // list. Marking the rule here is what lets `len`/`is_empty`/`evaluates` answer for a single
                // body without a full compile — `evaluates` asks exactly that question about one line.
                active: !badfilter,
            });
        }
        // Derived state: rebuilt by `build`, never carried across an `add_list`.
        self.gate = None;
        self.scopes.clear();
        self.scopes_unanchored.clear();
        self.scopes_by_host.clear();
        self.cached_engines_map().clear();
    }

    /// Compile the rule set. Called once after all lists are loaded.
    pub fn build(&mut self) {
        // **First** resolve `$badfilter`, across every list that was read. It has to happen before any
        // derived structure exists, because a cancelled rule must not reach *any* of them: not the gate
        // engine, not the host/name/value indexes, not a per-form engine. The previous version resolved
        // nothing at all — the disabled rule stayed in every structure and came back to life as soon as
        // another rule opened the gate, which is exactly the stage-1 review's second case.
        let cancelled: BTreeSet<u64> = self
            .rules
            .iter()
            .filter(|rule| rule.badfilter)
            .map(|rule| rule.key)
            .collect();
        for rule in &mut self.rules {
            // A `$badfilter` line is a directive, not a rule: it never applies to a request itself. A rule
            // whose identity some `$badfilter` repeats is cancelled.
            rule.active = !rule.badfilter && !cancelled.contains(&rule.key);
        }

        self.by_host.clear();
        self.by_name.clear();
        self.by_value.clear();
        self.scopes.clear();
        self.scopes_unanchored.clear();
        self.scopes_by_host.clear();
        self.cached_engines_map().clear();
        // A `BTreeMap` keyed by the stripped text, so two addresses that differ only in list order get
        // the same scope order: the reported result must never depend on which list was read first.
        let mut forms: BTreeMap<String, usize> = BTreeMap::new();
        for index in 0..self.rules.len() {
            if !self.rules[index].active {
                continue;
            }
            let rule = &self.rules[index];
            match rule.scope.clone() {
                Scope::Host(host) => self
                    .by_host
                    .entry(host.to_ascii_lowercase())
                    .or_default()
                    .push(index),
                _ => {
                    // Every rule is indexed by what its *matcher* can hit, so a request pays only for
                    // the parameters it carries. The index decides the candidate set; `in_force` still
                    // asks the scope of each candidate, so an index entry can never make a rule fire on
                    // its matcher alone.
                    match rule.value.only_name() {
                        Some(name) => self.by_name.entry(name.to_string()).or_default().push(index),
                        None => self.by_value.push(index),
                    }
                    if !matches!(rule.scope, Scope::Engine) {
                        continue;
                    }
                    let position = match forms.get(&rule.stripped) {
                        Some(position) => *position,
                        None => {
                            let position = self.scopes.len();
                            self.scopes.push(EngineScope {
                                stripped: rule.stripped.clone(),
                                exception: rule.exception,
                                host_anchor: pattern_anchor(&rule.text),
                                source_anchor: source_anchor(&rule.text),
                                rules: Vec::new(),
                            });
                            forms.insert(rule.stripped.clone(), position);
                            position
                        }
                    };
                    self.scopes[position].rules.push(index);
                    self.rules[index].form = Some(position);
                }
            }
        }
        for (position, form) in self.scopes.iter().enumerate() {
            match form.host_anchor.clone() {
                Some(host) => self.scopes_by_host.entry(host).or_default().push(position),
                None => self.scopes_unanchored.push(position),
            }
        }
        // **Every active blocking form**, including the ones the direct scopes decide: the gate answers
        // "does this family apply at all", and a gate missing the rules the host comparison handles would
        // close on almost every request and skip them entirely.
        //
        // Built last, from the rules `active` marks, so a cancelled rule contributes no form. Note that the
        // gate is an optimisation over *rules that are in force*, not over a set of distinct texts: two
        // different rules that strip to the same text both add that text, which is harmless (the gate is a
        // boolean) precisely because the per-rule filter below is what decides.
        let blocking_forms: Vec<String> = self
            .rules
            .iter()
            .filter(|rule| rule.active && !rule.exception)
            .map(|rule| rule.stripped.clone())
            .collect();
        self.gate = build_engine(blocking_forms.iter());
    }

    fn cached_engines_map(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<String, Option<adblock::Engine>>> {
        self.cache.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// The URL after `$removeparam`, or `None` when nothing is to be removed.
    ///
    /// This is the whole entry point for the modifier: the request as it arrived goes in, the final URL
    /// (or nothing) comes out. There is no base URL to compose with and no URL to repair, so the result
    /// cannot depend on how another layer already rewrote the request, and a hot reload or a serialized
    /// rule set decides exactly as the process that compiled the lists did.
    pub fn rewrite(&self, request: &HttpRequest, kind: RequestKind) -> Option<String> {
        if self.rules.is_empty() {
            return None;
        }
        let (base, query, tail) = split_query(&request.url)?;
        if query.is_empty() {
            return None;
        }
        if !self.gate_open(request, kind) {
            return None;
        }
        let params = params_of(query);
        let scope = RequestScope::of(request, kind);
        let blocking = self.in_force(&scope, &params, false);
        if blocking.is_empty() {
            return None;
        }
        // An exception changes nothing unless something is being pruned, so it is asked only after the
        // blocking half has an answer.
        let exceptions = if self.rules.iter().any(|rule| rule.exception) {
            self.in_force(&scope, &params, true)
        } else {
            Vec::new()
        };
        let mut any = false;
        let kept: Vec<Param<'_>> = params
            .iter()
            .filter(|param| {
                let name = param.name;
                let value = param.value_or_empty();
                let removed = blocking
                    .iter()
                    .any(|index| self.rules[*index].value.hits(name, value));
                if !removed {
                    return true;
                }
                any = true;
                // `$important` outranks every exception — that is the whole point of the modifier, and
                // AdGuard's own case 6 writes an important rule and an exception for the same parameter
                // and expects the rule to win.
                if blocking
                    .iter()
                    .any(|index| self.rules[*index].important && self.rules[*index].value.hits(name, value))
                {
                    return false;
                }
                // The occurrence is removed: keep it only when an exception names *this* occurrence.
                exceptions
                    .iter()
                    .any(|index| self.rules[*index].value.hits(name, value))
            })
            .copied()
            .collect();
        // Nothing removed, or an exception protected every occurrence a blocking rule named: the URL is
        // the one the request arrived with, and an unchanged URL must not be reported as a rewrite — the
        // relay would turn it into a pointless re-request.
        if !any || kept.len() == params.len() {
            return None;
        }
        Some(join_query(base, &kept, tail))
    }

    /// Whether any blocking rule of this family applies to this request.
    ///
    /// Answered by one engine query over every blocking form. A closed gate is a *sound* "nothing to do":
    /// it holds exactly the forms the per-rule queries would ask, and holds no exception (see the gate
    /// field).
    fn gate_open(&self, request: &HttpRequest, kind: RequestKind) -> bool {
        let Some(engine) = self.gate.as_ref() else {
            // No engine means there is no blocking rule at all (the collector reports the ones it
            // refused), so nothing can be pruned.
            return false;
        };
        let adblock_request = crate::http::decision::to_adblock_request(request, kind);
        engine.check_network_request(&adblock_request).should_block()
    }

    /// The rules of one half (`exception = false`: blocking, `true`: exceptions) in force for this
    /// request, in list order.
    ///
    /// Candidates come from the indexes rather than from a scan — the parameter names the URL actually
    /// carries, the hosts it could match, and the value-dependent rules — and every candidate's **scope**
    /// is then asked, so an index entry can never make a rule fire on its matcher alone. The scope answers
    /// for one request are memoised per scope form, so a rule set with 300 rules on one form costs one
    /// engine query rather than 300.
    fn in_force(
        &self,
        scope: &RequestScope<'_>,
        params: &[Param<'_>],
        exception: bool,
    ) -> Vec<usize> {
        let mut found: Vec<usize> = Vec::new();
        // Which scope forms are in force for this request, decided on first use.
        let mut forms: BTreeMap<usize, bool> = BTreeMap::new();
        let candidate = |index: usize, found: &mut Vec<usize>, forms: &mut BTreeMap<usize, bool>| {
            let rule = &self.rules[index];
            if !rule.active || rule.exception != exception || !self.kind_allows(rule, scope.kind) {
                return;
            }
            let in_force = match rule.form {
                None => true,
                Some(position) => *forms
                    .entry(position)
                    .or_insert_with(|| self.form_matches(position, scope)),
            };
            if in_force {
                found.push(index);
            }
        };
        // Every distinct parameter name in the URL, so a name-indexed rule is looked up once.
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for param in params {
            if !seen.insert(param.name) {
                continue;
            }
            if let Some(indices) = self.by_name.get(param.name) {
                for index in indices {
                    candidate(*index, &mut found, &mut forms);
                }
            }
        }
        for index in &self.by_value {
            candidate(*index, &mut found, &mut forms);
        }
        for suffix in host_suffixes(&scope.host) {
            if let Some(indices) = self.by_host.get(suffix) {
                for index in indices {
                    // A `Scope::Host` rule is fully decided by the index that produced it, so it has no
                    // form to ask — but it still has to be filtered to the right half and type scope.
                    let rule = &self.rules[*index];
                    if rule.active
                        && rule.exception == exception
                        && self.kind_allows(rule, scope.kind)
                    {
                        found.push(*index);
                    }
                }
            }
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    /// The engine's answer for one scope form, through the bounded cache.
    ///
    /// The screens run first, so a form whose pattern or `$domain=` provably cannot admit this request
    /// costs no query and no cache slot.
    fn form_matches(&self, position: usize, scope: &RequestScope<'_>) -> bool {
        let form = &self.scopes[position];
        if !form.admits(scope) {
            return false;
        }
        let exception = form.exception;
        let mut cache = self.cached_engines_map();
        if let Some(cached) = cache.get(&form.stripped) {
            return cached
                .as_ref()
                .is_some_and(|engine| query_engine(engine, &scope.adblock_request, exception));
        }
        if cache.len() >= MAX_REMOVEPARAM_SCOPE_ENGINES {
            // Past the cap the form is still evaluated exactly; it is simply not remembered. Clearing the
            // whole map keeps this a single operation, and a map at its cap means a rule set with far
            // more scope forms than any real list.
            cache.clear();
        }
        let built = build_engine(std::iter::once(&form.stripped));
        let matched = built
            .as_ref()
            .is_some_and(|engine| query_engine(engine, &scope.adblock_request, exception));
        cache.insert(form.stripped.clone(), built);
        matched
    }

    /// Whether the rule's own type scope allows this request.
    ///
    /// The document-only rule for an untyped **blocking** rule has to be applied here only for the
    /// scopes the engine is not asked about: an [`Scope::Engine`] blocking rule carries `$document` in
    /// its stripped form, so the engine already applied the rule. It is applied uniformly anyway —
    /// it is the same condition, stated once. An exception is never narrowed this way: it only ever
    /// *reduces* what a blocking rule may remove, and an untyped exception is the only spelling the
    /// engine's parser refuses, so narrowing it would silently disable every exception in a real list on
    /// a `fetch()`.
    fn kind_allows(&self, rule: &RemoveParamRule, kind: RequestKind) -> bool {
        rule.typed || rule.exception || kind == RequestKind::Document
    }

    /// Distinct scope forms in the rule set, for the delivery note's footprint report.
    pub fn scope_form_count(&self) -> usize {
        self.scopes.len()
    }

    /// Distinct per-form engines currently cached, so a delivery note can state the bound.
    pub fn cached_engines(&self) -> usize {
        self.cached_engines_map().len()
    }

    /// Rules in force, i.e. every collected rule except the `$badfilter` directives and the rules they
    /// cancel.
    ///
    /// Reportable numbers ("N removeparam rules" in the compile log, the stats JSON, the stats screen) have
    /// to count what actually decides a request. Counting the directives, or the rules they disable, would
    /// advertise filtering that does not happen — and the difference was visible on device before this was
    /// fixed (`extras.txt` reported 198 while 178 were in force).
    pub fn len(&self) -> usize {
        self.in_force_len()
    }

    /// Rules collected so far that are not directives, for the cap.
    ///
    /// A rule cancelled by a `$badfilter` may arrive *after* the directive, so "in force" is not known
    /// until `build`; the cap therefore bounds the number of rules *collected*, which is what bounds the
    /// work and the memory. Directives are excluded for the reason the cap exists — see `add_list`.
    fn in_force_len(&self) -> usize {
        self.rules.iter().filter(|rule| rule.active).count()
    }

    pub fn is_empty(&self) -> bool {
        !self.rules.iter().any(|rule| rule.active)
    }

    /// Every rule the family holds, **including** directives and cancelled rules, for diagnostics.
    pub fn rules(&self) -> &[RemoveParamRule] {
        &self.rules
    }

    pub fn rejected(&self) -> &[(String, String)] {
        &self.rejected
    }

    /// Every rule line this family evaluates, for `extras.txt`.
    ///
    /// `extras.txt` is the only thing that survives a restart: the container is rebuilt from it at load
    /// (`compile::load_extra_modifiers`). This family now holds **every** `$removeparam` rule — the ones
    /// the engine also applies included — because the evaluation needs the whole set, so the union is
    /// simply the list's own lines, de-duplicated and in list order.
    pub fn all_texts(&self) -> Vec<&String> {
        let mut seen = std::collections::BTreeSet::new();
        self.rules
            .iter()
            .filter(|rule| seen.insert(rule.text.as_str()))
            .map(|rule| &rule.text)
            .collect()
    }
}

/// Everything the per-request evaluation needs to know about one request, built once.
struct RequestScope<'a> {
    host: String,
    kind: RequestKind,
    /// The referer's hostname, which is what a `$domain=` entry names. `None` when there is no usable
    /// referer, in which case a rule naming positive domains cannot apply — measured, and the engine
    /// agrees: `$domain=example.com` does not match a request without a referer.
    source: Option<String>,
    /// Built once and shared by every engine query this request makes.
    adblock_request: adblock::request::Request,
    /// Kept so the scope can outlive the borrow it was built from.
    _request: &'a HttpRequest,
}

impl<'a> RequestScope<'a> {
    fn of(request: &'a HttpRequest, kind: RequestKind) -> Self {
        Self {
            host: request.hostname.to_ascii_lowercase(),
            kind,
            source: request
                .referer
                .as_deref()
                .and_then(adblock::url_parser::parse_url)
                .map(|parsed| parsed.hostname().to_ascii_lowercase()),
            adblock_request: crate::http::decision::to_adblock_request(request, kind),
            _request: request,
        }
    }
}

impl EngineScope {
    /// Whether the cheap screens admit this request at all.
    ///
    /// Both screens are **necessary conditions** read off the rule's own text, never an approximation of
    /// the engine's matcher: a pattern anchored at `||host` cannot match a request to another host, and a
    /// positive `$domain=` entry cannot match a request whose source is elsewhere. Whatever the screens
    /// cannot derive is left to the engine.
    fn admits(&self, scope: &RequestScope<'_>) -> bool {
        if let Some(anchor) = self.host_anchor.as_deref() {
            if !host_may_match(&scope.host, anchor) {
                return false;
            }
        }
        if let Some(entries) = self.source_anchor.as_deref() {
            let Some(source) = scope.source.as_deref() else {
                return false;
            };
            if !entries.iter().any(|entry| host_matches(source, entry)) {
                return false;
            }
        }
        true
    }
}

/// Whether a `||anchor` pattern can match a request to `host`.
///
/// `||` anchors at a **domain-label boundary**, so the needle has to start at the beginning of some
/// label of the hostname (`www.google.com` offers `www.google.com`, `google.com`, `com`) — and a pattern
/// does not have to be a whole host: `||google.` matches `www.google.com` because `google.` is a prefix of
/// `google.com`. So the screen is "some label boundary starts with the anchor", which is a **necessary
/// condition** on the engine's answer and therefore a sound reason to skip the query.
///
/// Deliberately a superset: a pattern that continues into a path (`||host/path`) still passes this
/// screen, and the engine decides the rest. Being a superset is what keeps it safe; being tighter would
/// risk skipping a rule the engine would have matched — which is exactly the failure
/// `the_pattern_screen_never_rejects_a_rule_the_engine_matches` exists to catch.
fn host_may_match(host: &str, anchor: &str) -> bool {
    if anchor.is_empty() {
        return true;
    }
    host_suffixes(host).any(|suffix| {
        suffix.len() >= anchor.len() && suffix[..anchor.len()].eq_ignore_ascii_case(anchor)
    })
}

/// The `pattern_anchor` screen, exposed for the differential check that pins its soundness.
pub fn pattern_screen_admits(hostname: &str, anchor: &str) -> bool {
    host_may_match(&hostname.to_ascii_lowercase(), anchor)
}

/// The `||host^` shortcut, exposed for the differential check that pins it to the engine's answer.
///
/// Not used by the tunnel — [`RemoveParamRules`] calls [`host_matches`] directly — but the equivalence has
/// to be checkable against the real catalog from outside a unit test, and this is the narrowest way to
/// expose it without making the matcher itself public.
pub fn host_shortcut_matches(hostname: &str, anchor: &str) -> bool {
    host_matches(hostname, anchor)
}

/// Whether `hostname` is `pattern` or a subdomain of it, exactly as `||pattern^` means.
///
/// The engine's own answer for this form: `a.shop.example` matches, `shop.example.evil.test` and
/// `notshop.example` do not. Pinned against the engine by a test, so the shortcut cannot quietly diverge
/// from what a per-rule query would say.
fn host_matches(hostname: &str, pattern: &str) -> bool {
    hostname.eq_ignore_ascii_case(pattern)
        || (hostname.len() > pattern.len()
            && hostname.as_bytes()[hostname.len() - pattern.len() - 1] == b'.'
            && hostname[hostname.len() - pattern.len()..].eq_ignore_ascii_case(pattern))
}

/// `||host^` — the one pattern shape whose match can be decided by comparing the hostname alone.
///
/// Returns the host only for exactly that: a `||` anchor, a plain host with no wildcard, a `^`
/// terminator and nothing else. Every other shape returns `None` and is answered by the engine, which is
/// the only thing that knows what `$domain=`, `$third-party`, a content type, a path or a wildcard does.
/// The shortcut is therefore only taken where it is the *same* answer, never as an approximation.
fn plain_host_scope(pattern: &str) -> Option<&str> {
    let rest = pattern.strip_prefix("||")?;
    let host = rest.strip_suffix('^')?;
    if host.is_empty() || host.contains(['/', '|', '*', '?', '&', '=']) {
        return None;
    }
    Some(host)
}

/// The host a rule's pattern is anchored at, when it states one that nothing else on the rule can widen.
///
/// Only a screen for the engine forms, so it has to be a *necessary* condition: a `||`-anchored pattern
/// whose host part has no wildcard can only match a request whose hostname is that host, a subdomain of
/// it, or (when a path follows) a URL that begins with it.
fn pattern_anchor(text: &str) -> Option<String> {
    let body = text.strip_prefix("@@").unwrap_or(text);
    let pattern = body.split_once('$').map(|(pattern, _)| pattern).unwrap_or(body);
    let rest = pattern.strip_prefix("||")?;
    let end = rest
        .find(['/', '^', '?', '|', '$', '&', '='])
        .unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() || host.contains('*') {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// The source hosts a rule's `$domain=` list admits, when the list can be used as a screen.
///
/// `None` when there is no `$domain=`, when every entry is an exclusion (a `~`-only list admits every
/// source but the ones it names, so it cannot exclude anything from the query), or when an entry is an
/// entity form (`example.*`) this comparison does not model. The engine still applies the whole list —
/// this only decides whether the rule is worth asking.
fn source_anchor(text: &str) -> Option<Vec<String>> {
    let body = text.strip_prefix("@@").unwrap_or(text);
    let (_, options) = body.split_once('$')?;
    let value = options
        .split(',')
        .find_map(|option| option.trim().strip_prefix("domain="))?;
    let mut positive = Vec::new();
    for entry in value.split('|') {
        let entry = entry.trim().to_ascii_lowercase();
        if entry.is_empty() || entry == "*" || entry == "_" || entry.starts_with('~') {
            continue;
        }
        if entry.contains('*') {
            return None;
        }
        positive.push(entry);
    }
    (!positive.is_empty()).then_some(positive)
}

/// The rule text the engine matches for one `$removeparam` rule.
///
/// Two corrections to the bare "strip the option" form, both stating a fact the engine would otherwise
/// get wrong for this family:
///
/// * a blank pattern strips to an empty line, which the engine refuses; `*` is the same "any URL" and
///   parses.
/// * a **blocking** rule with no content type is `document`-only (AdGuard's rule), while the engine
///   applies such a `$removeparam` rule to `document`, `subdocument` and `xmlhttprequest`. Writing
///   `$document` into the rule the engine matches is what makes its answer the right one instead of a
///   correction applied to a finished URL afterwards. An exception is not narrowed: `@@` only ever
///   reduces what a blocking rule may remove.
fn engine_form(exception: bool, pattern: &str, kept: &[&str], typed: bool) -> String {
    let pattern = if pattern.is_empty() { "*" } else { pattern };
    let mut options = kept.to_vec();
    if !exception && !typed && !options.contains(&"document") {
        options.push("document");
    }
    rebuild(exception, pattern, &options)
}

/// The engine's answer for one already-compiled rule.
fn query_engine(
    engine: &adblock::Engine,
    request: &adblock::request::Request,
    exception: bool,
) -> bool {
    if exception {
        // "Would this `@@` rule cancel a block?" — the engine only looks for exceptions when it found a
        // blocking rule, so the question has to be forced. `previously_matched_rule` *is* that question
        // ("assume a block matched"), not an assumption about this request, so the answer is still the
        // rule's own pattern and type scope.
        engine
            .check_network_request_subset(request, true, true)
            .exception
            .is_some()
    } else {
        engine.check_network_request(request).should_block()
    }
}

/// Whether this line is a `$badfilter` directive (it cancels a rule rather than being one).
fn is_badfilter_line(line: &str) -> bool {
    split_rule(line).is_some_and(|(_, _, options)| options.contains(&"badfilter"))
}

/// Identity for `$badfilter`: parsed scope, exception edge, and the original parameter matcher.
///
/// The engine canonicalises type aliases, option/domain order and case-insensitive URL patterns. Give it
/// a fixed legal modifier value so it can also identify scopes of regex/inverted/exception forms it
/// cannot otherwise parse. Keep the actual modifier bytes separately: parameter names and regex escapes
/// are case-sensitive, so lowercasing the whole line would cancel unrelated rules (`TAG` vs `tag`, or
/// `\D` vs `\d`). Do not add the implicit `$document` here: identity precedes our type-scope correction.
///
/// Public for differential checks. As with the engine's own IDs, this is a 64-bit key; collisions remain
/// theoretically possible. No rule text is discarded from the serialised artifact.
pub fn badfilter_key(line: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let Some((exception, pattern, options)) = split_rule(line) else {
        line.trim().hash(&mut hasher);
        return hasher.finish();
    };
    let modifier = options.iter().copied().find(|option| {
        *option == "removeparam" || option.starts_with("removeparam=")
    });
    let mut scope_options: Vec<&str> = options
        .iter()
        .copied()
        .filter(|option| *option != "badfilter" && Some(*option) != modifier)
        .collect();
    scope_options.push("removeparam=zshield_identity");
    let scope = rebuild(false, pattern, &scope_options);
    let (filters, _) = adblock::lists::parse_filters(
        [scope.as_str()], false, adblock::lists::ParseOptions::default(),
    );
    if let Some(filter) = filters.first() {
        filter.get_id().hash(&mut hasher);
    } else {
        // For a scope outside the engine's modifier grammar, only identical spellings (ignoring option
        // order) can disable each other; never erase case-sensitive bytes to guess equivalence.
        scope_options.sort_unstable();
        (pattern, scope_options).hash(&mut hasher);
    }
    (exception, modifier).hash(&mut hasher);
    hasher.finish()
}

/// Turn one `$removeparam` value into a matcher, or `None` when the form is one neither side evaluates.
fn compile_param_matcher(value: &str) -> Option<ParamMatch> {
    // `$removeparam` with no value: the whole query.
    let value = value.trim();
    if value.is_empty() {
        return Some(ParamMatch::All);
    }
    // `~` inverts the match: `$removeparam=~name` keeps *only* `name`, `$removeparam=~/re/` keeps every
    // parameter the regex matches. AdGuard's note is that a `~` anywhere but the first character is an
    // ordinary character, so only the prefix counts.
    let (inverted, value) = match value.strip_prefix('~') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    // `/regex/`, with uBO's optional flags.
    if let Some(rest) = value.strip_prefix('/') {
        let split = rest.rfind('/')?;
        let (body, flags) = (&rest[..split], &rest[split + 1..]);
        // The compiled-size limits are the complexity bound for a subscription-supplied pattern: a regex
        // that would need more than 64 KiB of program state is refused at compile time instead of being
        // allowed to consume the tunnel's CPU at match time.
        let mut builder = regex::RegexBuilder::new(body);
        builder.size_limit(64 * 1024).dfa_size_limit(64 * 1024);
        if flags.contains('i') {
            builder.case_insensitive(true);
        }
        if flags.contains('s') {
            builder.dot_matches_new_line(true);
        }
        return builder.build().ok().map(|regex| {
            let regex = Arc::new(regex);
            if inverted {
                ParamMatch::InvertedRegex(regex)
            } else {
                ParamMatch::Regex(regex)
            }
        });
    }
    // `|` prefix (uBO's legacy anchored form) and multiple names are not supported: the former is a
    // regex, the latter is too inefficient to be worth it, and both are absent from the catalog.
    if value.starts_with('|') || value.contains('|') {
        return None;
    }
    if value.is_empty() {
        // `~` alone names nothing to keep; refusing beats pruning the entire query.
        return None;
    }
    Some(if inverted {
        ParamMatch::InvertedName(value.to_string())
    } else {
        ParamMatch::Name(value.to_string())
    })
}

/// Percent-decode a query value, as uBO does before running a `$removeparam` regex against it.
///
/// Invalid escapes are left as written rather than treated as an error: the regex is the list author's,
/// and a value the browser sent anyway is what it should see.
fn percent_decode(value: &str) -> String {
    if !value.contains('%') && !value.contains('+') {
        return value.to_string();
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = &value[index + 1..index + 3];
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------------------------
// The whole set
// ---------------------------------------------------------------------------------------------

/// Every modifier this core evaluates itself, in force for one tunnel.
#[derive(Default, Debug)]
pub struct ExtraModifiers {
    pub popup: PopupRules,
    pub denyallow: DenyAllowRules,
    pub removeparam: RemoveParamRules,
    /// `#@#`/`*#@#` rules, kept here for the same reason the three above are: the engine cannot
    /// express them, so they travel with the artifact set that the core evaluates itself.
    ///
    /// Behind an `Arc` because it is copied into every document's cosmetic plan: loading a rule set is
    /// a one-off, but the plan is built once per page, and a `Vec` clone per page would put the whole
    /// global-unhide list in the per-document allocation path (`http::decision::cosmetic_plan_with`).
    pub global_unhide: Arc<crate::cosmetic::unhide::GlobalUnhides>,
    /// `$domain=example.*` rules. The engine parses the option and then can never match it
    /// ([`crate::https::entity_domains`]).
    pub entity_domain: crate::https::entity_domains::EntityDomainRules,
}

impl ExtraModifiers {
    /// Parse one list body into every rule set.
    pub fn add_list(&mut self, text: &str) {
        self.popup.add_list(text);
        self.denyallow.add_list(text);
        self.removeparam.add_list(text);
        // Copy-on-write for the same reason the plan holds an `Arc`: a set that is being extended is
        // not yet shared, so this is a move in the common case and a clone only if a plan already
        // took a snapshot.
        Arc::make_mut(&mut self.global_unhide).add_list(text);
        self.entity_domain.add_list(text);
    }

    /// Compile every rule set. Called once after all lists are loaded.
    pub fn build(&mut self) {
        self.popup.build();
        self.denyallow.build();
        self.removeparam.build();
        self.entity_domain.build();
    }

    /// Every rule line this file carries, in a deterministic order, for `extras.txt`.
    ///
    /// The *original* text, not the stripped form: the file is an input to [`collect`] at the next
    /// start, and re-deriving the stripped form there is what lets an upgraded core use rules the
    /// previous build could not. The rendering is deterministic (each set keeps its own insertion
    /// order) so a rebuild of the same lists produces the same bytes and the artifact fingerprint
    /// does not churn.
    fn lines(&self) -> impl Iterator<Item = &String> {
        self.popup
            .lines()
            .iter()
            .chain(self.denyallow.rules().iter().map(|rule| &rule.text))
            .chain(self.removeparam.all_texts())
            .chain(self.global_unhide.lines())
            .chain(self.entity_domain.rules().iter().map(|rule| &rule.text))
    }

    pub fn serialize_lines(&self) -> String {
        let mut out = String::with_capacity(self.lines().map(|line| line.len() + 1).sum());
        for line in self.lines() {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Total rules in force, for `statsJson`.
    pub fn len(&self) -> usize {
        self.popup.len()
            + self.denyallow.len()
            + self.removeparam.len()
            + self.global_unhide.len()
            + self.entity_domain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.popup.is_empty()
            && self.denyallow.is_empty()
            && self.removeparam.is_empty()
            && self.global_unhide.is_empty()
            && self.entity_domain.is_empty()
    }
}

/// Whether this core evaluates `line` itself, i.e. the engine's refusal is not the last word.
///
/// One line per family, each asked through the same collector that will run at request time: a
/// `$popup` line this returns `true` for is a line `PopupRules::blocks` can fire on.
///
/// Used by the DNS-layer line classifier for the "不支持" count, so a rule that filters cannot also be
/// reported as broken.
pub fn evaluates(line: &str) -> bool {
    if !line.contains("popup")
        && !line.contains("denyallow")
        && !line.contains("removeparam")
        && !line.contains("#@#")
        && !line.contains(".*")
    {
        return false;
    }
    // Parsed *without* `build()`: the question is "would this be collected", which is answered before
    // any engine is compiled. `collect` would build one per call, and this runs for every line of
    // every list that mentions one of the three names.
    let mut modifiers = ExtraModifiers::default();
    modifiers.add_list(line);
    !modifiers.is_empty()
}

/// Collect every rule from a set of list bodies and compile them.
pub fn collect<'a>(lists: impl IntoIterator<Item = &'a str>) -> ExtraModifiers {
    let mut modifiers = ExtraModifiers::default();
    for text in lists {
        modifiers.add_list(text);
    }
    modifiers.build();
    modifiers
}

#[cfg(test)]
mod tests;
