//! `$domain=` entries written as an entity — `example.*` — which the pinned engine never matches.
//!
//! `docs/EFFECTIVENESS.md` §10.5 item 2 records the testcases.agrd.dev element-hiding case 6 as
//! "network rule class, root cause not investigated". The root cause is in the engine:
//!
//! adblock 0.13.5 stores a `$domain=` list as `fast_hash` of each entry and matches it against
//! `Request::source_hostname_hashes`, which is the source hostname plus **every suffix after a dot**
//! (`testcases.agrd.dev` → `testcases.agrd.dev`, `agrd.dev`, `dev`). An entity entry `testcases.agrd.*`
//! hashes to `fast_hash("testcases.agrd")`, which is not in that list — so the rule parses cleanly,
//! reports no error, and can never match. Measured on 0.13.5 with
//! `core/examples/probe_domain_wildcard.rs`: the same rule with `domain=testcases.agrd.dev` blocks and
//! with `domain=testcases.agrd.*` does not, while the *cosmetic* channel's entity support
//! (`testcases.agrd.*##…`) works, because that path hashes entities separately.
//!
//! # Why this cannot be fixed by adding the entity hash to the request
//!
//! The obvious shortcut — push `fast_hash(hostname_without_public_suffix)` into
//! `source_hostname_hashes` — also makes a plain `domain=testcases.agrd` rule match the host
//! `testcases.agrd.dev`, because the two entries then share one hash. The engine matches domain
//! entries as *suffixes*; an entity is not a suffix, and conflating them turns a narrow rule into a
//! broad one. So entity entries are evaluated here instead, exactly as `$popup`/`$denyallow` are.
//!
//! # How a rule is evaluated
//!
//! Same shape as [`crate::https::extras::denyallow`]: the entity entries are removed from the
//! `$domain=` option, the rest is re-parsed and compiled by the engine (so pattern syntax, content
//! types, `$third-party` and the remaining plain domains keep the meaning the list author gave them),
//! and the entity condition is applied on top of the engine's answer by this module.
//!
//! A rule whose positive `$domain=` consisted *only* of entity entries loses that option entirely in
//! the stripped form, which would make it match every site. Such a rule is compiled **without** the
//! option and gated purely by the entity check, because the entity check is the whole of its scope.
//!
//! # Mixed `$domain=` lists
//!
//! A list usually writes the plain and the entity form together —
//! `||x.example^$script,domain=a.com|example.*`. The engine keeps the plain half (`domain=a.com`) and
//! matches only sources under `a.com`, so the engine's answer alone covers *one* of the two entries.
//! The entity half is therefore matched as a **second form**: the same rule with the whole `$domain=`
//! option removed (so the engine can no longer narrow it) and the source's entity required by string
//! comparison here. A rule matches when *either* form matches; `~entity` always wins over both.
//!
//! That matters for real lists: of the 143 entity rules in the five default lists, 73 are mixed
//! (`docs/EFFECTIVENESS.md` §12), so covering only the entity-only spelling leaves most of them dead.
//!
//! # Cost per request
//!
//! Every rule is first screened by string comparison — is the request's source inside the rule's
//! entity, could one of its plain entries match the source hostname — and only a rule that survives
//! that screen costs an engine query. Identical stripped forms are queried once per request.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::http::head::HttpRequest;
use crate::http::resource::RequestKind;

/// One `$domain=` entry that names an entity.
///
/// `testcases.agrd.*` → `testcases.agrd`. The suffix is matched against the source hostname's
/// hostname-minus-public-suffix, which is what "entity" means to AdGuard and uBO: `example.*` covers
/// `example.com`, `example.co.uk` and `sub.example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    /// The entity as written, without the trailing `.*`.
    pub name: String,
    /// `~` in front: this entity is *excluded* from the rule's scope.
    pub negated: bool,
}

/// One rule carrying entity entries in its `$domain=` option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityRule {
    /// The rule as the list wrote it.
    pub text: String,
    /// The rule with its entity entries removed from `$domain=`, which is what the engine matches.
    ///
    /// For a mixed rule this still carries the plain entries, so the engine matches it for sources
    /// under those only. That answer is the rule's *plain* form; the entity form is [`Self::entity_form`].
    pub stripped: String,
    /// `@@` line: matching this entity *allows* rather than blocks.
    pub exception: bool,
    /// The rule with `@@` dropped, which is what an exception rule is matched against.
    ///
    /// The engine answers `should_block()` for an `@@` line with "no" whether or not it matched, so
    /// the exception's own match has to be asked for separately — as the same pattern without `@@`.
    pub probe: String,
    /// Entity entries that name the rule's scope.
    pub included: Vec<Entity>,
    /// `~entity` entries that take a host back out of scope.
    pub excluded: Vec<Entity>,
    /// Plain `$domain=` entries survived into `stripped`, so the engine's own answer already carries
    /// part of the scope and the entity check is an addition to it rather than its replacement.
    pub has_plain: bool,
    /// The same rule with the **whole** `$domain=` option removed and `@@` dropped.
    ///
    /// This is the entity half of a mixed list: the engine no longer narrows it to the plain entries,
    /// so the entity check here is the only scope it has. `None` when no entity is included (a
    /// `~entity`-only rule adds nothing to the plain form) or when the form is identical to
    /// [`Self::probe`] (an entity-only rule, whose whole scope is the entity check already).
    pub entity_form: Option<EntityForm>,
}

/// The engine form used for the entity half of a rule whose `$domain=` also names plain domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityForm {
    /// Key into [`EntityDomainRules::engines`].
    pub probe: String,
    /// The rule's plain positive `$domain=` entries, lowercased and without `~`.
    pub plain: Vec<String>,
    /// The rule's plain `~` entries. The engine form carries no `$domain=` at all, so unlike the plain
    /// form these are not applied by the engine and have to be applied here.
    pub negated: Vec<String>,
}

impl EntityForm {
    /// Whether `host` is one of the rule's plain `$domain=` entries — the entry itself or a subdomain
    /// of it, which is how the engine compares them.
    fn matches(&self, host: &str) -> bool {
        self.plain.iter().any(|entry| host_matches(host, entry))
    }

    /// Whether a `~plain` entry of the rule takes `host` back out of scope.
    fn excludes(&self, host: &str) -> bool {
        self.negated.iter().any(|entry| host_matches(host, entry))
    }
}

/// Whether `host` is `entry` or a subdomain of it, the comparison `$domain=` makes.
fn host_matches(host: &str, entry: &str) -> bool {
    host == entry
        || (host.len() > entry.len()
            && host.ends_with(entry)
            && host.as_bytes()[host.len() - entry.len() - 1] == b'.')
}

impl EntityRule {
    /// Whether the request could match this rule at all, decided without an engine query.
    ///
    /// This front filter is what keeps the per-request cost from growing with the rule count: over the
    /// five default lists there are 146 entity rules, and a request must skip the ones whose scope it
    /// is obviously outside of. A rule is a candidate when the source's entity is one of its entity
    /// inclusions, or — for a rule that also names plain domains — when the source host is under one
    /// of those. A `~entity` entry removes the request from every form of the rule, which is what `~`
    /// means; `~plain` is left to the engine on the plain form, and applied by
    /// [`Self::entity_form_admits`] on the entity form.
    ///
    /// The screen asks the same question the engine's `$domain=` asks, on the same source, so it only
    /// ever excludes rules that could not have matched.
    fn could_match(&self, scope: &RequestScope) -> bool {
        if self
            .excluded
            .iter()
            .any(|entry| entity_matches(scope.entity.as_deref(), &entry.name))
        {
            return false;
        }
        // A source under one of the rule's plain `$domain=` entries: the engine form for such a rule
        // carries them, so the engine decides it, and the entity form's own scope admits it too.
        if self
            .entity_form
            .as_ref()
            .is_some_and(|form| form.matches(&scope.source_host))
        {
            return true;
        }
        self.included.is_empty()
            || self
                .included
                .iter()
                .any(|entry| entity_matches(scope.entity.as_deref(), &entry.name))
    }

    /// Whether the *entity* form of a mixed rule is in scope for `scope`.
    ///
    /// That form carries no `$domain=` at all, so nothing but this check scopes it: the entity
    /// inclusions, the plain positives (which `$domain=` OR-s with them) and both kinds of negation.
    fn entity_form_admits(&self, scope: &RequestScope) -> bool {
        let Some(form) = self.entity_form.as_ref() else {
            return false;
        };
        if form.excludes(&scope.source_host) {
            return false;
        }
        form.matches(&scope.source_host)
            || self
                .included
                .iter()
                .any(|entry| entity_matches(scope.entity.as_deref(), &entry.name))
    }
}

/// Every entity-`$domain` rule, with one engine per distinct stripped rule text.
#[derive(Default)]
pub struct EntityDomainRules {
    rules: Vec<EntityRule>,
    rejected: Vec<(String, String)>,
    /// One entry per distinct stripped rule text.
    engines: BTreeMap<String, Option<Arc<adblock::Engine>>>,
    /// The engine forms a request's source can actually be in scope for, keyed by the form.
    ///
    /// [`build`](Self::build) fills the two reverse indexes below from this, so a request looks up
    /// only the rules it could match instead of walking every stored rule: the five default lists carry
    /// 143 entity rules in 210 engine forms, and a request is in scope for a handful of them.
    by_form: HashMap<String, Vec<Candidate>>,
    /// Rules reachable from an entity inclusion: `example` → the candidates allowed on any
    /// `*.example.*` source.
    ///
    /// Keyed by the entity, and looked up for **every suffix of the source's entity** (`a.b.example`
    /// tries `a.b.example`, `b.example`, `example`), which is what makes `example.*` cover
    /// `sub.example.com` without a scan.
    by_entity: HashMap<String, Vec<Candidate>>,
    /// Rules with no entity inclusion at all — a `domain=~entity` rule, whose only scope is its plain
    /// entries (or nothing, when the `$domain=` was purely negative). They cannot be indexed by entity
    /// and are always considered; there are three of them in the default lists.
    unscoped: Vec<Candidate>,
    /// Plain `$domain=` entries that make a rule's *plain* form in scope, keyed by the entry.
    ///
    /// Looked up for every suffix of the source hostname (`a.b.example.com` → … → `com`), the way the
    /// engine compares a `$domain=` entry.
    by_plain: HashMap<String, Vec<Candidate>>,
}

/// One (rule, engine form) pair: the unit an engine query answers for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Candidate {
    /// Index into [`EntityDomainRules::rules`].
    rule: usize,
    /// The query is the rule's *entity* form, which carries no `$domain=` and therefore needs the
    /// scope applied here rather than by the engine.
    entity_form: bool,
}

impl std::fmt::Debug for EntityDomainRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityDomainRules")
            .field("rules", &self.rules.len())
            .field("rejected", &self.rejected.len())
            .finish()
    }
}

impl EntityDomainRules {
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
            let Some(rule) = parse_rule(trimmed) else {
                continue;
            };
            for (form, _) in forms_of(&rule) {
                self.engines.entry(form).or_insert(None);
            }
            self.rules.push(rule);
        }
    }

    /// Compile every stripped rule. Called once after all lists are loaded.
    ///
    /// One engine per distinct rule text: an entity-`$domain` rule is rare (a handful per catalog) and
    /// each is a single-filter engine, so the total cost is a few microseconds of compile and a few
    /// hundred bytes resident — the same trade [`crate::https::extras`] makes for `$denyallow`.
    ///
    /// The rule index is rebuilt here as well, from the rules alone, so a set that was loaded from an
    /// artifact and one that was parsed from list text behave identically.
    pub fn build(&mut self) {
        let mut compiled: BTreeMap<String, Option<Arc<adblock::Engine>>> = BTreeMap::new();
        for stripped in self.engines.keys() {
            let mut set = adblock::lists::FilterSet::new(false);
            set.add_filter_list(stripped.clone(), adblock::lists::ParseOptions::default());
            compiled.insert(
                stripped.clone(),
                Some(Arc::new(adblock::Engine::new_with_filter_set(set))),
            );
        }
        self.engines = compiled;
        self.reindex();
    }

    /// Rebuild the reverse indexes from `rules`.
    ///
    /// Every candidate is registered under each entity / plain entry that can put it in scope, so a
    /// request resolves to its candidate set with a handful of hash lookups (one per suffix of its
    /// entity and of its source host) instead of a walk over all 210 forms.
    fn reindex(&mut self) {
        self.by_form.clear();
        self.by_entity.clear();
        self.unscoped.clear();
        self.by_plain.clear();
        for (index, rule) in self.rules.iter().enumerate() {
            for (form, entity_form) in forms_of(rule) {
                let candidate = Candidate {
                    rule: index,
                    entity_form,
                };
                self.by_form.entry(form).or_default().push(candidate);

                // Plain `$domain=` entries put the *plain* form in scope (the engine's own narrowing);
                // on the entity form they are applied here, and the same lookup covers both.
                if let Some(entity) = rule.entity_form.as_ref() {
                    for entry in entity.plain.iter().chain(entity.negated.iter()) {
                        self.by_plain
                            .entry(entry.clone())
                            .or_default()
                            .push(candidate);
                    }
                }
                match rule.included.is_empty() {
                    // `domain=~a|~b`: nothing names an entity, so no entity lookup can reach it.
                    true => self.unscoped.push(candidate),
                    false => {
                        for entity in &rule.included {
                            self.by_entity
                                .entry(entity.name.clone())
                                .or_default()
                                .push(candidate);
                        }
                    }
                }
            }
        }
        for list in self.by_entity.values_mut() {
            list.sort_unstable_by_key(|candidate| (candidate.rule, candidate.entity_form));
            list.dedup();
        }
        for list in self.by_plain.values_mut() {
            list.sort_unstable_by_key(|candidate| (candidate.rule, candidate.entity_form));
            list.dedup();
        }
    }

    /// The candidates a request's source can put in scope, each listed once.
    ///
    /// Built from the reverse indexes, then filtered by [`EntityRule::could_match`], which applies the
    /// `~entity` / `~plain` exclusions and the "is this form in scope at all" question.
    fn candidates(&self, scope: &RequestScope) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = Vec::new();
        if let Some(entity) = scope.entity.as_deref() {
            for suffix in host_suffixes(entity) {
                if let Some(list) = self.by_entity.get(suffix) {
                    found.extend_from_slice(list);
                }
            }
        }
        for suffix in host_suffixes(&scope.source_host) {
            if let Some(list) = self.by_plain.get(suffix) {
                found.extend_from_slice(list);
            }
        }
        found.extend_from_slice(&self.unscoped);
        found.retain(|candidate| self.rules[candidate.rule].could_match(scope));
        found.sort_unstable_by_key(|candidate| (candidate.rule, candidate.entity_form));
        found.dedup();
        found
    }

    /// What this rule family says about `request`, both halves from one pass.
    ///
    /// [`verdict`](Self::verdict) and [`exempts`](Self::exempts) answer different questions but are
    /// asked together for every request, and each one walks the candidates and queries the engines — so
    /// the caller that needs both (`HttpFilter::decide_full`) asks once.
    pub fn evaluate(&self, request: &HttpRequest, kind: RequestKind) -> EntityVerdict {
        if self.rules.is_empty() {
            return EntityVerdict::default();
        }
        let hits = self.engine_hits(&RequestScope::of(request), kind);
        EntityVerdict {
            // A block that an `@@` rule of this family cancels is not a block: `$denyallow`'s
            // equivalent branch reads the same way (`Some(false)` means forwarded).
            blocks: !hits.blocked.is_empty() && hits.exempted.is_empty(),
            exempts: !hits.exempted.is_empty(),
        }
    }

    /// Whether an `@@` rule of this family exempts `request`.
    ///
    /// Separate from [`verdict`](Self::verdict) because the two answer different questions and the
    /// blocking half usually lives in the **main** engine, not here: a list writes
    /// `||ads.example^$script` (which the engine compiles) and `@@||ads.example^$script,domain=….*`
    /// (which it cannot). So an entity exception has to be able to cancel a block this module never
    /// saw, and folding it into `verdict` would make that impossible — `verdict` would return `None`
    /// (nothing of this family blocks) and the exception would be dropped on the floor.
    ///
    /// An exception is not narrowed by the blocking rule's own `$important`: `@@` cancels it here
    /// because the list author wrote an exception for exactly this request, and the caller
    /// ([`crate::http::decision`]) decides whether that is allowed to win (it is not, for an
    /// `$important` block — see `HttpFilter::decide_full`).
    pub fn exempts(&self, request: &HttpRequest, kind: RequestKind) -> bool {
        self.evaluate(request, kind).exempts
    }

    /// Every rule that decides something about this request, as two index lists.
    ///
    /// A rule can match through its plain form (the engine already narrowed it to that rule's plain
    /// entries) or through its entity form (the form carries no `$domain=`, so the entity comparison is
    /// the scope). A `~entity` exclusion cancels both, which is what `~` means.
    ///
    /// The work is proportional to the rules the source can be in scope for, not to the rule count:
    /// [`candidates`](Self::candidates) resolves that set through the reverse indexes, and identical
    /// forms are queried once per request.
    fn engine_hits(&self, scope: &RequestScope, kind: RequestKind) -> Hits {
        let mut hits = Hits::default();
        if self.rules.is_empty() {
            return hits;
        }
        let candidates = self.candidates(scope);
        if candidates.is_empty() {
            return hits;
        }
        let adblock_request = crate::http::decision::to_adblock_request(scope.request, kind);
        // One query per distinct form, memoised: several rules share a stripped form, and a request
        // matching two of them must not pay for the engine twice.
        let mut queried: BTreeMap<&str, bool> = BTreeMap::new();
        for candidate in candidates {
            let rule = &self.rules[candidate.rule];
            let form = match (&rule.entity_form, candidate.entity_form) {
                (Some(entity_form), true) => entity_form.probe.as_str(),
                _ => rule.probe.as_str(),
            };
            let Some(engine) = self.engines.get(form).and_then(Option::as_ref) else {
                continue;
            };
            let matched = *queried
                .entry(form)
                .or_insert_with(|| engine.check_network_request(&adblock_request).should_block());
            if !matched {
                continue;
            }
            // The plain form's scope is enforced by the engine itself — it carries the rule's
            // `$domain=` list — so nothing is left to apply here beyond the `~entity` screen
            // [`EntityRule::could_match`] already ran. The entity form carries no `$domain=` at all, so
            // its scope is entirely [`EntityRule::entity_form_admits`].
            if candidate.entity_form && !rule.entity_form_admits(scope) {
                continue;
            }
            if rule.exception {
                hits.exempted.push(candidate.rule);
            } else {
                hits.blocked.push(candidate.rule);
            }
        }
        hits
    }

    /// What this rule family says about `request`.
    ///
    /// `None` when no rule of this family decides anything, `Some(true)` when the request must be
    /// blocked, `Some(false)` when an `@@` rule puts it back in scope.
    pub fn verdict(&self, request: &HttpRequest, kind: RequestKind) -> Option<bool> {
        if self.rules.is_empty() {
            return None;
        }
        let verdict = self.evaluate(request, kind);
        match (verdict.blocks, verdict.exempts) {
            // An exempting `@@` rule answers even when nothing of this family blocks: the block it
            // cancels usually lives in the main engine, which is why `verdict` reports it at all.
            (_, true) => Some(false),
            (false, false) => None,
            (true, false) => Some(true),
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[EntityRule] {
        &self.rules
    }

    pub fn rejected(&self) -> &[(String, String)] {
        &self.rejected
    }
}

/// What the entity-`$domain` family says about one request, decided in a single pass.
///
/// Both halves are reported separately because the caller applies them to *different* starting
/// decisions: `exempts` cancels a block the main engine made, `blocks` adds one it could not.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntityVerdict {
    /// A blocking rule of this family is in scope and no `@@` rule of it cancels that.
    pub blocks: bool,
    /// An `@@` rule of this family is in scope, so a block from elsewhere must not stand.
    pub exempts: bool,
}

/// The rules of this family a request matched, split by what they say.
#[derive(Debug, Default)]
struct Hits {
    /// Rules that block it.
    blocked: Vec<usize>,
    /// `@@` rules that put it back in scope.
    exempted: Vec<usize>,
}

/// The parts of a request every entity rule compares against, computed once per request.
struct RequestScope<'a> {
    request: &'a HttpRequest,
    /// The **source** hostname from the `Referer`, lowercased. `$domain=` names the page a request came
    /// from, not the host it is sent to, so this — not [`HttpRequest::hostname`] — is what a plain
    /// entry has to match.
    source_host: String,
    /// The source's entity ([`source_entity`]).
    entity: Option<String>,
}

impl<'a> RequestScope<'a> {
    fn of(request: &'a HttpRequest) -> Self {
        Self {
            request,
            source_host: source_host_of(request).unwrap_or_default(),
            entity: source_entity(request),
        }
    }
}

/// The source hostname from the `Referer`, lowercased.
///
/// `$domain=` names the page a request came from, not the host it is sent to, so this — never
/// [`HttpRequest::hostname`] — is what a plain entry has to match.
fn source_host_of(request: &HttpRequest) -> Option<String> {
    let referer = request.referer.as_deref()?;
    let parsed = adblock::url_parser::parse_url(referer)?;
    Some(parsed.hostname().to_ascii_lowercase())
}

/// `host` and every suffix of it after a dot: `a.b.example` → `a.b.example`, `b.example`, `example`.
///
/// The reverse indexes are keyed by the entity / plain entry alone, and `example` has to be found from
/// any host under it, so the lookup enumerates the suffixes rather than trying every stored entry.
/// Bounded by the number of labels, which is a handful.
fn host_suffixes(host: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(host), |current| {
        current.find('.').map(|dot| &current[dot + 1..])
    })
}

/// Whether `entity` is `name` or a subdomain-part of it.
///
/// `example` matches `example` and `sub.example`, never `notexample`.
fn entity_matches(entity: Option<&str>, name: &str) -> bool {
    let Some(entity) = entity else {
        return false;
    };
    entity == name
        || (entity.len() > name.len()
            && entity.ends_with(name)
            && entity.as_bytes()[entity.len() - name.len() - 1] == b'.')
}

/// The source hostname without its public suffix, which is the "entity" a `$domain=example.*` names.
///
/// Read from the `Referer`, the same source the engine uses for `$domain=`. `None` when there is no
/// usable referer, which makes every entity rule not apply — the same conservative default
/// [`crate::http::decision::source_of`] takes for first-/third-party.
///
/// The suffix has to be the **public** suffix, not the registrable domain: for
/// `testcases.agrd.dev` the public suffix is `dev`, so the entity is `testcases.agrd` — which is
/// exactly what `testcases.agrd.*` names, and what the engine's own cosmetic entity hashing produces
/// (`filters::cosmetic::get_entity_hashes_from_labels`). Using eTLD+1 instead would yield `agrd` and
/// make the rule's own name not match its own host.
///
/// `UrlParser::domain()` is the registrable domain (eTLD+1), so the public suffix is that value minus
/// its first label.
fn source_entity(request: &HttpRequest) -> Option<String> {
    let referer = request.referer.as_deref()?;
    let parsed = adblock::url_parser::parse_url(referer)?;
    let hostname = parsed.hostname();
    let domain = parsed.domain();
    // `domain` is eTLD+1, so `example.dev` → `dev`; the suffix is never the whole domain.
    let (_, public_suffix) = domain.split_once('.')?;
    if public_suffix.is_empty() || hostname.len() <= public_suffix.len() {
        return None;
    }
    let without_suffix = hostname.strip_suffix(public_suffix)?.strip_suffix('.')?;
    if without_suffix.is_empty() {
        None
    } else {
        Some(without_suffix.to_string())
    }
}

/// The engine forms one rule can be matched through, for the per-form engine table.
///
/// The *plain* form is the rule with only its entity entries removed, asked for **without** `@@`: the
/// engine answers `should_block()` with "no" for an exception whether or not it matched, so an
/// exception's own match has to be asked for as the same pattern without the marker. The *entity*
/// form, for a mixed rule, is the rule with no `$domain=` at all.
fn forms_of(rule: &EntityRule) -> Vec<(String, bool)> {
    match rule.entity_form.as_ref() {
        Some(form) if form.probe != rule.probe => {
            vec![(rule.probe.clone(), false), (form.probe.clone(), true)]
        }
        _ => vec![(rule.probe.clone(), false)],
    }
}

/// Parse one line into an [`EntityRule`], or `None` when it carries no entity `$domain=` entry.
fn parse_rule(line: &str) -> Option<EntityRule> {
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
    let domain_option = options
        .iter()
        .find(|option| option.starts_with("domain="))?;
    let entries: Vec<&str> = domain_option["domain=".len()..].split('|').collect();

    let mut included = Vec::new();
    let mut excluded = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for entry in &entries {
        let (negated, name) = match entry.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, *entry),
        };
        match name.strip_suffix(".*") {
            // A bare `*` is "every site", not an entity; leave it to the engine.
            Some(entity) if !entity.is_empty() && entity != "*" => {
                let parsed = Entity {
                    name: entity.to_ascii_lowercase(),
                    negated,
                };
                if negated {
                    excluded.push(parsed);
                } else {
                    included.push(parsed);
                }
            }
            _ => kept.push(entry),
        }
    }
    if included.is_empty() && excluded.is_empty() {
        return None;
    }

    // Rebuild the line: entity entries out of `domain=`, everything else untouched. When nothing is
    // left in the option it is dropped entirely, and the entity check above becomes the rule's whole
    // scope — which is why `verdict` gates the engine's answer on it.
    let mut rebuilt: Vec<String> = Vec::new();
    for option in &options {
        if *option == *domain_option {
            if !kept.is_empty() {
                rebuilt.push(format!("domain={}", kept.join("|")));
            }
        } else {
            rebuilt.push((*option).to_string());
        }
    }
    let prefix = if exception { "@@" } else { "" };
    let stripped = if rebuilt.is_empty() {
        format!("{prefix}{pattern}")
    } else {
        format!("{prefix}{pattern}${}", rebuilt.join(","))
    };
    // An `@@` rule's own match has to be asked for without the `@@`: `should_block()` is `false` for
    // an exception whether or not it matched. The plain entries (if any) stay in, because the
    // exception's scope is the same `$domain=` list.
    let probe = stripped.strip_prefix("@@").unwrap_or(&stripped).to_string();

    // The entity half of a *mixed* list: the whole `$domain=` option removed, so the engine can no
    // longer narrow the rule to the plain entries and the entity comparison is the only scope it has.
    // An entity-only rule needs no such form: its `probe` already carries no `$domain=`, and its scope
    // is the entity check alone. A `~entity`-only rule adds nothing either — with no inclusion there is
    // no entity half, and the plain form is the whole rule.
    let entity_form = if included.is_empty() || !kept.iter().any(|entry| !entry.starts_with('~')) {
        None
    } else {
        let mut without_domain: Vec<&str> = Vec::new();
        for option in &options {
            if *option != *domain_option {
                without_domain.push(option);
            }
        }
        let form = if without_domain.is_empty() {
            pattern.to_string()
        } else {
            format!("{pattern}${}", without_domain.join(","))
        };
        if form == probe {
            None
        } else {
            let mut plain = Vec::new();
            let mut negated = Vec::new();
            for entry in &kept {
                let target = match entry.strip_prefix('~') {
                    Some(rest) => (rest, &mut negated),
                    None => (*entry, &mut plain),
                };
                let host = target
                    .0
                    .trim_start_matches('*')
                    .trim_start_matches('.')
                    .to_ascii_lowercase();
                if !host.is_empty() {
                    target.1.push(host);
                }
            }
            Some(EntityForm {
                probe: form,
                plain,
                negated,
            })
        }
    };

    Some(EntityRule {
        text: line.to_string(),
        stripped,
        probe,
        exception,
        included,
        excluded,
        has_plain: !kept.is_empty(),
        entity_form,
    })
}

#[cfg(test)]
mod tests;
