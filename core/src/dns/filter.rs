//! Domain-level filter engine for M0.
//!
//! Supported syntax (see `docs/DESIGN.md` §5 and the M0 task card):
//!
//! | Form | Meaning |
//! |---|---|
//! | `0.0.0.0 a.com` / `127.0.0.1 a.com` / bare `a.com` | hosts entry, blocks `a.com` and its subdomains |
//! | `\|\|a.com^` | block `a.com` and subdomains, on any scheme/path |
//! | `\|a.com^` | block exactly `a.com` |
//! | `@@\|\|a.com^` | exception for `a.com` and subdomains |
//! | `$important` | beats exceptions |
//! | `$badfilter` | disables the identical rule |
//! | `! comment`, empty line | ignored |
//!
//! Anything else (path rules, `$third-party`, `$dnsrewrite`, element hiding, ...) is counted as
//! unsupported and ignored; it is not an error. Path/URL level rules arrive with adblock-rust in
//! M1.
//!
//! Matching is suffix based: a rule for `a.com` matches `a.com` and `x.a.com` but never
//! `nota.com`. The implementation stores each blocked domain in a compressed trie over reversed
//! labels so lookup is O(labels) with no allocation and no false positives from plain string
//! suffix comparison.

use std::collections::{HashMap, HashSet};

/// Why a rule was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// A URL/path pattern or an unsupported modifier (M1 territory).
    UnsupportedSyntax,
    /// `$badfilter` without a matching rule.
    DanglingBadfilter,
    /// Malformed hosts entry or modifier list.
    Malformed,
    /// A rule that could not be re-emitted (internal consistency check).
    Internal,
    /// A rule whose domain matches a DNS-layer rule but which additionally carries modifiers that
    /// must not be applied at the DNS layer (`$third-party`, `$domain=`, `$denyallow`, ...). It is
    /// counted here so the DNS layer never blocks a whole domain on the strength of a rule that
    /// only applies to part of it (task card §4).
    ScopeWidening,
}

/// Number of [`Unsupported`] variants; used to size `unsupported_by_reason`.
pub const UNSUPPORTED_REASONS: usize = 5;

impl Unsupported {
    fn index(self) -> usize {
        self as usize
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Unsupported::UnsupportedSyntax => "unsupported_syntax",
            Unsupported::DanglingBadfilter => "dangling_badfilter",
            Unsupported::Malformed => "malformed",
            Unsupported::Internal => "internal",
            Unsupported::ScopeWidening => "network_only",
        }
    }
}

/// Outcome of `Filter::match_domain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No rule applies.
    Allow,
    /// A blocking rule applies.
    Block,
}

/// Comparison target for one parsed line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleKind {
    /// Matches the domain and any subdomain.
    Domain,
    /// Matches the domain exactly.
    Exact,
    /// Matches an exact IP literal (hosts entry such as `0.0.0.0 93.184.216.34`).
    Ip,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    kind: RuleKind,
    value: String,
    exception: bool,
    important: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RawRule {
    exception: bool,
    important: bool,
    badfilter: bool,
    kind: Option<RuleKind>,
    form: Option<RuleForm>,
    value: String,
}

/// The canonical string identity of a rule, used by `$badfilter`.
impl Rule {
    fn identity(&self) -> String {
        let prefix = if self.exception { "@@" } else { "" };
        let important = if self.important { "$important" } else { "" };
        let body = match self.kind {
            RuleKind::Domain => format!("||{}^", self.value),
            RuleKind::Exact => format!("|{}^", self.value),
            RuleKind::Ip => format!("|{}|", self.value),
        };
        format!("{prefix}{body}{important}")
    }
}

/// Rule statistics, surfaced through `statsJson` so unsupported rules stay visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuleStats {
    pub files_loaded: usize,
    pub lines: usize,
    pub block_rules: usize,
    pub exception_rules: usize,
    /// Lines **neither** layer can use (see [`FilterBuilder::add_text`]). This is what "不支持"
    /// means in the UI, in the compile statistics and in the hot-reload log — one definition, three
    /// places that print it (`docs/JNI.md` §"规则统计").
    pub unsupported: usize,
    /// Rules that are valid for the adblock engine but not for the DNS layer (path patterns,
    /// `$third-party`, element hiding, ...). Kept separate from [`unsupported`](Self::unsupported)
    /// on purpose: they are *not* broken, and counting them as broken would make every list look
    /// like tens of thousands of failures.
    pub network_only: usize,
    pub badfilter_applied: usize,
    pub unsupported_by_reason: [usize; UNSUPPORTED_REASONS],
}

/// Compiled filter set.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Blocking domains (suffix match) - key is the plain domain, value is the trie node handle
    /// implicit in `suffix_index`.
    block_suffix: DomainSet,
    /// Blocking exact hosts.
    block_exact: DomainSet,
    /// Blocking IP literals.
    block_ips: DomainSet,
    /// Exception domains, which win over plain blocks.
    allow_suffix: DomainSet,
    allow_exact: DomainSet,
    /// Domains whose block is `$important`: these survive an exception.
    important_suffix: DomainSet,
    important_exact: DomainSet,
    /// User allowlist (the `allowlist` field of the compile request). Checked before anything else,
    /// including `$important` blocks: a domain the user explicitly allows is never blocked by a
    /// subscription. See `docs/JNI.md`.
    priority_allow_suffix: DomainSet,
    stats: RuleStats,
}

/// Accumulates parsed rules from several sources so that `$badfilter` can act across file
/// boundaries (a `$badfilter` in list B must disable the matching rule in list A, exactly like
/// AdGuard and uBO).
///
/// `Filter::load_text` builds one of these per call; the compile path builds a single one for all
/// lists plus the user's custom rules, which is what makes cross-file `$badfilter` work.
#[derive(Debug, Default)]
pub struct FilterBuilder {
    rules: Vec<Rule>,
    /// Identity of every rule seen, so a `$badfilter` can tell "disables something" from "dangling".
    seen: HashMap<String, usize>,
    disabled: HashSet<String>,
    pending_badfilters: Vec<RawRule>,
    stats: RuleStats,
}

/// Per-source line counts, produced while the rules are parsed.
///
/// The compile path needs these for the per-list statistics the UI shows. They are counted here, in
/// the single pass that builds the rules, rather than in a separate classification pass: on device a
/// duplicate pass over 37 MB of list text cost 1.8 s of a 5.8 s compile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListCounts {
    /// Every line, comments included.
    pub lines: u64,
    /// Rules that became DNS-layer rules (hosts entries and unmodified domain patterns).
    pub dns_rules: u64,
    /// Valid rules handed to the adblock engine only.
    pub network_rules: u64,
    /// Element hiding / scriptlet rules (a subset of `network_rules`).
    pub cosmetic_rules: u64,
    /// Lines neither layer can use — the "不支持" the UI, the compile statistics and the hot-reload
    /// log all report. See [`FilterBuilder::add_text`] for the exact rule.
    pub unsupported: u64,
}

/// Whether the adblock engine can parse `line`.
///
/// The DNS layer is this crate's own parser ([`parse_line`]); the network/cosmetic layer is
/// adblock-rust, which is fed the whole list text in a parallel thread. A line the DNS layer refuses
/// may therefore still be perfectly usable by the engine, and vice versa — which is exactly why the
/// old per-layer tallies disagreed (compile statistics and the hot-reload log both printed
/// "unsupported" from a different definition). Asking the engine's own parser is what makes one
/// definition possible; it costs ~0.4 µs per line and runs only for lines the DNS layer refused.
fn engine_accepts(line: &str) -> bool {
    adblock::lists::parse_filter(line, false, adblock::lists::ParseOptions::default()).is_ok()
        // M5b: a line the engine *refuses* can still be one this core applies itself — the `$popup`,
        // `$denyallow` and regex `$removeparam` families are re-parsed with the offending option
        // removed and matched by `https::extras`. Without this the "不支持" the UI shows would count
        // 6,484 rules as broken that now filter, and the number exists precisely so a user can trust
        // it. Asked through the shipping collector, so the two cannot disagree.
        || crate::https::extras::evaluates(line)
}

impl FilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse the contents of one list (or the user's custom rules — same syntax), returning this
    /// source's line counts.
    ///
    /// # The "unsupported" definition (`docs/JNI.md` §"规则统计")
    ///
    /// A line is counted as `unsupported` when **neither layer can use it**: this crate's DNS parser
    /// rejects it *and* adblock-rust's parser rejects it. Everything else is a rule:
    ///
    /// | line | DNS layer | engine | counted as |
    /// |---|---|---|---|
    /// | `\|\|a.com^` | blocks the domain | also parses | `dns_rules` |
    /// | `\|\|a.com^$third-party` | not a DNS rule | parses | `network_rules` |
    /// | `\|\|a.com^$unknownmod` | not a DNS rule | **rejects** it | `unsupported` |
    /// | `a.com##.ad` | not a DNS rule | parses | `network_rules` (+ `cosmetic_rules`) |
    /// | `\|\|a.com^$` (empty modifier) | rejects it | **rejects** it | `unsupported` |
    ///
    /// Comments, blank lines and `[Adblock Plus 2.0]` headers are not rules at all and are counted
    /// in none of the four classes — they only show up in `lines`. Before MYS-2716 only the DNS
    /// layer's verdict counted, so a rule the engine happily used but the DNS layer could not
    /// (every path rule, every `$third-party` rule) inflated nothing — but a *modifier typo* the
    /// engine silently dropped was counted twice over, and the two numbers printed in the UI and in
    /// the hot-reload log came from two different tallies.
    pub fn add_text(&mut self, text: &str) -> ListCounts {
        let mut pending = Vec::new();
        let mut counts = ListCounts::default();
        for line in text.lines() {
            self.stats.lines += 1;
            counts.lines += 1;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
                continue;
            }
            // `[Adblock Plus 2.0]` is a header line, not a rule.
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                continue;
            }
            match parse_line(trimmed) {
                Ok(Some(raw)) if raw.badfilter => {
                    counts.dns_rules += 1;
                    pending.push(raw);
                }
                Ok(Some(raw)) => match raw.into_rule() {
                    Some(rule) => {
                        counts.dns_rules += 1;
                        *self.seen.entry(rule.identity()).or_insert(0) += 1;
                        self.rules.push(rule);
                    }
                    None => {
                        // A hosts-shaped line whose host could not be extracted: the engine may still
                        // read something out of it, so ask before calling it broken.
                        self.count_rejected(trimmed, &mut counts, Unsupported::Malformed);
                    }
                },
                Ok(None) => {
                    // "Not a DNS-layer rule" is *not* the same as "the engine can use it": a
                    // `$nonsense` modifier lands in this arm too (the DNS parser stops at the first
                    // modifier it does not know), and adblock-rust rejects the line outright. Only
                    // the engine's own verdict separates a usable engine rule from a broken one.
                    if engine_accepts(trimmed) {
                        counts.network_rules += 1;
                        if is_cosmetic_line(trimmed) {
                            counts.cosmetic_rules += 1;
                        }
                        self.count(Unsupported::ScopeWidening);
                    } else {
                        counts.unsupported += 1;
                        self.count(Unsupported::UnsupportedSyntax);
                    }
                }
                Err(reason) => {
                    self.count_rejected(trimmed, &mut counts, reason);
                }
            }
        }
        // Badfilters are resolved after every source has been parsed; keeping them queued also
        // means a badfilter may precede the rule it disables.
        self.pending_badfilters.extend(pending);
        self.stats.files_loaded += 1;
        counts
    }

    /// Count a line the DNS layer rejected: `unsupported` only when the engine rejects it too.
    ///
    /// The reason breakdown (`unsupported_by_reason`) always records the DNS layer's verdict — it is
    /// a diagnostic of *this* parser — while the user-facing `unsupported` follows the shared
    /// definition.
    fn count_rejected(&mut self, line: &str, counts: &mut ListCounts, reason: Unsupported) {
        if engine_accepts(line) {
            // The engine has a use for it: it is an engine rule, not a broken line.
            counts.network_rules += 1;
            if is_cosmetic_line(line) {
                counts.cosmetic_rules += 1;
            }
            self.count(Unsupported::ScopeWidening);
            return;
        }
        counts.unsupported += 1;
        self.count(reason);
    }

    /// Apply every collected `$badfilter` and return how many rules survived.
    ///
    /// Call this exactly once, after the last [`add_text`](Self::add_text).
    ///
    /// A dangling `$badfilter` is recorded in [`RuleStats::unsupported_by_reason`] but **not** in
    /// [`RuleStats::unsupported`]: the line itself is well-formed adblock syntax that the engine can
    /// use, so under the shared definition it is not "不支持" — it merely names a rule that does not
    /// exist. The reason counter is the DNS layer's own diagnostic and deliberately keeps its own
    /// total (`docs/JNI.md` §"规则统计").
    pub fn resolve_badfilters(&mut self) -> usize {
        for raw in std::mem::take(&mut self.pending_badfilters) {
            let target = RawRule {
                badfilter: false,
                ..raw
            };
            let Some(rule) = target.into_rule() else {
                // A `$badfilter` whose pattern does not survive its own re-parse: the engine still
                // accepts the line, so it is a DNS-layer limitation, not a broken rule.
                self.stats.unsupported_by_reason[Unsupported::Malformed.index()] += 1;
                continue;
            };
            let id = rule.identity();
            let hits = self.seen.get(&id).copied().unwrap_or(0);
            if hits > 0 {
                self.disabled.insert(id);
                self.stats.badfilter_applied += 1;
            } else {
                self.stats.unsupported_by_reason[Unsupported::DanglingBadfilter.index()] += 1;
            }
        }
        let kept = self
            .rules
            .iter()
            .filter(|rule| !self.disabled.contains(&rule.identity()))
            .count();
        kept
    }

    /// Fold the surviving rules of this builder into `filter` and return this batch's statistics.
    ///
    /// The returned value counts what this batch contributed (parse-time counters plus the rules
    /// that survived `$badfilter`), which is what a caller loading one file wants to report.
    pub fn apply_to(self, filter: &mut Filter) -> RuleStats {
        let FilterBuilder {
            rules,
            disabled,
            mut stats,
            ..
        } = self;
        for rule in rules {
            if disabled.contains(&rule.identity()) {
                continue;
            }
            filter.insert(rule, &mut stats);
        }
        // Every insert above landed in a `DomainSet`'s scratch list; the matchers binary-search the
        // frozen block, so the sets are closed here — once per compile, not once per query.
        filter.freeze();
        filter.stats.files_loaded += stats.files_loaded;
        filter.stats.lines += stats.lines;
        filter.stats.block_rules += stats.block_rules;
        filter.stats.exception_rules += stats.exception_rules;
        filter.stats.unsupported += stats.unsupported;
        filter.stats.network_only += stats.network_only;
        filter.stats.badfilter_applied += stats.badfilter_applied;
        for (idx, count) in stats.unsupported_by_reason.iter().enumerate() {
            filter.stats.unsupported_by_reason[idx] += count;
        }
        stats
    }

    /// Record one line the **DNS layer** rejected, with its reason.
    ///
    /// `ScopeWidening` is "a valid rule that is not a DNS-layer rule" (the engine's job), so it never
    /// touches `unsupported`. Everything else increments both the shared `unsupported` total and the
    /// per-reason breakdown; the callers that must *not* increment the shared total (a dangling
    /// `$badfilter`, which the engine happily uses) write the reason counter directly.
    fn count(&mut self, reason: Unsupported) {
        if reason == Unsupported::ScopeWidening {
            self.stats.network_only += 1;
            return;
        }
        self.stats.unsupported += 1;
        self.stats.unsupported_by_reason[reason.index()] += 1;
    }
}

impl Filter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge a user allowlist (plain domains, or full `@@||domain^` exceptions) into the filter.
    ///
    /// These entries are checked **before** every block rule, including `$important` ones: the user
    /// asking for a domain to be allowed must win over a subscription. Entries are normalised the
    /// same way as list rules, so `Ads.Example.com`, `ads.example.com` and `@@||ads.example.com^`
    /// are all the same entry.
    pub fn add_allowlist<'a, I>(&mut self, entries: I)
    where
        I: IntoIterator<Item = &'a str>,
    {
        for entry in entries {
            let domain = normalize_domain(strip_allowlist_decoration(entry));
            if domain.is_empty() {
                continue;
            }
            self.priority_allow_suffix.insert(&domain);
        }
        self.priority_allow_suffix.freeze();
    }

    /// Close every [`DomainSet`] so the matchers can binary-search it.
    ///
    /// Called by the two mutation entry points ([`FilterBuilder::apply_to`] and
    /// [`add_allowlist`](Self::add_allowlist)); no other path inserts domains.
    fn freeze(&mut self) {
        self.block_suffix.freeze();
        self.block_exact.freeze();
        self.block_ips.freeze();
        self.allow_suffix.freeze();
        self.allow_exact.freeze();
        self.important_suffix.freeze();
        self.important_exact.freeze();
        self.priority_allow_suffix.freeze();
    }

    /// Number of user allowlist entries currently held.
    pub fn allowlist_len(&self) -> usize {
        self.priority_allow_suffix.len()
    }

    /// Whether `domain` is covered by the user allowlist.
    pub fn is_allowlisted(&self, domain: &str) -> bool {
        let name = normalize_domain(domain);
        !name.is_empty() && self.priority_allow_suffix.matches(&name)
    }

    /// Serialize the compiled DNS rules into the `dns.bin` format (see [`crate::compiled`]).
    ///
    /// The payload is a newline-separated list of `kind<TAB>domain` records grouped by section.
    /// That is more compact than JSON for millions of domains and — more importantly — lets the
    /// decoder build the tries directly without an intermediate object graph.
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = String::with_capacity(1 << 16);
        // Header: the rule statistics describe the sources, so they cannot be recomputed from the
        // domains alone. Carrying them inside the artifact keeps `dns.bin` self-describing, which
        // is what lets a cold start report rule counts without re-reading a single list.
        out.push_str(&format!(
            "s\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            self.stats.files_loaded,
            self.stats.lines,
            self.stats.block_rules,
            self.stats.exception_rules,
            self.stats.unsupported,
            self.stats.network_only,
            self.stats.badfilter_applied
        ));
        if self.stats.unsupported_by_reason.iter().any(|count| *count > 0) {
            out.push('r');
            for count in self.stats.unsupported_by_reason {
                out.push('\t');
                out.push_str(&count.to_string());
            }
            out.push('\n');
        }
        // Every section is written in the order its `DomainSet` is already frozen in (ascending),
        // which is what lets the reader rebuild the block without sorting or allocating per domain.
        let sections = [
            ("b", &self.block_suffix),
            ("B", &self.block_exact),
            ("i", &self.block_ips),
            ("a", &self.allow_suffix),
            ("A", &self.allow_exact),
            ("m", &self.important_suffix),
            ("M", &self.important_exact),
            ("p", &self.priority_allow_suffix),
        ];
        for (tag, set) in sections {
            for domain in set.sorted() {
                out.push_str(tag);
                out.push('\t');
                out.push_str(domain);
                out.push('\n');
            }
        }
        out.into_bytes()
    }

    /// Rebuild a filter from [`encode_payload`](Self::encode_payload) output.
    ///
    /// The payload carries its own rule statistics, so a deserialized filter reports the same
    /// counts in `statsJson` as the one that produced the file.
    pub fn decode_payload(payload: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(payload)
            .map_err(|e| format!("dns.bin is not valid UTF-8: {e}"))?;
        let mut filter = Filter::default();
        let mut saw_header = false;
        let mut dns_sections = DnsSectionBuffers::default();
        for (index, line) in text.lines().enumerate() {
            let Some((tag, domain)) = line.split_once('\t') else {
                return Err(format!("dns.bin line {} is malformed", index + 1));
            };
            if domain.is_empty() {
                return Err(format!("dns.bin line {} has an empty domain", index + 1));
            }
            match tag {
                "s" => {
                    filter.stats = parse_stats_record(domain)?;
                    saw_header = true;
                }
                "r" => {
                    let counts = domain
                        .split('\t')
                        .map(|value| value.parse::<usize>())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| format!("dns.bin line {}: bad reason counts: {e}", index + 1))?;
                    if counts.len() != UNSUPPORTED_REASONS {
                        return Err(format!(
                            "dns.bin line {}: expected {UNSUPPORTED_REASONS} reason counts, got {}",
                            index + 1,
                            counts.len()
                        ));
                    }
                    filter.stats.unsupported_by_reason.copy_from_slice(&counts);
                }
                "b" | "B" | "i" | "a" | "A" | "m" | "M" | "p" => {
                    dns_sections.push(tag, domain)
                }
                other => {
                    return Err(format!(
                        "dns.bin line {} has unknown section tag {other:?}",
                        index + 1
                    ))
                }
            }
        }
        if !saw_header {
            return Err("dns.bin has no statistics header".to_string());
        }
        let DnsSectionBuffers {
            block_suffix,
            block_exact,
            block_ips,
            allow_suffix,
            allow_exact,
            important_suffix,
            important_exact,
            priority_allow,
        } = dns_sections;
        filter.block_suffix = domain_set_from_sorted(block_suffix.lines())?;
        filter.block_exact = domain_set_from_sorted(block_exact.lines())?;
        filter.block_ips = domain_set_from_sorted(block_ips.lines())?;
        filter.allow_suffix = domain_set_from_sorted(allow_suffix.lines())?;
        filter.allow_exact = domain_set_from_sorted(allow_exact.lines())?;
        filter.important_suffix = domain_set_from_sorted(important_suffix.lines())?;
        filter.important_exact = domain_set_from_sorted(important_exact.lines())?;
        filter.priority_allow_suffix = domain_set_from_sorted(priority_allow.lines())?;
        Ok(filter)
    }

    /// Number of rules that will actually be consulted.
    pub fn len(&self) -> usize {
        self.stats.block_rules + self.stats.exception_rules
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn stats(&self) -> RuleStats {
        self.stats
    }

    /// Parse a whole rule file's contents.
    pub fn load_text(&mut self, text: &str) -> RuleStats {
        let mut builder = FilterBuilder::new();
        builder.add_text(text);
        builder.resolve_badfilters();
        builder.apply_to(self)
    }

    fn insert(&mut self, rule: Rule, stats: &mut RuleStats) {
        let domain = normalize_domain(&rule.value);
        match rule.kind {
            RuleKind::Ip => match (rule.exception, rule.important) {
                (true, _) => {
                    // An exception for an IP literal removes the block.
                    self.block_ips.remove(&domain);
                    stats.exception_rules += 1;
                }
                (false, _) => {
                    self.block_ips.insert(&domain);
                    stats.block_rules += 1;
                }
            },
            RuleKind::Exact => match (rule.exception, rule.important) {
                (true, _) => {
                    self.allow_exact.insert(&domain);
                    stats.exception_rules += 1;
                }
                (false, true) => {
                    self.important_exact.insert(&domain);
                    stats.block_rules += 1;
                }
                (false, false) => {
                    self.block_exact.insert(&domain);
                    stats.block_rules += 1;
                }
            },
            RuleKind::Domain => match (rule.exception, rule.important) {
                (true, _) => {
                    self.allow_suffix.insert(&domain);
                    stats.exception_rules += 1;
                }
                (false, true) => {
                    self.important_suffix.insert(&domain);
                    stats.block_rules += 1;
                }
                (false, false) => {
                    self.block_suffix.insert(&domain);
                    stats.block_rules += 1;
                }
            },
        }
    }

    /// Decide on a single hostname (query name or CNAME target).
    ///
    /// Order: user allowlist > `$important` blocks > list exceptions > plain blocks.
    ///
    /// No allocation happens unless the input actually needs normalising: DNS names arrive already
    /// lowercased and dot-terminated-stripped by the wire parser, and this runs once per query per
    /// name plus once per CNAME target, so an unconditional `to_ascii_lowercase()` here would be a
    /// per-query `malloc` for nothing.
    pub fn match_domain(&self, domain: &str) -> Verdict {
        let trimmed = domain.trim_end_matches('.');
        let name: &str = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            &normalize_domain(trimmed)
        } else {
            trimmed.trim()
        };
        if name.is_empty() {
            return Verdict::Allow;
        }
        // The user allowlist beats everything, including `$important`: it is the one place where
        // the person holding the phone outranks the subscription authors.
        if self.priority_allow_suffix.matches_normalized(name) {
            return Verdict::Allow;
        }
        // An IP literal (hosts entry such as `0.0.0.0 93.184.216.34`) is matched verbatim.
        if looks_like_ip(name) {
            return if self.block_ips.contains(name) {
                Verdict::Block
            } else {
                Verdict::Allow
            };
        }

        if self.important_suffix.matches_normalized(name) || self.important_exact.contains(name) {
            return Verdict::Block;
        }
        if self.allow_suffix.matches_normalized(name) || self.allow_exact.contains(name) {
            return Verdict::Allow;
        }
        if self.block_suffix.matches_normalized(name) || self.block_exact.contains(name) {
            return Verdict::Block;
        }
        Verdict::Allow
    }

    /// Decide on a query: the query name plus every CNAME target in the upstream answer.
    ///
    /// Returns the offending name so the request log can explain the block.
    pub fn match_query<'a, I>(&self, names: I) -> Option<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        for name in names {
            if self.match_domain(name) == Verdict::Block {
                return Some(normalize_domain(name));
            }
        }
        None
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Cheap syntactic check for an IP literal, without paying for a full `IpAddr` parse on every DNS
/// name (which is what the query path would otherwise do).
///
/// A DNS name reaching here is `[a-z0-9._-]`; an IPv4 literal is all digits and dots, and an IPv6
/// literal always contains a colon.
fn looks_like_ip(name: &str) -> bool {
    if name.contains(':') {
        return true;
    }
    name.bytes().next().is_some_and(|byte| byte.is_ascii_digit())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
}

/// Decode the `s` header record written by [`Filter::encode_payload`].
///
/// Layout: `files_loaded, lines, block_rules, exception_rules, unsupported, network_only,
/// badfilter_applied`.
fn parse_stats_record(record: &str) -> Result<RuleStats, String> {
    let values = record
        .split('\t')
        .map(|value| value.parse::<usize>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("dns.bin statistics header is malformed: {e}"))?;
    if values.len() != 7 {
        return Err(format!(
            "dns.bin statistics header has {} fields, expected 7",
            values.len()
        ));
    }
    Ok(RuleStats {
        files_loaded: values[0],
        lines: values[1],
        block_rules: values[2],
        exception_rules: values[3],
        unsupported: values[4],
        network_only: values[5],
        badfilter_applied: values[6],
        unsupported_by_reason: [0; UNSUPPORTED_REASONS],
    })
}

/// Accept an allowlist entry written as a bare domain or as a full exception rule.
///
/// The UI (and `docs/JNI.md`) promise that `allowlist` holds domains; being tolerant about
/// `@@||ads.example.com^` and `0.0.0.0 ads.example.com` costs three `strip_*` calls and removes a
/// whole class of "I pasted a rule and nothing happened" reports.
fn strip_allowlist_decoration(entry: &str) -> &str {
    let mut value = entry.trim();
    if let Some(rest) = value.strip_prefix("@@") {
        value = rest.trim_start();
    }
    if let Some(rest) = value.strip_prefix("||") {
        value = rest;
        if let Some(rest) = value.strip_suffix('^') {
            value = rest;
        }
    } else if let Some(rest) = value.strip_prefix('|') {
        value = rest;
        if let Some(rest) = value.strip_suffix('^') {
            value = rest;
        }
    }
    // Make sure a trailing `^` of an unstripped form does not end up inside the domain.
    value.trim().trim_end_matches('^')
}

/// What one line of a filter list is, from the DNS layer's point of view.
///
/// This is the classification `CompileStats` reports per list (task card §4) and the same thing
/// the DNS-layer rule selection decision hangs on: only [`LineClass::Dns`] rules are allowed to
/// block a whole domain name. Everything else is left to the adblock engine (M2/M3), because a
/// rule that carries a scope modifier must not become an unconditional domain block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineClass {
    /// Blank line.
    Blank,
    /// `!` / `#` comment (including list metadata headers).
    Comment,
    /// A members hosts entry: `0.0.0.0 a.com`, `127.0.0.1 a.com`, or a bare `a.com`.
    Hosts,
    /// A `||domain^` / `|domain^` network rule with no modifier that narrows its scope.
    Domain,
    /// A rule that belongs to the adblock engine only: path patterns, `$third-party`,
    /// `$domain=`, resource types, element hiding, scriptlets, ...
    NetworkOnly,
    /// A line that could not be parsed at all.
    Malformed,
}

impl LineClass {
    /// Whether the line contributes a rule to the DNS filter.
    pub fn is_dns(self) -> bool {
        matches!(self, LineClass::Hosts | LineClass::Domain)
    }

    /// Whether the line is element hiding / a scriptlet / any other cosmetic rule.
    pub fn is_cosmetic(self) -> bool {
        matches!(self, LineClass::NetworkOnly)
    }
}

/// Where a parsed DNS rule came from, which is what `LineClass` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleForm {
    /// `0.0.0.0 a.com`, `127.0.0.1 a.com`, or a bare `a.com`.
    Hosts,
    /// `||domain^` or `|domain^`.
    Pattern,
}

/// Classify a single line without retaining anything.
///
/// Used by the compile statistics; [`FilterBuilder::add_text`] uses the same parser so the counts
/// and the compiled filter can never disagree.
pub fn classify_line(line: &str) -> LineClass {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return LineClass::Blank;
    }
    if trimmed.starts_with('!') || trimmed.starts_with('#') {
        return LineClass::Comment;
    }
    // `[Adblock Plus 2.0]` header lines are metadata too.
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        return LineClass::Comment;
    }
    match parse_line(trimmed) {
        Ok(Some(raw)) if raw.badfilter => LineClass::Domain,
        Ok(Some(raw)) => match raw.form {
            Some(RuleForm::Hosts) => LineClass::Hosts,
            Some(RuleForm::Pattern) | None => LineClass::Domain,
        },
        Ok(None) => LineClass::NetworkOnly,
        Err(_) => LineClass::Malformed,
    }
}

/// Whether a line is a cosmetic (element hiding / scriptlet) rule.
///
/// Cosmetic rules are `NetworkOnly` for the DNS layer; this tells them apart so the per-list
/// statistics the UI shows can report element-hiding rules separately (task card §4).
pub fn is_cosmetic_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('#') {
        return false;
    }
    let pattern = trimmed
        .strip_prefix("@@")
        .unwrap_or(trimmed)
        .split('$')
        .next()
        .unwrap_or(trimmed);
    pattern.contains("##") || pattern.contains("#@#") || pattern.contains("#$#")
}

impl RawRule {
    fn into_rule(self) -> Option<Rule> {
        let kind = self.kind?;
        if self.value.is_empty() {
            return None;
        }
        Some(Rule {
            kind,
            value: self.value,
            exception: self.exception,
            important: self.important,
        })
    }
}

/// Parse one non-comment line into a rule description, or `None` when the syntax is outside the
/// M0 subset.
fn parse_line(line: &str) -> Result<Option<RawRule>, Unsupported> {
    let mut exception = false;
    let mut body = line;

    if let Some(rest) = body.strip_prefix("@@") {
        exception = true;
        body = rest;
    }

    // Split modifiers. `$` cannot appear in a domain, so the first `$` starts them.
    let (pattern, modifiers) = match body.find('$') {
        Some(idx) => (&body[..idx], Some(&body[idx + 1..])),
        None => (body, None),
    };

    let mut important = false;
    let mut badfilter = false;
    if let Some(modifiers) = modifiers {
        if modifiers.is_empty() {
            return Err(Unsupported::Malformed);
        }
        for modifier in modifiers.split(',') {
            let modifier = modifier.trim();
            match modifier {
                "important" => important = true,
                "badfilter" => badfilter = true,
                // Everything else belongs to the M1 adblock-rust engine (or is not a DNS-level
                // concept at all).
                _ => return Ok(None),
            }
        }
    }

    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(Unsupported::Malformed);
    }
    // Element hiding and scriptlet rules.
    if pattern.contains("##") || pattern.contains("#@#") || pattern.contains("#$#") {
        return Ok(None);
    }

    // `*.domain` (OISD, HaGeZi and every other domainswild list) means "this domain and every
    // subdomain", which is exactly what the suffix matcher does. Answering it at the DNS layer is the
    // difference between one DNS answer and one SNI check per connection: M5a measured 293,494 such
    // rules falling through to the network layer purely because `is_plain_domain` refuses `*`.
    //
    // The rewrite is only exact when the wildcard is the whole first label (`*.a.com`), which is the
    // only form these lists use. A partial-label wildcard (`*ad.a.com`, `a*.com`) would be a *suffix*
    // match on half a label and is not the same rule — those stay with the engine. A bare `*` or `*.`
    // with nothing after it names no domain at all.
    if let Some(rest) = pattern.strip_prefix("*.") {
        let domain = rest.trim_end_matches('^');
        if is_plain_domain(domain) && !domain.starts_with('.') && !domain.starts_with('*') {
            return Ok(Some(RawRule {
                exception,
                important,
                badfilter,
                kind: Some(RuleKind::Domain),
                form: Some(RuleForm::Pattern),
                value: normalize_domain(domain),
            }));
        }
        return Ok(None);
    }

    if let Some(rest) = pattern.strip_prefix("||") {
        let domain = rest.strip_suffix('^').unwrap_or(rest);
        if !is_plain_domain(domain) {
            return Ok(None);
        }
        return Ok(Some(RawRule {
            exception,
            important,
            badfilter,
            kind: Some(RuleKind::Domain),
            form: Some(RuleForm::Pattern),
            value: normalize_domain(domain),
        }));
    }

    if let Some(rest) = pattern.strip_prefix('|') {
        let domain = rest.strip_suffix('^').unwrap_or(rest);
        // `|http://...` and friends are URL rules.
        if !is_plain_domain(domain) {
            return Ok(None);
        }
        return Ok(Some(RawRule {
            exception,
            important,
            badfilter,
            kind: Some(RuleKind::Exact),
            form: Some(RuleForm::Pattern),
            value: normalize_domain(domain),
        }));
    }

    // Hosts format: `<ip> <host> [<host> ...]` or a bare domain.
    let mut fields = pattern.split_whitespace();
    let Some(first) = fields.next() else {
        return Err(Unsupported::Malformed);
    };
    let rest: Vec<&str> = fields.collect();

    if rest.is_empty() && is_plain_domain(first) {
        return Ok(Some(RawRule {
            exception,
            important,
            badfilter,
            kind: Some(RuleKind::Domain),
            form: Some(RuleForm::Hosts),
            value: normalize_domain(first),
        }));
    }

    if let Ok(ip) = first.parse::<std::net::IpAddr>() {
        // `0.0.0.0 host` / `127.0.0.1 host` are the blocking forms; a hosts entry pointing at a
        // real address is a redirection, which M0 does not implement.
        let blocks = ip.is_unspecified() || ip.is_loopback();
        if !blocks {
            return Ok(None);
        }
        let Some(host) = rest.iter().find(|host| is_plain_domain(host)) else {
            return Err(Unsupported::Malformed);
        };
        // `0.0.0.0 93.184.216.34` blocks that IP literal rather than a name.
        let kind = if host.parse::<std::net::IpAddr>().is_ok() {
            RuleKind::Ip
        } else {
            RuleKind::Domain
        };
        return Ok(Some(RawRule {
            exception,
            important,
            badfilter,
            kind: Some(kind),
            form: Some(RuleForm::Hosts),
            value: normalize_domain(host),
        }));
    }

    Ok(None)
}

/// A plausible DNS name: labels of [a-z0-9_-], dots, no wildcards, at least one dot unless it is
/// clearly an IP address (handled separately).
fn is_plain_domain(candidate: &str) -> bool {
    if candidate.is_empty() || candidate.len() > 253 {
        return false;
    }
    if candidate.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if candidate.contains('/') || candidate.contains('*') || candidate.contains('|') {
        return false;
    }
    let trimmed = candidate.trim_end_matches('.');
    if trimmed.is_empty() {
        return false;
    }
    trimmed.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// A set of domains supporting "this name or any parent name" lookup.
///
/// The M0 implementation was a trie over reversed labels; inserting a few hundred thousand domains
/// through it took 28 s because each node scanned its children linearly (O(n²) overall). What the
/// matcher actually needs is only the suffix-closure question — "is `a.b.com` or `b.com` or `com` in
/// the set?" — so the set answers by walking the name's parent chain: O(labels) lookups.
///
/// A rule for the bare TLD (`||com^`) is still honoured, because `com` itself is one of the suffixes
/// checked.
///
/// # Why not a `HashSet` (M4b)
///
/// It was one, and it dominated the process's memory: 193 thousand blocked domains in a
/// `HashSet<String>` cost **10.0 MiB** measured with the counting allocator in
/// `core/examples/mem_probe.rs` — 4.2 MB of domain text plus 5.8 MB of per-entry overhead (a
/// `String` header is 24 bytes, the hash table holds a 24-byte bucket plus a control byte, and the
/// allocator rounds each of 193 thousand small allocations up). The set is built once and only ever
/// read, and its members are known when it is built, so it is stored as one sorted `Box<str>` block
/// plus a `u32` offset per entry:
///
/// | Representation | 193 177 domains |
/// |---|---|
/// | `HashSet<String>` | 10.0 MiB measured |
/// | sorted block + `u32` offsets | 4.5 MiB measured (4.2 MB text + 772 KB offsets) |
///
/// Lookup is a binary search over the offsets followed by a slice compare, which is not slower than
/// hashing at this size: the search touches ~18 cache lines of a contiguous array instead of
/// chasing 193 thousand separately allocated buffers through a bucket array.
///
/// The sorted order also makes the on-disk form (one domain per line, ascending) the in-memory form:
/// [`Filter::decode_payload`] copies the payload's domain bytes straight into the block instead of
/// allocating one `String` per domain.
///
/// Insertion still happens during a compile ([`FilterBuilder::apply_to`]), so building goes through
/// a `Vec<String>` scratch list and [`freeze`](Self::freeze) closes it into the compact form.
#[derive(Debug, Clone, Default)]
struct DomainSet {
    /// All domains, concatenated in ascending byte order.
    block: Box<str>,
    /// `offsets[i]..offsets[i + 1]` is the `i`-th domain in `block`. The last entry is
    /// `block.len()`, so an empty set has no entries at all (`offsets` empty).
    offsets: Vec<u32>,
    /// Domains added since the last [`freeze`](Self::freeze). Non-empty only while a compile is
    /// building the set.
    pending: Vec<String>,
}

impl DomainSet {
    fn insert(&mut self, domain: &str) {
        let domain = normalize_domain(domain);
        if !domain.is_empty() {
            self.pending.push(domain);
        }
    }

    /// Fold `pending` into the sorted block.
    ///
    /// Called once at the end of a compile (all inserts are pending) and never on the load path
    /// (the block arrives already frozen and sorted). Rebuilding from the union keeps the invariant
    /// — block strictly ascending, offsets monotonic — trivially true; the cost is one sort over the
    /// domains, which is what the compile paid when this was a `HashSet` too.
    fn freeze(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let mut all: Vec<&str> = (0..self.offsets.len().saturating_sub(1))
            .map(|index| self.domain_at(index))
            .collect();
        all.extend(self.pending.iter().map(String::as_str));
        all.sort_unstable();
        all.dedup();
        let mut block = String::with_capacity(all.iter().map(|domain| domain.len()).sum());
        let mut offsets: Vec<u32> = Vec::with_capacity(all.len() + 1);
        for domain in all {
            offsets.push(block.len() as u32);
            block.push_str(domain);
        }
        offsets.push(block.len() as u32);
        self.block = block.into_boxed_str();
        self.offsets = offsets;
        self.pending = Vec::new();
    }

    fn domain_at(&self, index: usize) -> &str {
        &self.block[self.offsets[index] as usize..self.offsets[index + 1] as usize]
    }

    /// Drop one domain.
    ///
    /// Only `$badfilter` on an IP literal needs this, and it happens during a parse, before the set
    /// is frozen.
    fn remove(&mut self, name: &str) {
        self.freeze();
        if self.offsets.len() <= 1 {
            return;
        }
        if !self.contains(name) {
            return;
        }
        let kept: Vec<String> = (0..self.offsets.len() - 1)
            .map(|index| self.domain_at(index).to_string())
            .filter(|domain| domain != name)
            .collect();
        self.block = "".into();
        self.offsets = Vec::new();
        self.pending = kept;
        self.freeze();
    }

    /// Exact membership test, by binary search over the sorted block.
    fn contains(&self, name: &str) -> bool {
        let count = self.offsets.len().saturating_sub(1);
        let mut low = 0usize;
        let mut high = count;
        while low < high {
            let mid = (low + high) / 2;
            match self.domain_at(mid).cmp(name) {
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
                std::cmp::Ordering::Equal => return true,
            }
        }
        false
    }

    fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1) + self.pending.len()
    }

    /// Every domain in the set, in ascending order, for serialization.
    ///
    /// Borrowed rather than cloned: the frozen block *is* the sorted output, so writing `dns.bin`
    /// costs no per-domain allocation.
    fn sorted(&self) -> impl Iterator<Item = &str> {
        (0..self.offsets.len().saturating_sub(1))
            .map(|index| self.domain_at(index))
            .chain(self.pending.iter().map(String::as_str))
    }

    /// Match `name` or any of its parent domains.
    ///
    /// The same question the `HashSet` version answered, with the same answer: walk the parent chain
    /// one label at a time and binary-search each candidate. O(labels × log n), no allocation.
    fn matches_normalized(&self, name: &str) -> bool {
        if name.is_empty() || self.offsets.len() <= 1 {
            return false;
        }
        if self.contains(name) {
            return true;
        }
        let mut rest = name;
        while let Some(index) = rest.find('.') {
            rest = &rest[index + 1..];
            if rest.is_empty() {
                break;
            }
            if self.contains(rest) {
                return true;
            }
        }
        false
    }

    fn matches(&self, domain: &str) -> bool {
        if self.offsets.len() <= 1 {
            return false;
        }
        let name = normalize_domain(domain);
        self.matches_normalized(&name)
    }
}

/// Build a frozen [`DomainSet`] from domains that are already in ascending order.
///
/// This is the load path: `dns.bin` stores each section sorted, so the whole set becomes one
/// allocation of exactly the payload bytes plus the offset array — no per-domain `String`.
///
/// A record that is not strictly greater than its predecessor means the artifact was not produced by
/// this crate's writer. That is reported as an error rather than skipped: binary search over an
/// unsorted block answers *wrongly*, and a silently dropped rule is a filter that silently stops
/// blocking — the one failure mode this crate is not allowed to have. The caller turns the error into
/// "recompile", which is what every other malformed-artifact case does.
fn domain_set_from_sorted<'a, I>(domains: I) -> Result<DomainSet, String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut block = String::new();
    let mut offsets: Vec<u32> = Vec::new();
    // The previous domain is borrowed from `block`'s own buffer rather than allocated: an owned
    // `String` per entry would be 193 thousand allocations on the load path, exactly what this
    // representation exists to avoid.
    let mut previous_start = 0usize;
    for domain in domains {
        if domain.is_empty() {
            continue;
        }
        if !offsets.is_empty() && domain <= &block[previous_start..] {
            return Err(format!(
                "dns.bin section is not in ascending order ({domain:?} after {:?})",
                &block[previous_start..]
            ));
        }
        offsets.push(block.len() as u32);
        block.push_str(domain);
        previous_start = block.len() - domain.len();
    }
    offsets.push(block.len() as u32);
    Ok(DomainSet {
        block: block.into_boxed_str(),
        offsets,
        pending: Vec::new(),
    })
}

/// The eight domain sections of a `dns.bin` payload, collected while the payload is parsed.
///
/// Each holds the section's `domain\n` records verbatim, so [`Filter::decode_payload`] appends
/// slices instead of allocating one pointer per domain (16 bytes × 193 thousand would be 3 MiB, the
/// very overhead this representation removes).
#[derive(Default)]
struct DnsSectionBuffers {
    block_suffix: String,
    block_exact: String,
    block_ips: String,
    allow_suffix: String,
    allow_exact: String,
    important_suffix: String,
    important_exact: String,
    priority_allow: String,
}

impl DnsSectionBuffers {
    fn push(&mut self, tag: &str, domain: &str) {
        let target = match tag {
            "b" => &mut self.block_suffix,
            "B" => &mut self.block_exact,
            "i" => &mut self.block_ips,
            "a" => &mut self.allow_suffix,
            "A" => &mut self.allow_exact,
            "m" => &mut self.important_suffix,
            "M" => &mut self.important_exact,
            "p" => &mut self.priority_allow,
            // `decode_payload` rejects unknown tags before reaching here.
            _ => return,
        };
        target.push_str(domain);
        target.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(text: &str) -> Filter {
        let mut f = Filter::new();
        f.load_text(text);
        f
    }

    #[test]
    fn hosts_formats_are_all_blocking() {
        let f = filter(
            "0.0.0.0 a.example.com\n\
             127.0.0.1 b.example.com\n\
             c.example.com\n",
        );
        assert_eq!(f.match_domain("a.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("b.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("c.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("d.example.com"), Verdict::Allow);
    }

    #[test]
    fn hosts_entries_block_subdomains_but_not_similar_names() {
        let f = filter("0.0.0.0 hosts.example.com\n");
        assert_eq!(f.match_domain("hosts.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("deep.hosts.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("nothosts.example.com"), Verdict::Allow);
        assert_eq!(f.match_domain("hosts.example.com.evil.net"), Verdict::Allow);
    }

    #[test]
    fn domain_rule_blocks_subdomains_only() {
        let f = filter("||doubleclick.net^\n");
        assert_eq!(f.match_domain("doubleclick.net"), Verdict::Block);
        assert_eq!(f.match_domain("a.doubleclick.net"), Verdict::Block);
        assert_eq!(f.match_domain("stats.g.doubleclick.net"), Verdict::Block);
        // The task card's explicit negative case.
        assert_eq!(f.match_domain("notdoubleclick.net"), Verdict::Allow);
        assert_eq!(f.match_domain("doubleclick.net.example.org"), Verdict::Allow);
    }

    #[test]
    fn start_anchor_rule_matches_exactly_one_name() {
        let f = filter("|exact.example.com^\n");
        assert_eq!(f.match_domain("exact.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("sub.exact.example.com"), Verdict::Allow);
    }

    #[test]
    fn exception_rules_win_over_blocks() {
        let f = filter(
            "||example.com^\n\
             @@||cdn.example.com^\n",
        );
        assert_eq!(f.match_domain("example.com"), Verdict::Block);
        assert_eq!(f.match_domain("ads.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("cdn.example.com"), Verdict::Allow);
        assert_eq!(f.match_domain("img.cdn.example.com"), Verdict::Allow);
    }

    #[test]
    fn important_beats_exception() {
        let f = filter(
            "||tracker.example.com^$important\n\
             @@||tracker.example.com^\n",
        );
        assert_eq!(f.match_domain("tracker.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("x.tracker.example.com"), Verdict::Block);
    }

    #[test]
    fn important_does_not_disable_unrelated_exceptions() {
        let f = filter(
            "||ads.example.com^$important\n\
             ||cdn.example.com^\n\
             @@||cdn.example.com^\n",
        );
        assert_eq!(f.match_domain("ads.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("cdn.example.com"), Verdict::Allow);
    }

    #[test]
    fn badfilter_disables_the_identical_rule() {
        let mut f = Filter::new();
        let stats = f.load_text(
            "||ads.example.com^\n\
             ||ads.example.com^$badfilter\n\
             ||kept.example.com^\n",
        );
        assert_eq!(stats.badfilter_applied, 1);
        assert_eq!(f.match_domain("ads.example.com"), Verdict::Allow);
        assert_eq!(f.match_domain("kept.example.com"), Verdict::Block);

        // A `$badfilter` whose target does not exist costs nothing user-visible: the line is valid
        // adblock syntax the engine uses, so under the shared "不支持" definition it is not broken.
        // The DNS layer still records its own reason for diagnostics (`docs/JNI.md` §"规则统计").
        let mut g = Filter::new();
        let stats = g.load_text("||never.example.com^$badfilter\n");
        assert_eq!(stats.badfilter_applied, 0);
        assert_eq!(
            stats.unsupported, 0,
            "a dangling $badfilter is a well-formed rule, not an unsupported line"
        );
        assert_eq!(
            stats.unsupported_by_reason[Unsupported::DanglingBadfilter.index()],
            1,
            "the DNS layer's own diagnostic still records the dangling reference"
        );
        assert_eq!(stats.network_only, 0, "it is a DNS-layer rule, just an unpaired one");
    }

    #[test]
    fn badfilter_only_removes_matching_flavour() {
        // A badfilter for the plain rule must not disable the $important variant.
        let f = filter(
            "||ads.example.com^$important\n\
             ||ads.example.com^$badfilter\n",
        );
        assert_eq!(f.match_domain("ads.example.com"), Verdict::Block);
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let mut f = Filter::new();
        let stats = f.load_text(
            "! a comment\n\
             \n\
             # hash comment\n\
             ||real.example.com^\n",
        );
        assert_eq!(stats.unsupported, 0);
        assert_eq!(stats.block_rules, 1);
        assert_eq!(f.match_domain("real.example.com"), Verdict::Block);
    }

    #[test]
    fn engine_only_rules_are_counted_not_fatal() {
        let mut f = Filter::new();
        let stats = f.load_text(
            "||ads.example.com^$third-party\n\
             /banner/*/img^\n\
             example.com##.ad\n\
             ||ok.example.com^\n",
        );
        // Valid engine rules are network-only, not parse failures: "不支持" must mean "broken", or
        // every real list would report tens of thousands of failures it does not have.
        assert_eq!(stats.network_only, 3);
        assert_eq!(stats.unsupported, 0);
        assert_eq!(stats.block_rules, 1);
        assert_eq!(f.match_domain("ok.example.com"), Verdict::Block);
    }

    #[test]
    fn genuinely_broken_lines_are_counted_as_unsupported() {
        let mut f = Filter::new();
        let stats = f.load_text(
            "||broken.example^$\n\
             ||ok.example.com^\n",
        );
        assert_eq!(stats.unsupported, 1);
        assert_eq!(stats.network_only, 0);
        assert_eq!(stats.block_rules, 1);
    }

    /// MYS-2716 #3: "不支持" has exactly one definition, and it is the one the compile statistics,
    /// the `dns.bin` header and the hot-reload log all print.
    ///
    /// The bug: the compile statistics said 0 while the hot-reload log said "107 unsupported" for
    /// the same rule set, because the compile side counted per-line DNS-layer rejections (which
    /// excludes every `network_rules` line) and the reload side read `RuleStats::unsupported`. Both
    /// now derive from the same per-line tally: a line is unsupported only when **neither** layer
    /// can use it.
    #[test]
    fn unsupported_means_neither_layer_can_use_the_line() {
        let mut builder = FilterBuilder::new();
        // Both layers use it: a DNS rule.
        // DNS cannot, the engine can: an engine-only rule.
        // Neither can: the modifier list is empty, which adblock-rust also rejects.
        // The DNS layer stops at the unknown modifier, and adblock-rust rejects it as well.
        // The last line is metadata, not a rule: counted in `lines` only.
        let counts = builder.add_text(
            "||both.example^\n\
             ||engine.example^$third-party\n\
             ||broken.example^$\n\
             ||nonsense.example^$nonsense\n\
             ! a comment\n",
        );
        builder.resolve_badfilters();
        let mut f = Filter::new();
        let stats = builder.apply_to(&mut f);

        assert_eq!(counts.dns_rules, 1, "||both.example^");
        assert_eq!(counts.network_rules, 1, "||engine.example^$third-party");
        assert_eq!(
            counts.unsupported, 2,
            "the empty modifier list and the unknown modifier are the only unsupported ones: \
             the engine rejects both, so neither layer can use them"
        );

        // Every class adds up to the number of non-metadata lines: nothing is counted twice and
        // nothing falls through the cracks.
        let rules = counts.dns_rules + counts.network_rules + counts.unsupported;
        assert_eq!(rules, 4, "four rule lines, one comment");

        // The two places that used to disagree now report the same number, by construction.
        assert_eq!(
            stats.unsupported, counts.unsupported as usize,
            "the hot-reload log's figure and the compile statistics' figure are the same tally"
        );
        assert_eq!(
            stats.unsupported + stats.network_only,
            counts.unsupported as usize + counts.network_rules as usize,
            "RuleStats splits exactly the same lines the per-list counts do"
        );
        assert_eq!(stats.unsupported_by_reason.iter().sum::<usize>(), stats.unsupported);
    }

    /// The shared definition has to survive the `dns.bin` round trip, because `reload` prints the
    /// header rather than re-counting the lists (`docs/JNI.md` §"规则统计").
    #[test]
    fn the_unsupported_definition_survives_the_artifact_round_trip() {
        let mut f = Filter::new();
        let stats = f.load_text(
            "||both.example^\n\
             ||engine.example^$third-party\n\
             ||broken.example^$\n\
             ||also-broken.example^$nonsense\n",
        );
        assert_eq!(stats.unsupported, 2);
        let decoded = Filter::decode_payload(&f.encode_payload()).expect("round trip");
        assert_eq!(
            decoded.stats().unsupported,
            stats.unsupported,
            "the compiled artifact must carry the same figure the compile reported"
        );
        assert_eq!(decoded.stats().network_only, stats.network_only);
    }

    #[test]
    fn cname_chain_is_matched() {
        let f = filter("||doubleclick.net^\n");
        let names = [
            "metrics.example.com",
            "tracker.doubleclick.net",
            "edge.example.net",
        ];
        assert_eq!(
            f.match_query(names.into_iter()),
            Some("tracker.doubleclick.net".to_string())
        );

        let clean = ["metrics.example.com", "edge.example.net"];
        assert_eq!(f.match_query(clean.into_iter()), None);
    }

    #[test]
    fn cname_chain_respects_exceptions() {
        let f = filter(
            "||doubleclick.net^\n\
             @@||safe.doubleclick.net^\n",
        );
        let allowed = ["metrics.example.com", "safe.doubleclick.net"];
        assert_eq!(f.match_query(allowed.into_iter()), None);
        let blocked = ["metrics.example.com", "evil.doubleclick.net"];
        assert_eq!(
            f.match_query(blocked.into_iter()),
            Some("evil.doubleclick.net".to_string())
        );
    }

    #[test]
    fn matching_is_case_and_dot_insensitive() {
        let f = filter("||DoubleClick.NET^\n");
        assert_eq!(f.match_domain("A.DOUBLECLICK.net."), Verdict::Block);
        assert_eq!(f.match_domain("doubleclick.net"), Verdict::Block);
    }

    #[test]
    fn ip_literal_hosts_entries_block_that_ip() {
        let f = filter("0.0.0.0 93.184.216.34\n");
        assert_eq!(f.match_domain("93.184.216.34"), Verdict::Block);
        assert_eq!(f.match_domain("93.184.216.35"), Verdict::Allow);
    }

    #[test]
    fn trie_lookup_has_no_suffix_false_positives() {
        let f = filter(
            "||example.com^\n\
             ||ads.net^\n",
        );
        for name in [
            "myexample.com",
            "anexample.com",
            "example.com.au",
            "badads.net",
            "ads.network",
        ] {
            assert_eq!(
                f.match_domain(name),
                Verdict::Allow,
                "{name} must not match"
            );
        }
        assert_eq!(f.match_domain("example.com"), Verdict::Block);
        assert_eq!(f.match_domain("ads.net"), Verdict::Block);
    }

    #[test]
    fn trie_handles_many_rules_quickly() {
        let mut text = String::new();
        for i in 0..5000 {
            text.push_str(&format!("||host{i}.ads.example.com^\n"));
        }
        let mut f = Filter::new();
        f.load_text(&text);
        assert_eq!(f.stats().block_rules, 5000);
        assert_eq!(f.match_domain("host4242.ads.example.com"), Verdict::Block);
        assert_eq!(f.match_domain("host5000.ads.example.com"), Verdict::Allow);
        // A parent rule would match all of them.
        f.load_text("||ads.example.com^\n");
        assert_eq!(f.match_domain("host5000.ads.example.com"), Verdict::Block);
    }

    #[test]
    fn scope_modifiers_never_become_domain_blocks() {
        // The task card's explicit DNS-layer selection table (task card §4).
        let f = filter(
            "||third.example^$third-party\n\
             ||path.example/ads.js\n\
             ||domainopt.example^$domain=foo.example\n\
             ||script.example^$script\n\
             ||ok.example^\n\
             ||ok-important.example^$important\n\
             0.0.0.0 hosts.example\n",
        );
        // Modifier-scoped rules must not block the whole domain at the DNS layer.
        assert_eq!(f.match_domain("third.example"), Verdict::Allow, "$third-party");
        assert_eq!(f.match_domain("path.example"), Verdict::Allow, "path rule");
        assert_eq!(f.match_domain("domainopt.example"), Verdict::Allow, "$domain=");
        assert_eq!(f.match_domain("script.example"), Verdict::Allow, "$script");
        // Unmodified and `$important` domain rules do.
        assert_eq!(f.match_domain("ok.example"), Verdict::Block);
        assert_eq!(f.match_domain("ok-important.example"), Verdict::Block);
        assert_eq!(f.match_domain("hosts.example"), Verdict::Block);

        // The build-wide statistics stay honest: the four modifier-scoped rules are counted as
        // network rules (the engine's job), not as parse failures.
        let stats = f.stats();
        assert_eq!(stats.block_rules, 3);
        assert_eq!(stats.unsupported, 0, "valid engine rules are not parse failures");
        assert_eq!(stats.network_only, 4);
    }

    #[test]
    fn line_classification_is_stable() {
        assert_eq!(classify_line(""), LineClass::Blank);
        assert_eq!(classify_line("   "), LineClass::Blank);
        assert_eq!(classify_line("! Title: x"), LineClass::Comment);
        assert_eq!(classify_line("# hash"), LineClass::Comment);
        assert_eq!(classify_line("[Adblock Plus 2.0]"), LineClass::Comment);
        assert_eq!(classify_line("0.0.0.0 a.example"), LineClass::Hosts);
        assert_eq!(classify_line("127.0.0.1 a.example"), LineClass::Hosts);
        assert_eq!(classify_line("a.example"), LineClass::Hosts);
        assert_eq!(classify_line("||a.example^"), LineClass::Domain);
        assert_eq!(classify_line("|a.example^"), LineClass::Domain);
        assert_eq!(classify_line("||a.example^$important"), LineClass::Domain);
        assert_eq!(classify_line("||a.example^$third-party"), LineClass::NetworkOnly);
        assert_eq!(classify_line("||a.example/path"), LineClass::NetworkOnly);
        assert_eq!(classify_line("a.example##.ad"), LineClass::NetworkOnly);
        assert_eq!(classify_line("/re/"), LineClass::NetworkOnly);
        // A domain rule with a broken modifier list is malformed, not "unsupported syntax".
        assert_eq!(classify_line("||a.example^$"), LineClass::Malformed);
    }

    #[test]
    fn cosmetic_lines_are_recognised() {
        assert!(is_cosmetic_line("example.com##.ad"));
        assert!(is_cosmetic_line("example.com#@#.ad"));
        assert!(is_cosmetic_line("example.com##+js(set-constant, ads, false)"));
        // `$generichide` is a network modifier, not a cosmetic rule.
        assert!(!is_cosmetic_line("@@||example.com^$generichide"));
        assert!(!is_cosmetic_line("||example.com^"));
        assert!(!is_cosmetic_line("! comment ## not a rule"));
        assert!(!is_cosmetic_line(""));
    }

    #[test]
    fn user_allowlist_beats_every_list_rule() {
        let mut f = filter(
            "||blocked.example^\n\
             ||blocked.example^$important\n\
             @@||other.example^\n",
        );
        f.add_allowlist(["sub.blocked.example", "@@||other.example^"]);
        assert_eq!(f.match_domain("blocked.example"), Verdict::Block);
        assert_eq!(f.match_domain("sub.blocked.example"), Verdict::Allow);
        assert_eq!(f.match_domain("deep.sub.blocked.example"), Verdict::Allow);
        assert_eq!(f.match_domain("other.example"), Verdict::Allow);
        assert_eq!(f.allowlist_len(), 2);
        assert!(f.is_allowlisted("deep.sub.blocked.example"));
        assert!(!f.is_allowlisted("blocked.example"));
    }

    #[test]
    fn dns_payload_round_trip_keeps_every_rule_and_the_statistics() {
        let mut f = filter(
            "||a.example^\n\
             ||a.example^$important\n\
             @@||b.example^\n\
             0.0.0.0 c.example\n\
             |exact.example^\n\
             0.0.0.0 1.2.3.4\n\
             ||skip.example^$third-party\n",
        );
        f.add_allowlist(["allowed.example"]);
        let original = f.stats();
        let restored = Filter::decode_payload(&f.encode_payload()).expect("decode");

        assert_eq!(restored.stats(), original);
        for name in [
            "a.example",
            "sub.a.example",
            "b.example",
            "c.example",
            "exact.example",
            "1.2.3.4",
            "skip.example",
            "allowed.example",
            "clean.example",
        ] {
            assert_eq!(
                restored.match_domain(name),
                f.match_domain(name),
                "verdict different for {name}"
            );
        }
    }

    #[test]
    fn dns_payload_rejects_a_missing_or_broken_header() {
        assert!(Filter::decode_payload(b"b\ta.example\n").is_err());
        assert!(Filter::decode_payload(b"s\tnot\tnumbers\n").is_err());
        assert!(Filter::decode_payload(b"s\t1\t2\t3\n").is_err());
        assert!(Filter::decode_payload(b"s\t0\t0\t0\t0\t0\t0\nq\tx.example\n").is_err());
    }

    #[test]
    fn rule_stats_are_aggregated_across_files() {
        let mut f = Filter::new();
        f.load_text("||a.example.com^\n$bad_modifier\n");
        f.load_text("@@||b.example.com^\n");
        let stats = f.stats();
        assert_eq!(stats.files_loaded, 2);
        assert_eq!(stats.block_rules, 1);
        assert_eq!(stats.exception_rules, 1);
        // `$bad_modifier` is an unknown modifier: the DNS layer stops at it, and adblock-rust
        // rejects the line too, so **neither** layer can use it. That is the MYS-2716 definition of
        // "不支持" — before it, this line was reported as an engine rule while the engine silently
        // dropped it (`docs/JNI.md` §"规则统计").
        assert_eq!(stats.network_only, 0);
        assert_eq!(stats.unsupported, 1);
    }
    // ---------------------------------------------------------------------------------------
    // M4b: the compact `DomainSet` must decide exactly what the `HashSet<String>` version did.
    // ---------------------------------------------------------------------------------------

    /// The reference implementation this crate used through v0.0.9: a `HashSet` of full domain
    /// strings, answered by walking the name's parent chain. Kept only in the tests, as the oracle
    /// the compact representation is compared against — the equality claim is checked by code rather
    /// than asserted in a comment.
    fn hash_set_suffix_match(domains: &HashSet<String>, name: &str) -> bool {
        if domains.is_empty() || name.is_empty() {
            return false;
        }
        if domains.contains(name) {
            return true;
        }
        let mut rest = name;
        while let Some(index) = rest.find('.') {
            rest = &rest[index + 1..];
            if rest.is_empty() {
                break;
            }
            if domains.contains(rest) {
                return true;
            }
        }
        false
    }

    fn oracle_sets(filter: &Filter) -> [HashSet<String>; 8] {
        [
            &filter.block_suffix,
            &filter.block_exact,
            &filter.block_ips,
            &filter.allow_suffix,
            &filter.allow_exact,
            &filter.important_suffix,
            &filter.important_exact,
            &filter.priority_allow_suffix,
        ]
        .map(|set| set.sorted().map(str::to_string).collect())
    }

    /// The pre-M4b decision order, against `HashSet` sets: identical structure to
    /// [`Filter::match_domain`] with only the data structure swapped.
    fn oracle_verdict(sets: &[HashSet<String>; 8], domain: &str) -> Verdict {
        // Same order as `oracle_sets` returns.
        let [block_suffix, block_exact, block_ips, allow_suffix, allow_exact, important_suffix, important_exact, priority_allow] =
            sets;
        let trimmed = domain.trim_end_matches('.');
        let name: &str = if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
            &normalize_domain(trimmed)
        } else {
            trimmed.trim()
        };
        if name.is_empty() {
            return Verdict::Allow;
        }
        if hash_set_suffix_match(priority_allow, name) {
            return Verdict::Allow;
        }
        if looks_like_ip(name) {
            return if block_ips.contains(name) { Verdict::Block } else { Verdict::Allow };
        }
        if hash_set_suffix_match(important_suffix, name) || important_exact.contains(name) {
            return Verdict::Block;
        }
        if hash_set_suffix_match(allow_suffix, name) || allow_exact.contains(name) {
            return Verdict::Allow;
        }
        if hash_set_suffix_match(block_suffix, name) || block_exact.contains(name) {
            return Verdict::Block;
        }
        Verdict::Allow
    }

    /// Names a filter built from `text` must decide: every rule domain, each of its parents and a
    /// child of each, plus the shapes that trip a suffix matcher (look-alikes, trailing dot, upper
    /// case, empty, IP literals).
    fn probe_names(text: &str) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for line in text.lines() {
            let body = line.trim().trim_start_matches("@@");
            let body = body
                .trim_start_matches("||")
                .trim_start_matches('|')
                .trim_end_matches('^')
                .trim_end_matches('|');
            let domain = body.split('$').next().unwrap_or("");
            let domain = normalize_domain(domain);
            if domain.is_empty() || !domain.contains('.') {
                continue;
            }
            let labels: Vec<&str> = domain.split('.').collect();
            for start in 0..labels.len() {
                let suffix = labels[start..].join(".");
                names.push(suffix.clone());
                names.push(format!("x.{suffix}"));
            }
            names.push(format!("not{domain}"));
            names.push(format!("{domain}.evil.example"));
            names.push(format!("{domain}."));
            names.push(domain.to_ascii_uppercase());
            names.push(format!("sub.{}", domain.to_ascii_uppercase()));
        }
        names.push(String::new());
        names.push(".".to_string());
        names.push("127.0.0.1".to_string());
        names.push("::1".to_string());
        names
    }

    /// One rule of every shape this parser understands, including the interactions where a matcher
    /// that got the order wrong would still pass a naive test: `$important` vs an exception, a
    /// `$badfilter`, a bare-TLD rule, a hosts entry for an IP literal, mixed case.
    const EQUIVALENCE_RULES: &str = "\
||doubleclick.net^\n\
||ads.example.com^\n\
||deep.ads.example.com^\n\
||com^\n\
|exact.example.com^\n\
||important.example.com^$important\n\
@@||allowed.example.com^\n\
||blocked.example.com^\n\
||blocked.example.com^$important\n\
@@||sub.blocked.example.com^\n\
||badfiltered.example.com^\n\
||badfiltered.example.com^$badfilter\n\
0.0.0.0 hosts.example.com\n\
127.0.0.1 93.184.216.34\n\
||A.Mixed.Case.Example^\n\
";

    #[test]
    fn the_compact_domain_set_decides_exactly_like_the_hash_set() {
        let mut f = Filter::new();
        f.load_text(EQUIVALENCE_RULES);
        f.add_allowlist(["user.allow.example.com", "@@||other.allow.example.com^"]);
        let sets = oracle_sets(&f);
        let names = probe_names(EQUIVALENCE_RULES);
        assert!(names.len() > 60, "the probe set must be broad, got {}", names.len());
        for name in &names {
            assert_eq!(
                f.match_domain(name),
                oracle_verdict(&sets, name),
                "verdict differs for {name:?}"
            );
        }
    }

    #[test]
    fn a_round_trip_through_the_artifact_keeps_every_verdict() {
        // The load path rebuilds the sets from the serialized form, which is a different code path
        // from the compile path (frozen-by-insert vs frozen-from-sorted). Both must answer alike.
        let mut original = Filter::new();
        original.load_text(EQUIVALENCE_RULES);
        original.add_allowlist(["user.allow.example.com"]);
        let payload = original.encode_payload();
        let restored = Filter::decode_payload(&payload).expect("decode");

        let names = probe_names(EQUIVALENCE_RULES);
        for name in &names {
            assert_eq!(
                restored.match_domain(name),
                original.match_domain(name),
                "the artifact round trip changed the verdict for {name:?}"
            );
        }
        assert!(names.len() > 60);
        assert_eq!(restored.stats(), original.stats());
    }

    #[test]
    fn the_sorted_block_is_strictly_ascending() {
        // Binary search is only correct on sorted, duplicate-free input: assert the invariant the
        // search depends on rather than trusting the writer.
        let mut f = Filter::new();
        f.load_text("||b.example^\n||a.example^\n||c.example^\n||a.example^\n0.0.0.0 z.example\n");
        let domains: Vec<&str> = f.block_suffix.sorted().collect();
        assert_eq!(domains, vec!["a.example", "b.example", "c.example", "z.example"]);
        for set in [
            &f.block_exact,
            &f.block_ips,
            &f.allow_suffix,
            &f.allow_exact,
            &f.important_suffix,
            &f.important_exact,
            &f.priority_allow_suffix,
        ] {
            let entries: Vec<&str> = set.sorted().collect();
            assert!(
                entries.windows(2).all(|pair| pair[0] < pair[1]),
                "a frozen section is not strictly ascending: {entries:?}"
            );
        }
    }

    #[test]
    fn an_unsorted_artifact_is_rejected_rather_than_silently_losing_rules() {
        // `dns.bin` is sorted by its writer. A file that is not must be reported unusable — the
        // Kotlin side then recompiles — never decoded into a set that binary search answers
        // wrongly: a dropped rule is a filter that silently stops blocking.
        let payload = b"s\t1\t1\t0\t0\t0\t0\t0\nb\tz.example\nb\ta.example\n";
        let error = Filter::decode_payload(payload).expect_err("must be rejected");
        assert!(error.contains("ascending"), "unexpected error: {error}");

        // A duplicate is equally fatal: the same "not produced by this writer" signal.
        let duplicate = b"s\t1\t1\t0\t0\t0\t0\t0\nb\ta.example\nb\ta.example\n";
        assert!(Filter::decode_payload(duplicate).is_err());

        // Sorted input decodes and answers correctly.
        let sorted = b"s\t1\t1\t0\t0\t0\t0\t0\nb\tm.example\nb\tz.example\n";
        let f = Filter::decode_payload(sorted).expect("decode");
        assert_eq!(f.block_suffix.sorted().collect::<Vec<_>>(), vec!["m.example", "z.example"]);
        assert_eq!(f.match_domain("m.example"), Verdict::Block);
        assert_eq!(f.match_domain("a.example"), Verdict::Allow);
    }

    #[test]
    fn a_large_domain_set_matches_every_member_and_its_children() {
        // The default list set has 193 thousand blocked domains; 20 thousand is enough to exercise
        // a deep binary search without making the test slow.
        let mut text = String::new();
        for index in 0..20_000 {
            text.push_str(&format!("||host{index}.example.com^\n"));
        }
        let mut f = Filter::new();
        f.load_text(&text);
        assert_eq!(f.stats().block_rules, 20_000);
        for index in [0usize, 1, 500, 9_999, 19_998, 19_999] {
            assert_eq!(
                f.match_domain(&format!("host{index}.example.com")),
                Verdict::Block,
                "host{index} must be blocked"
            );
            assert_eq!(
                f.match_domain(&format!("cdn.host{index}.example.com")),
                Verdict::Block,
                "a child of host{index} must be blocked"
            );
        }
        // Siblings must not match: the classic suffix-matcher false positive.
        assert_eq!(f.match_domain("nothost1.example.com"), Verdict::Allow);
        assert_eq!(f.match_domain("host20000.example.com"), Verdict::Allow);
    }

    // -----------------------------------------------------------------------------------------
    // `*.domain` (M5b §4): the same verdicts as the network layer used to give it.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn a_wildcard_domain_rule_blocks_the_domain_and_its_subdomains() {
        let f = filter("*.oisd.example\n");
        for name in [
            "oisd.example",
            "a.oisd.example",
            "x.y.z.oisd.example",
            "OISD.Example",
        ] {
            assert_eq!(f.match_domain(name), Verdict::Block, "{name} must be blocked");
        }
        // The two false positives a naive `contains` would produce, and the one a bare `||` would.
        for name in [
            "notoisd.example",
            "oisd.example.evil.net",
            "oisdXexample",
        ] {
            assert_eq!(f.match_domain(name), Verdict::Allow, "{name} must resolve");
        }
    }

    #[test]
    fn a_wildcard_rule_keeping_its_own_form_still_means_the_same_thing() {
        // The old and the new spelling of the same rule must land in the same place: `*.a.example`
        // and `||a.example^` are the same instruction, and a list that writes one must not filter
        // differently from a list that writes the other.
        let wildcard = filter("*.same.example\n");
        let plain = filter("||same.example^\n");
        for name in [
            "same.example",
            "a.same.example",
            "x.y.same.example",
            "notsame.example",
            "same.example.org",
        ] {
            assert_eq!(
                wildcard.match_domain(name),
                plain.match_domain(name),
                "the two spellings must agree about {name}"
            );
        }
    }

    #[test]
    fn a_partial_label_wildcard_is_not_a_dns_rule() {
        // `*ad.example` matches half a label, which a suffix matcher cannot express. Turning it into
        // a whole-domain block would block `ad.example` and `bad.example` and, worse, everything under
        // them — so it stays with the network layer, which can match it exactly.
        for line in ["*ad.example", "a*.example", "*", "*.", "*.bad/example"] {
            let f = filter(&format!("{line}\n"));
            assert_eq!(
                f.stats().block_rules,
                0,
                "{line} must not become a DNS-layer rule"
            );
            assert_eq!(
                f.match_domain("ad.example"),
                Verdict::Allow,
                "{line} must not block a domain at the DNS layer"
            );
        }
    }

    #[test]
    fn a_wildcard_exception_and_a_wildcard_important_behave_like_their_plain_forms() {
        let f = filter("*.blocked.example\n@@*.blocked.example\n*.kept.example\n@@*.kept.example\n*.kept.example^$important\n");
        assert_eq!(f.match_domain("a.blocked.example"), Verdict::Allow);
        assert_eq!(
            f.match_domain("a.kept.example"),
            Verdict::Block,
            "`$important` must still beat an exception"
        );
    }

    #[test]
    fn a_wildcard_rule_with_a_scope_modifier_stays_out_of_the_dns_layer() {
        // `*.a.example^$third-party` only forbids part of the traffic; blocking the whole domain would
        // break the site in a way the list author never asked for. Same rule as for `||a.example^`.
        let f = filter("*.scoped.example^$third-party\n");
        assert_eq!(f.stats().block_rules, 0);
        assert_eq!(f.match_domain("a.scoped.example"), Verdict::Allow);
    }

    #[test]
    fn a_wildcard_rule_is_classified_as_a_dns_rule() {
        // The coverage report reads this, so the classification and the compiled filter cannot
        // disagree about what a `*.domain` line is.
        assert_eq!(classify_line("*.oisd.example"), LineClass::Domain);
        assert_eq!(classify_line("*.oisd.example^"), LineClass::Domain);
        assert_eq!(classify_line("@@*.oisd.example"), LineClass::Domain);
        // Not a rule the DNS layer can express, so it must not be classified as one.
        assert_ne!(classify_line("*ad.example"), LineClass::Domain);
    }
}
