//! Telling a browser-parseable CSS selector from one that is not, before it reaches a `<style>`.
//!
//! # Why this exists
//!
//! A `<style>` element is a **rule list**, and the CSS error-handling rules are blunt: a selector
//! list is discarded as a whole when any one of its members fails to parse (CSS Syntax § "consume a
//! list of rules"). M5a measured the consequence on a real page: 15 procedural selectors
//! (`:has-text()`, `:upward()`, `:xpath()`, …) sat in the same comma-separated rule as 28 valid ones,
//! the browser threw the rule away, and every element-hiding case on the page failed — including
//! ones whose selectors were perfectly fine (`docs/EFFECTIVENESS.md` §9.3.3).
//!
//! Two changes remove that failure mode:
//!
//! 1. `core/Cargo.toml` enables adblock's `css-validation` feature, so the engine splits procedural
//!    operators out of the plain-CSS channel instead of leaking them into it, and drops selectors its
//!    own grammar rejects. That is what makes a procedural rule become a *script* rather than a bad
//!    selector (see [`crate::cosmetic::procedural`]).
//! 2. Everything that still reaches this module is checked here, and a selector that fails is dropped
//!    **individually** and counted, so the loss is one hide rule and never a rule list.
//!
//! # How a selector is checked
//!
//! Not with a hand-written grammar: a table of "which pseudo-classes exist" rots the first time a
//! browser ships one, and a false rejection silently stops hiding ads. The selector is fed back
//! through the engine's own parser (`adblock::lists::parse_filter`, the same `cssparser`/`selectors`
//! grammar a browser implements) as a cosmetic rule on a domain that cannot occur, and the question
//! asked is only "did it parse". That is the same answer the compile step relies on, so the two
//! cannot disagree.
//!
//! The cost is ~6 µs per selector (measured on the host), and a document carries hundreds of them —
//! so the answers are cached. Within one browser session the same subscription set produces the same
//! selectors on every page, which makes the cache hit rate close to 100% after the first page.

use std::collections::HashMap;
use std::sync::Mutex;

/// How many verdicts the cache holds before it is dropped wholesale.
///
/// A filter list has tens of thousands of distinct selectors in total, but one document sees a few
/// hundred, so this holds every selector seen on the order of a hundred pages. Dropping the whole map
/// at the bound costs one re-validation pass and keeps the structure bounded without an LRU's
/// bookkeeping — this is not a hot enough path to be worth the bookkeeping.
const CACHE_CAPACITY: usize = 8192;

/// The domain prefix the probe rules are written on. It never has to resolve: only the selector side
/// of the rule is parsed.
const PROBE_DOMAIN: &str = "zshield-selector-probe.invalid";

/// What a selector screen concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A browser will parse it, so it may go into a rule list.
    Usable,
    /// A browser will reject it; putting it in a rule list would take its neighbours down with it.
    Unparseable,
}

impl Verdict {
    pub fn is_usable(self) -> bool {
        self == Verdict::Usable
    }
}

/// A cache of selector verdicts, shared by every document this process injects into.
#[derive(Debug, Default)]
pub struct SelectorValidator {
    verdicts: Mutex<HashMap<String, bool>>,
}

impl SelectorValidator {
    pub fn new() -> Self {
        Self::default()
    }

    /// The verdict for one selector, computed once and remembered.
    pub fn check(&self, selector: &str) -> Verdict {
        let selector = selector.trim();
        if selector.is_empty() {
            return Verdict::Unparseable;
        }
        {
            let cache = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(usable) = cache.get(selector) {
                return if *usable {
                    Verdict::Usable
                } else {
                    Verdict::Unparseable
                };
            }
        }
        let usable = parse_as_cosmetic(selector);
        let mut cache = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
        // `clear` rather than evict-one: see `CACHE_CAPACITY`.
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(selector.to_string(), usable);
        if usable {
            Verdict::Usable
        } else {
            Verdict::Unparseable
        }
    }

    /// Keep only the selectors that passed, in order, and report how many were dropped.
    ///
    /// The first value is `(selector, verdict)` pairs so a caller that wants to report *why* a rule
    /// was lost can; the count is what the statistics use.
    pub fn partition<'a>(&self, selectors: &'a [String]) -> (Vec<&'a str>, usize) {
        let mut usable = Vec::with_capacity(selectors.len());
        let mut dropped = 0usize;
        for selector in selectors {
            match self.check(selector) {
                Verdict::Usable => usable.push(selector.trim()),
                Verdict::Unparseable => dropped += 1,
            }
        }
        (usable, dropped)
    }
}

/// Whether a browser would parse `selector` on its own.
///
/// Written as a cosmetic rule on a synthetic domain and handed to the engine's parser: a selector the
/// grammar rejects comes back as [`adblock::lists::FilterParseError::CosmeticFilterError`]. A rule that
/// parses as anything *other* than cosmetic (a network rule, say) means the selector contained syntax
/// that changed the rule's meaning — `##^` HTML filtering, for instance — and is refused too, because
/// what would be emitted is no longer the selector the list asked for.
fn parse_as_cosmetic(selector: &str) -> bool {
    use adblock::lists::{parse_filter, ParseOptions, ParsedLine};
    // A newline would end the rule early and make the rest of the selector a second line; a `$` before
    // the separator would be read as an option. Neither can appear in a selector that is safe to emit,
    // and both are cheaper to refuse here than to reason about later.
    if selector.contains(['\n', '\r']) {
        return false;
    }
    let line = format!("{PROBE_DOMAIN}##{selector}");
    match parse_filter(&line, false, ParseOptions::default()) {
        Ok(ParsedLine::Cosmetic(filter)) => {
            // The rule must have come back as exactly this selector. `css-validation` canonicalizes
            // some forms (`:-abp-has` → `:has`), so a *different* string is still fine as long as it
            // is a single plain CSS selector; a non-CSS operator means the selector was procedural,
            // which is not something this module's caller may emit as CSS.
            filter.selector.len() == 1
                && matches!(
                    filter.selector[0],
                    adblock::filters::cosmetic::CosmeticFilterOperator::CssSelector(_)
                )
                && filter.action.is_none()
        }
        Ok(ParsedLine::Network(_)) | Err(_) => false,
    }
}

/// The process-wide cache every document shares.
///
/// One cache rather than one per document: the verdict for a selector does not depend on the page, and a
/// subscription set produces the same selectors on every page — so a shared cache turns the ~6 µs
/// check into one hash lookup after the first page. `OnceLock` because the first caller may be any of
/// several forwarding tasks.
pub fn shared() -> &'static SelectorValidator {
    static SHARED: std::sync::OnceLock<SelectorValidator> = std::sync::OnceLock::new();
    SHARED.get_or_init(SelectorValidator::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usable(selector: &str) -> bool {
        SelectorValidator::new().check(selector).is_usable()
    }

    #[test]
    fn ordinary_selectors_pass() {
        for selector in [
            ".ad-banner",
            "#case-1-elemhide > .test-banner",
            "div[data-ad]",
            "a[class][href^=\"https://example.com/\"]",
            "li:nth-child(2n+1)",
            "p:not(.keep)",
            ":is(.a, .b)",
            "div:has(a.banner-link)",
            "div > span + em ~ b",
        ] {
            assert!(usable(selector), "{selector} must be usable");
        }
    }

    #[test]
    fn procedural_operators_are_not_css() {
        // These are the exact forms M5a found in a `<style>` on a real page (§9.3.3). They are legal
        // filter-list syntax and legal *procedural* syntax, and every one of them is a parse error to
        // a CSS parser — which is why they must never share a rule list with a plain selector.
        for selector in [
            "div:has-text(Sponsored)",
            ".x:upward(2)",
            ".x:matches-css(display:block)",
            ".x:xpath(//div)",
            "div:contains(Refresh)",
            ".x:min-text-length(20)",
            ".x:matches-attr(data-ad)",
        ] {
            assert!(!usable(selector), "{selector} must not be emitted as CSS");
        }
    }

    #[test]
    fn a_broken_selector_is_refused_rather_than_repaired() {
        for selector in [
            "div >> span",
            ".unclosed[",
            "div::",
            "",
            "   ",
            ".a\nbody{display:none}",
        ] {
            assert!(!usable(selector), "{selector:?} must be refused");
        }
    }

    #[test]
    fn the_partition_keeps_order_and_counts_the_losses() {
        let selectors: Vec<String> = vec![
            ".good-one".into(),
            "div:has-text(Sponsored)".into(),
            ".good-two".into(),
            "div >> span".into(),
            ".good-three".into(),
        ];
        let validator = SelectorValidator::new();
        let (kept, dropped) = validator.partition(&selectors);
        assert_eq!(kept, vec![".good-one", ".good-two", ".good-three"]);
        assert_eq!(dropped, 2);
        // The second pass is answered from the cache and must agree.
        assert_eq!(validator.partition(&selectors), (kept, dropped));
    }

    #[test]
    fn one_bad_selector_costs_only_itself() {
        // The defect this module exists for, stated as a property: the survivors are the selectors
        // that parse, *all* of them, regardless of what else was in the list.
        let mut selectors: Vec<String> = (0..30).map(|i| format!(".ad-{i}")).collect();
        selectors.insert(7, "div:has-text(Sponsored)".to_string());
        selectors.insert(0, ".x:upward(1)".to_string());
        let (kept, dropped) = SelectorValidator::new().partition(&selectors);
        assert_eq!(dropped, 2);
        assert_eq!(kept.len(), 30);
    }
}
