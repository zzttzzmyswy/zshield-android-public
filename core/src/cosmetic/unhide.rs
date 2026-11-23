//! Global cosmetic unhide rules — `#@#` and `*#@#` — which the pinned engine silently discards.
//!
//! `docs/EFFECTIVENESS.md` §10.5 item 1 records the symptom: the element-hiding test page's case 3
//! keeps `.test-banner` visible even though `testcases.agrd.dev,pages.dev#@##case-3-…> .test-banner`
//! is installed, while `h1`/`h2`/`h3` next to it are hidden. That reading was incomplete — the
//! `h1`/`h2`/`h3` cases fail too, for a different reason.
//!
//! # What the engine actually does
//!
//! adblock 0.13.5 parses three spellings of "unhide this selector everywhere":
//!
//! | spelling | engine result |
//! |---|---|
//! | `#@#.cls` (empty location list) | `CosmeticFilterError::GenericUnhide` — **the rule is dropped** |
//! | `*#@#.cls` (a location of `*`) | parsed, but the location hashes to nothing real, so **it never matches** |
//! | `site.example#@#.cls` | works: `hide_selectors.remove(selector)` + `exceptions.insert(selector)` |
//!
//! Measured on 0.13.5 (`core/examples/probe_global_unhide.rs`), against the element-hiding page:
//! `testcases.agrd.dev###case-x > h1` plus `*#@#`/`#@#` leaves `#case-x > h1` in `hide_selectors`; the
//! same rule with `site.example#@#` removes it. So a *global* unhide — one with no hostname, or with a
//! `*` hostname — is the one form the engine cannot express, and it is the form uBO/AdGuard lists use
//! for "this class is not an ad anywhere".
//!
//! # What this module does
//!
//! It collects those two forms and applies them itself, on top of the engine's answer: any selector a
//! global unhide names is removed from `hide_selectors`, from the generic query's result, and added to
//! `exceptions` so the class-id query cannot reintroduce it. The engine keeps doing everything else.
//!
//! The alternative — rewriting the line into a per-hostname unhide for every hostname in the list —
//! would change what the rule means (it must apply on *every* site, including ones the list never
//! names) and would multiply one rule into thousands.

/// One `#@#` / `*#@#` rule, kept as the selector it unhides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalUnhide {
    /// The rule as the list wrote it, for the diagnostics.
    pub text: String,
    /// The CSS selector the rule un-hides, verbatim after the `#@#` marker.
    pub selector: String,
}

/// Every global unhide rule in force.
#[derive(Default, Debug, Clone)]
pub struct GlobalUnhides {
    rules: Vec<GlobalUnhide>,
}

impl GlobalUnhides {
    /// Add one list body.
    ///
    /// Only the two forms the engine cannot express are collected. A rule with a real hostname list is
    /// left to the engine: it already removes the selector and records the exception, and taking it
    /// over here as well would unhide it on sites the rule does not name.
    pub fn add_list(&mut self, text: &str) {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('[') {
                continue;
            }
            let Some((locations, selector)) = split_cosmetic(trimmed) else {
                continue;
            };
            if !is_global(locations) {
                continue;
            }
            if selector.is_empty() || self.rules.iter().any(|rule| rule.selector == selector) {
                continue;
            }
            self.rules.push(GlobalUnhide {
                text: trimmed.to_string(),
                selector: selector.to_string(),
            });
        }
    }

    /// Remove every globally-unhidden selector from `selectors`.
    ///
    /// Returns how many were removed, so the caller can report it instead of silently filtering less.
    pub fn apply(&self, selectors: &mut Vec<String>) -> usize {
        if self.rules.is_empty() {
            return 0;
        }
        let before = selectors.len();
        selectors.retain(|selector| !self.unhides(selector));
        before - selectors.len()
    }

    /// Whether a global unhide names this selector.
    ///
    /// Compared after trimming only: a filter list writes the selector once and the engine hands the
    /// same text back, so whitespace is the only difference that happens in practice, and a looser
    /// comparison (whitespace-collapsed, case-folded) would start matching selectors the author meant
    /// to keep apart.
    pub fn unhides(&self, selector: &str) -> bool {
        let selector = selector.trim();
        self.rules.iter().any(|rule| rule.selector == selector)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[GlobalUnhide] {
        &self.rules
    }

    /// The original rule lines, for `extras.txt`.
    pub fn lines(&self) -> impl Iterator<Item = &String> {
        self.rules.iter().map(|rule| &rule.text)
    }
}

/// Split a cosmetic rule into its location list and its selector, if it is an *unhide* rule.
///
/// Returns `None` for hide rules, scriptlets, action rules (`:style()`, `:remove()`), HTML filters
/// (`##^`) and anything else this module has no business touching. The marker forms are the ABP/uBO
/// `#@#` and its AdGuard extended-CSS twin `#@?#`; `#@$#`/`#@%#` are separate families.
fn split_cosmetic(line: &str) -> Option<(&str, &str)> {
    let marker = line.find("#@#")?;
    let locations = &line[..marker];
    let selector = &line[marker + 3..];
    // `#@?#` (extended CSS) is a different rule family: its selector is a procedural expression, not
    // a plain CSS selector, and removing it by text would not make the engine stop applying it.
    if selector.starts_with('?') || selector.starts_with('$') || selector.starts_with('%') {
        return None;
    }
    // `^` is AdGuard's HTML filtering marker; `+js(...)` is a scriptlet.
    if selector.starts_with('^') || selector.starts_with("+js(") {
        return None;
    }
    Some((locations, selector.trim()))
}

/// Whether a location list names every site.
///
/// `""` is the bare `#@#` form; a list of only `*` entries is the `*#@#` form. Anything with a real
/// hostname is the engine's job.
fn is_global(locations: &str) -> bool {
    locations
        .split(',')
        .map(str::trim)
        .filter(|location| !location.is_empty())
        .all(|location| location == "*")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(rules: &str) -> GlobalUnhides {
        let mut set = GlobalUnhides::default();
        set.add_list(rules);
        set
    }

    #[test]
    fn a_bare_hash_at_hash_is_a_global_unhide() {
        let rules = collect("#@##case-3-elemhide-exception > h2\n");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules.rules()[0].selector,
            "#case-3-elemhide-exception > h2"
        );
        assert!(rules.unhides("#case-3-elemhide-exception > h2"));
    }

    #[test]
    fn a_star_hostname_is_a_global_unhide() {
        // The element-hiding companion list's case-3 wildcard exception, verbatim.
        let rules = collect("*#@##case-3-elemhide-exception > h1\n");
        assert_eq!(rules.len(), 1);
        assert!(rules.unhides("#case-3-elemhide-exception > h1"));
    }

    #[test]
    fn a_list_of_stars_is_still_global() {
        // Two `*` entries do not make the rule site-specific.
        let rules = collect("*#@#.ad\n");
        assert_eq!(rules.len(), 1);
        let mut selectors = vec![".ad".to_string(), ".kept".to_string()];
        assert_eq!(rules.apply(&mut selectors), 1);
        assert_eq!(selectors, vec![".kept".to_string()]);
    }

    #[test]
    fn a_mixed_list_with_one_real_hostname_is_not_global() {
        // `site.example,*#@#.ad` names one site and a wildcard; adblock treats the `*` as a location
        // and the real hostname as another, so the rule is site-scoped and must be left to it.
        let rules = collect("site.example,*#@#.ad\n");
        assert!(rules.is_empty());
    }

    #[test]
    fn a_hostname_scoped_unhide_is_left_to_the_engine() {
        // `testcases.agrd.dev,pages.dev#@#…` is a form adblock 0.13.5 handles correctly: it removes the
        // selector and records the exception. Taking it over here would unhide the selector on every
        // *other* site too, which is the opposite of what the rule says.
        let rules = collect("testcases.agrd.dev,pages.dev#@##case-3-elemhide-exception > .test-banner\n");
        assert!(rules.is_empty());
    }

    #[test]
    fn a_negated_location_is_not_global() {
        let rules = collect("~site.example#@#.ad\n");
        assert!(rules.is_empty());
    }

    #[test]
    fn hide_rules_and_scriptlets_are_not_collected() {
        let rules = collect(
            "###case-2-generic-elemhide > .test-banner\n\
             site.example#@#.kept\n\
             site.example##+js(set-constant, a, b)\n\
             site.example#@#+js(set-constant, a, b)\n\
             site.example#@?#div:has-text(x)\n\
             site.example#@#^script:has-text(x)\n",
        );
        assert!(rules.is_empty(), "{:?}", rules.rules());
    }

    #[test]
    fn applying_removes_the_selector_from_the_hide_list() {
        let rules = collect("*#@##case-3-elemhide-exception > h1\n");
        let mut selectors = vec![
            "#case-1-elemhide > .test-banner".to_string(),
            "#case-3-elemhide-exception > h1".to_string(),
        ];
        assert_eq!(rules.apply(&mut selectors), 1);
        assert_eq!(selectors, vec!["#case-1-elemhide > .test-banner".to_string()]);
    }

    #[test]
    fn a_duplicate_rule_is_kept_once() {
        let rules = collect("*#@#.ad\n#@#.ad\n");
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn surrounding_whitespace_does_not_defeat_the_match() {
        let rules = collect("#@#  .ad  \n");
        assert!(rules.unhides(".ad"));
        assert!(rules.unhides("  .ad  "));
    }
}
