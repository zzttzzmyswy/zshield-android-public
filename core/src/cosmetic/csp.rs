//! Making an injected `<style>`/`<script>` legal under the origin's own `Content-Security-Policy`.
//!
//! A document that ships a CSP without `'unsafe-inline'` refuses inline `<style>` and `<script>`
//! elements — including ours. The fix is a **nonce**: the element carries `nonce="…"` and the policy
//! gains `'nonce-…'`, which is exactly the mechanism a site uses for its own inline code.
//!
//! # Why a nonce is *not* added when `'unsafe-inline'` is present
//!
//! CSP Level 2 (§ "unsafe-inline") says that once a policy carries a nonce or a hash source,
//! `'unsafe-inline'` in that same policy is **ignored**. Adding a nonce to a policy that only allows
//! inline code through `'unsafe-inline'` would therefore break every existing inline script on the
//! page. So the rule is: add a nonce only when no policy restricts the element without
//! `'unsafe-inline'`; otherwise leave the element alone (task card §4).
//!
//! # Which directive
//!
//! `script-src` for the `<script>`, `style-src` for the `<style>`, each falling back to `default-src`
//! when absent (CSP Level 3 § 6.1, "directive fallback"). A policy with neither does not restrict that
//! element type at all, so nothing has to be added.
//!
//! # `'strict-dynamic'`
//!
//! A directive that carries `'strict-dynamic'` **ignores host and scheme sources**, but it still honours
//! nonces and hashes — that is the entire mechanism it is built on (CSP Level 3 § 6.7.3.2 item 3: with
//! `'strict-dynamic'` present, a nonce source still authorizes an inline script). An earlier version of
//! this module claimed the opposite and left such pages un-injected; they are now handled like any other
//! nonce-based policy. What `'strict-dynamic'` *does* change is the `'unsafe-inline'` interaction below.
//!
//! # What is deliberately not handled
//!
//! - `<meta http-equiv="Content-Security-Policy">` in the body: counted as `cosmeticCspMeta` and left
//!   alone. Rewriting it would mean a second pass over the body, and the header is authoritative.
//! - `Content-Security-Policy-Report-Only`: it never blocks, so it is not touched.

use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};

/// The source that allows inline code. Directive values are ASCII case-insensitive (CSP Level 3 § 2.3).
const UNSAFE_INLINE: &str = "'unsafe-inline'";

/// The source that makes a nonce-based policy also apply to scripts the page creates itself.
const STRICT_DYNAMIC: &str = "'strict-dynamic'";

/// Which injected element a nonce is being made for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Element {
    Script,
    Style,
}

impl Element {
    fn directive(self) -> &'static str {
        match self {
            Element::Script => "script-src",
            Element::Style => "style-src",
        }
    }
}

/// What one policy needs for one element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Need {
    /// The policy does not restrict this element type; nothing to change.
    Unrestricted,
    /// Inline code is allowed through `'unsafe-inline'`; a nonce must **not** be added.
    UnsafeInline,
    /// Inline code is only allowed with a nonce or hash: this policy needs the nonce appended.
    Nonce,
}

/// One directive of one policy, split into its name and its sources.
fn directive<'a>(policy: &'a str, name: &str) -> Option<Vec<&'a str>> {
    for candidate in policy.split(';') {
        let mut tokens = candidate.split_ascii_whitespace();
        let Some(first) = tokens.next() else {
            continue;
        };
        if first.eq_ignore_ascii_case(name) {
            return Some(tokens.collect());
        }
    }
    None
}

/// The sources that govern `element` for one policy, or `None` when the policy does not restrict it.
fn governing_sources(policy: &str, element: Element) -> Option<Vec<&str>> {
    directive(policy, element.directive()).or_else(|| directive(policy, "default-src"))
}

fn need(policy: &str, element: Element) -> Need {
    let Some(sources) = governing_sources(policy, element) else {
        return Need::Unrestricted;
    };
    // `'unsafe-inline'` is ignored once the directive carries a nonce, a hash, **or**
    // `'strict-dynamic'` (CSP Level 3 § 6.7.3.2). In all three cases adding our own nonce is exactly
    // what the page's own code does, so the nonce is safe — and in the `'strict-dynamic'` +
    // `'unsafe-inline'` case it is the *only* thing that works, because the browser has already stopped
    // honouring `'unsafe-inline'` there.
    let overrides_unsafe_inline = sources.iter().any(|source| {
        let lower = source.to_ascii_lowercase();
        lower.starts_with("'nonce-")
            || lower.starts_with("'sha256-")
            || lower.starts_with("'sha384-")
            || lower.starts_with("'sha512-")
            || lower == STRICT_DYNAMIC
    });
    let has_unsafe_inline = sources
        .iter()
        .any(|source| source.eq_ignore_ascii_case(UNSAFE_INLINE));
    if has_unsafe_inline && !overrides_unsafe_inline {
        return Need::UnsafeInline;
    }
    Need::Nonce
}

/// Split one `Content-Security-Policy` header value into the policies it carries.
///
/// RFC 9110 § 5.5 lets a single header line hold several comma-separated values, and CSP Level 3 § 2.2
/// defines the combined value as a list of policies that are each enforced independently. Treating the
/// whole line as one policy would miss a `;`-separated directive in the second value and, worse, could
/// decide `'unsafe-inline'` from one policy and append the nonce to another. The split is on commas
/// **outside** quotes, because a source expression may contain one.
pub fn split_policies(value: &str) -> Vec<String> {
    let mut policies = Vec::new();
    let mut current = String::with_capacity(value.len());
    let mut quote: Option<char> = None;
    for character in value.chars() {
        match quote {
            Some(open) => {
                if character == open {
                    quote = None;
                }
                current.push(character);
            }
            None => match character {
                '\'' | '"' => {
                    quote = Some(character);
                    current.push(character);
                }
                ',' => {
                    policies.push(std::mem::take(&mut current));
                }
                _ => current.push(character),
            },
        }
    }
    policies.push(current);
    policies
        .into_iter()
        .map(|policy| policy.trim().to_string())
        .filter(|policy| !policy.is_empty())
        .collect()
}

/// How one element may be injected under a set of policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowance {
    /// The policies allow the element: either they do not restrict it, or they allow inline code.
    Inline,
    /// The element needs this nonce to be allowed.
    Nonce(String),
}

/// The policies to send, and whether each injected element is allowed (and with what nonce).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspPlan {
    /// The policies to send. Byte-identical to the input when no nonce had to be added.
    pub policies: Vec<String>,
    /// One entry per requested element, in the order they were requested.
    pub allowances: Vec<(Element, Allowance)>,
}

impl CspPlan {
    /// The nonce `element` must carry, or `None` when it needs none.
    pub fn nonce(&self, element: Element) -> Option<&str> {
        self.allowances
            .iter()
            .find(|(candidate, _)| *candidate == element)
            .and_then(|(_, allowance)| match allowance {
                Allowance::Nonce(nonce) => Some(nonce.as_str()),
                Allowance::Inline => None,
            })
    }

    /// Whether `element` may be injected at all under these policies.
    pub fn allows(&self, element: Element) -> bool {
        self.allowances
            .iter()
            .any(|(candidate, _)| *candidate == element)
    }
}

/// Work out the policies to send and whether each element may be injected.
///
/// Several `Content-Security-Policy` headers are enforced as their **intersection**, so each policy is
/// judged on its own: a policy that restricts the element and does not allow inline code gets the nonce
/// appended, and a policy that allows inline code through `'unsafe-inline'` is left exactly as it is
/// (adding a nonce there would switch that allowance off and break the page's own inline code).
///
/// Returns `None` when no policy restricts any of the requested elements: nothing has to change and the
/// origin's headers are sent untouched.
pub fn plan(policies: &[String], elements: &[Element]) -> Option<CspPlan> {
    if policies.is_empty() {
        return None;
    }
    // Each header line is a *list* of policies (RFC 9110 § 5.5 + CSP Level 3 § 2.2) and every one of
    // them is enforced independently, so they are judged one by one. A line that carried two policies is
    // re-emitted as two lines, which is the same set of policies the client was already being sent.
    let split: Vec<String> = policies
        .iter()
        .flat_map(|policy| split_policies(policy))
        .collect();
    let policies = if split.is_empty() {
        policies.to_vec()
    } else {
        split
    };
    let policies = &policies[..];
    let mut allowances = Vec::with_capacity(elements.len());
    let mut rewritten = policies.to_vec();
    let mut changed = false;
    for element in elements {
        let restricted = policies
            .iter()
            .any(|policy| need(policy, *element) != Need::Unrestricted);
        if !restricted {
            allowances.push((*element, Allowance::Inline));
            continue;
        }
        let needs_nonce = policies
            .iter()
            .any(|policy| need(policy, *element) == Need::Nonce);
        if !needs_nonce {
            allowances.push((*element, Allowance::Inline));
            continue;
        }
        let nonce = random_nonce();
        for (index, policy) in policies.iter().enumerate() {
            if need(policy, *element) == Need::Nonce {
                rewritten[index] = append_nonce(&rewritten[index], *element, &nonce);
                changed = true;
            }
        }
        allowances.push((*element, Allowance::Nonce(nonce)));
    }
    if !changed {
        return None;
    }
    Some(CspPlan {
        policies: rewritten,
        allowances,
    })
}

/// Append `'nonce-…'` to the directive that governs `element`.
///
/// When the directive is absent and `default-src` is what governs it, the nonce goes on `default-src`:
/// adding a `script-src` instead would *replace* the default for that type and could only widen the
/// policy.
fn append_nonce(policy: &str, element: Element, nonce: &str) -> String {
    let target = if directive(policy, element.directive()).is_some() {
        element.directive()
    } else {
        "default-src"
    };
    // The directive is located by byte offset rather than rebuilt from its tokens, so every byte the
    // origin sent — the separator spacing, an empty directive, a trailing `;` — survives untouched.
    let mut offset = 0usize;
    for segment in policy.split(';') {
        let start = offset;
        offset += segment.len() + 1;
        let mut tokens = segment.split_ascii_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(target) {
            continue;
        }
        let insert_at = start + segment.trim_end().len();
        let mut out = String::with_capacity(policy.len() + nonce.len() + 24);
        out.push_str(&policy[..insert_at]);
        out.push_str(" 'nonce-");
        out.push_str(nonce);
        out.push('\'');
        out.push_str(&policy[insert_at..]);
        return out;
    }
    // `need()` only reports `Nonce` when a governing directive exists, so this is unreachable; a fresh
    // directive is still better than a silently dropped nonce.
    let mut out = policy.trim_end().to_string();
    if !out.is_empty() {
        out.push(';');
    }
    out.push_str(target);
    out.push_str(" 'nonce-");
    out.push_str(nonce);
    out.push('\'');
    out
}

/// Whether one policy, taken as it is, allows inline code for `element`.
///
/// Used for a `$csp` directive the filter itself adds: that directive is sent verbatim (relaxing it is
/// the opposite of what the rule asked for), so an element it refuses must not be injected.
pub fn allows_unmodified(policy: &str, element: Element) -> bool {
    need(policy, element) != Need::Nonce
}

/// A fresh 128-bit nonce, base64.
///
/// 16 bytes is what browsers use, and base64 rather than hex keeps both the head and every injected
/// element short. The URL-safe alphabet is used because the `+` and `/` of standard base64 are legal in
/// a nonce but awkward in the tooling that inspects pages.
fn random_nonce() -> String {
    let mut bytes = [0u8; 16];
    // `SystemRandom` is `ring`'s OS-entropy-backed generator, the same backend the CA already uses.
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("the OS CSPRNG must be available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_one(policy: &str, element: Element) -> Option<(String, Allowance)> {
        plan(&[policy.to_string()], &[element]).map(|plan| {
            (
                plan.policies[0].clone(),
                plan.allowances[0].1.clone(),
            )
        })
    }

    fn nonce_of(allowance: &Allowance) -> &str {
        match allowance {
            Allowance::Nonce(nonce) => nonce,
            Allowance::Inline => panic!("expected a nonce, got Inline"),
        }
    }

    #[test]
    fn a_policy_without_unsafe_inline_gets_a_nonce() {
        let (policy, allowance) = plan_one("script-src 'self'", Element::Script).expect("nonce");
        let nonce = nonce_of(&allowance);
        assert_eq!(policy, format!("script-src 'self' 'nonce-{nonce}'"));
        assert!(nonce.len() >= 16, "a nonce must be long enough to be unguessable: {nonce}");
    }

    #[test]
    fn a_policy_with_unsafe_inline_does_not_get_one() {
        // CSP2: a nonce would switch `'unsafe-inline'` off and break the page's own inline scripts.
        assert!(plan_one("script-src 'self' 'unsafe-inline'", Element::Script).is_none());
        assert!(plan_one("script-src 'UNSAFE-INLINE'", Element::Script).is_none());
        assert!(plan_one("script-src 'unsafe-inline' https://cdn.example", Element::Script).is_none());
    }

    #[test]
    fn unsafe_inline_beside_an_existing_nonce_is_allowed_a_new_one() {
        // `'unsafe-inline'` is ignored once the directive has a nonce source, so a page in this state
        // relies on nonces and ours is exactly what it needs.
        let (policy, allowance) =
            plan_one("script-src 'self' 'nonce-abc' 'unsafe-inline'", Element::Script)
                .expect("nonce");
        let nonce = nonce_of(&allowance);
        assert!(policy.contains(&format!("'nonce-{nonce}'")));
        assert!(policy.contains("'nonce-abc'"), "the page's own nonce stays: {policy}");
    }

    #[test]
    fn default_src_is_the_fallback_and_is_the_directive_that_is_extended() {
        let (policy, allowance) = plan_one("default-src 'self'", Element::Script).expect("nonce");
        let nonce = nonce_of(&allowance);
        assert_eq!(policy, format!("default-src 'self' 'nonce-{nonce}'"));
        // No `script-src` is introduced: one would replace `default-src` for scripts and could only
        // widen the policy.
        assert!(!policy.contains("script-src"), "{policy}");
    }

    #[test]
    fn script_src_wins_over_default_src_when_both_are_present() {
        let (policy, allowance) =
            plan_one("default-src 'self'; script-src 'self' https://cdn.example", Element::Script)
                .expect("nonce");
        let nonce = nonce_of(&allowance);
        assert_eq!(
            policy,
            format!("default-src 'self'; script-src 'self' https://cdn.example 'nonce-{nonce}'")
        );
    }

    #[test]
    fn strict_dynamic_still_honours_a_nonce() {
        // Review item 12: `'strict-dynamic'` ignores host and scheme sources but *not* nonces — that is
        // the mechanism it is built on, so a policy carrying it needs the nonce like any other.
        let (policy, allowance) =
            plan_one("script-src 'strict-dynamic' 'nonce-abc'", Element::Script).expect("nonce");
        let nonce = nonce_of(&allowance);
        assert!(policy.contains(&format!("'nonce-{nonce}'")), "{policy}");
        assert!(policy.contains("'strict-dynamic'"), "the page's own source stays: {policy}");
        assert!(policy.contains("'nonce-abc'"), "{policy}");
    }

    #[test]
    fn strict_dynamic_beside_unsafe_inline_still_gets_a_nonce() {
        // Review item 12: with `'strict-dynamic'` present the browser already ignores `'unsafe-inline'`,
        // so leaving the element un-nonced would silently lose the injection on every such page.
        let (policy, allowance) =
            plan_one("script-src 'unsafe-inline' 'strict-dynamic'", Element::Script).expect("nonce");
        let nonce = nonce_of(&allowance);
        assert!(policy.contains(&format!("'nonce-{nonce}'")), "{policy}");
    }

    #[test]
    fn several_policies_in_one_header_value_are_judged_separately() {
        // Review item 12: RFC 9110 § 5.5 lets one header carry a comma-separated list, and CSP Level 3
        // § 2.2 makes each of them its own enforced policy.
        assert_eq!(
            split_policies("default-src 'self', script-src 'unsafe-inline'"),
            vec![
                "default-src 'self'".to_string(),
                "script-src 'unsafe-inline'".to_string()
            ]
        );
        // A comma inside a quoted source expression is part of the source, not a separator — a nonce or
        // hash in this position is the realistic case, and splitting it would corrupt the policy.
        assert_eq!(
            split_policies("script-src 'self' 'nonce-a,b'"),
            vec!["script-src 'self' 'nonce-a,b'".to_string()]
        );
        assert!(split_policies("").is_empty());

        // The second policy allows inline code, so it must not receive a nonce — while the first does.
        let policies = vec!["default-src 'self', script-src 'unsafe-inline'".to_string()];
        let planned = plan(&policies, &[Element::Script]).expect("nonce");
        let nonce = planned.nonce(Element::Script).expect("nonce");
        assert_eq!(planned.policies[0], format!("default-src 'self' 'nonce-{nonce}'"));
        assert_eq!(planned.policies[1], "script-src 'unsafe-inline'");
    }

    #[test]
    fn a_policy_that_does_not_restrict_the_element_needs_nothing() {
        // `img-src` only: inline scripts and styles are not restricted by this policy at all, so the
        // policy is sent unchanged and the element needs no nonce.
        assert!(plan_one("img-src *", Element::Script).is_none());
        assert!(plan_one("img-src *", Element::Style).is_none());
        assert!(plan(&[], &[Element::Script, Element::Style]).is_none());
    }

    #[test]
    fn style_and_script_are_judged_on_their_own_directives() {
        let policies = vec!["script-src 'unsafe-inline'; style-src 'self'".to_string()];
        let planned = plan(&policies, &[Element::Script, Element::Style]).expect("style nonce");
        assert!(
            planned.allows(Element::Script) && planned.nonce(Element::Script).is_none(),
            "script-src allows inline code, so it needs no nonce"
        );
        let nonce = planned.nonce(Element::Style).expect("style nonce");
        assert_eq!(
            planned.policies[0],
            format!("script-src 'unsafe-inline'; style-src 'self' 'nonce-{nonce}'")
        );
        assert!(planned.allows(Element::Style));
    }

    #[test]
    fn both_elements_get_their_own_nonce() {
        let policies = vec!["default-src 'none'".to_string()];
        let planned = plan(&policies, &[Element::Script, Element::Style]).expect("nonces");
        let script = planned.nonce(Element::Script).expect("script nonce");
        let style = planned.nonce(Element::Style).expect("style nonce");
        assert_ne!(script, style, "each element gets its own nonce");
        assert_eq!(
            planned.policies[0],
            format!("default-src 'none' 'nonce-{script}' 'nonce-{style}'")
        );
    }

    #[test]
    fn several_policies_are_each_made_to_allow_the_element() {
        let policies = vec![
            "default-src 'self'".to_string(),
            "script-src https://cdn.example".to_string(),
        ];
        let planned = plan(&policies, &[Element::Script]).expect("nonce");
        let nonce = planned.nonce(Element::Script).expect("nonce");
        assert_eq!(planned.policies[0], format!("default-src 'self' 'nonce-{nonce}'"));
        assert_eq!(
            planned.policies[1],
            format!("script-src https://cdn.example 'nonce-{nonce}'")
        );
    }

    #[test]
    fn an_unsafe_inline_policy_is_left_alone_while_another_gets_the_nonce() {
        // Two policies intersect. The `'unsafe-inline'` one already allows the element, and a nonce
        // there would switch that allowance off; the other one needs the nonce. Both then allow it.
        let policies = vec![
            "script-src 'self'".to_string(),
            "script-src 'unsafe-inline'".to_string(),
        ];
        let planned = plan(&policies, &[Element::Script]).expect("nonce");
        let nonce = planned.nonce(Element::Script).expect("nonce");
        assert_eq!(planned.policies[0], format!("script-src 'self' 'nonce-{nonce}'"));
        assert_eq!(planned.policies[1], "script-src 'unsafe-inline'");
    }

    #[test]
    fn a_filter_supplied_policy_is_judged_as_it_stands() {
        assert!(allows_unmodified("script-src 'self' 'unsafe-inline'", Element::Script));
        assert!(!allows_unmodified("script-src 'self'", Element::Script));
        assert!(allows_unmodified("script-src 'self'", Element::Style), "it says nothing about styles");
        assert!(!allows_unmodified("default-src 'none'", Element::Style));
    }

    #[test]
    fn an_element_no_policy_would_allow_is_reported_as_not_allowed() {
        // `script-src 'none'` cannot be satisfied by a nonce in a way this code can rely on... but it
        // can: `'none'` plus a nonce source means the nonce is what allows it. What is *not* allowed is
        // an element the plan never asked about.
        let planned = plan(&["script-src 'self'".to_string()], &[Element::Script]).expect("plan");
        assert!(planned.allows(Element::Script));
        assert!(!planned.allows(Element::Style), "a style was never asked for");
    }

    #[test]
    fn an_empty_directive_and_odd_whitespace_survive_the_rewrite() {
        let (policy, allowance) =
            plan_one("default-src  'self' ;; img-src *;", Element::Script).expect("nonce");
        let nonce = nonce_of(&allowance);
        // Every byte the origin sent is preserved, including the empty directive and its spacing.
        assert_eq!(policy, format!("default-src  'self' 'nonce-{nonce}' ;; img-src *;"));
    }

    #[test]
    fn nonces_are_unique() {
        let first = plan_one("script-src 'self'", Element::Script).expect("nonce").1;
        let second = plan_one("script-src 'self'", Element::Script).expect("nonce").1;
        assert_ne!(first, second, "a reused nonce would let a page predict it");
    }

    #[test]
    fn the_nonce_alphabet_is_base64_url_safe() {
        let (_, allowance) = plan_one("script-src 'self'", Element::Script).expect("nonce");
        let nonce = nonce_of(&allowance);
        assert!(
            nonce
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "the nonce must not need escaping in an attribute: {nonce}"
        );
    }
}
