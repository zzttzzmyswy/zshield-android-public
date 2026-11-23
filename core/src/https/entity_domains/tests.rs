//! Tests for `$domain=` entity entries (`super`).

use super::*;
use crate::http::head::Version;

fn request_with(url: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
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

fn rules(list: &str) -> EntityDomainRules {
    let mut set = EntityDomainRules::default();
    set.add_list(list);
    set.build();
    set
}

#[test]
fn an_entity_domain_rule_matches_a_host_under_that_entity() {
    // The element-hiding page's case 6, verbatim.
    let set = rules("||*/tld-test-files/$image,domain=testcases.agrd.*|pages.*\n");
    assert_eq!(set.len(), 1);
    let image = request_with(
        "https://testcases.agrd.dev/Filters/element-hiding-rules/tld-test-files/adguard.png",
        Some("https://testcases.agrd.dev/Filters/element-hiding-rules/test-element-hiding-rules.html"),
        RequestKind::Image,
    );
    assert_eq!(set.verdict(&image, RequestKind::Image), Some(true));
}

#[test]
fn an_entity_matches_every_tld_and_every_subdomain() {
    let set = rules("*$script,domain=example.*\n");
    for referer in [
        "https://example.com/",
        "https://example.co.uk/",
        "https://news.example.org/",
        "https://a.b.example.net/",
    ] {
        let probe = request_with(
            "https://cdn.example.net/lib.js",
            Some(referer),
            RequestKind::Script,
        );
        assert_eq!(
            set.verdict(&probe, RequestKind::Script),
            Some(true),
            "referer {referer}"
        );
    }
}

#[test]
fn an_entity_does_not_match_a_lookalike_host() {
    let set = rules("*$script,domain=example.*\n");
    let probe = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://notexample.com/"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&probe, RequestKind::Script), None);
}

#[test]
fn a_request_without_a_referer_is_not_in_any_entity_scope() {
    // No source means the entity is unknown; guessing would put every first navigation at risk, which
    // is the same conservative default the network decision takes for third-partiness.
    let set = rules("*$script,domain=example.*\n");
    let probe = request_with("https://cdn.example.net/lib.js", None, RequestKind::Script);
    assert_eq!(set.verdict(&probe, RequestKind::Script), None);
}

#[test]
fn an_excluded_entity_takes_the_host_back_out_of_scope() {
    let set = rules("*$script,domain=example.*|~private.example.*\n");
    let inside = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://private.example.com/"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&inside, RequestKind::Script), None);
    let outside = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://public.example.com/"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&outside, RequestKind::Script), Some(true));
}

#[test]
fn a_plain_domain_entry_keeps_working_alongside_an_entity_entry() {
    // The engine still enforces `plain.example`; only the entity half is this module's business, and
    // the two must not interfere.
    let set = rules("*$script,domain=plain.example|example.*\n");
    let rule = &set.rules()[0];
    assert_eq!(rule.stripped, "*$script,domain=plain.example");
    assert_eq!(rule.included.len(), 1);
    assert_eq!(rule.included[0].name, "example");

    let plain = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://plain.example/"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&plain, RequestKind::Script), Some(true));
}

#[test]
fn an_entity_only_rule_drops_the_option_and_is_gated_by_the_entity_check() {
    // With the entity removed there is no `$domain=` left. If the stripped rule were trusted on its
    // own it would match every site — the entity gate is what keeps it scoped.
    let set = rules("*$script,domain=example.*\n");
    assert_eq!(set.rules()[0].stripped, "*$script");
    let other = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://unrelated.test/"),
        RequestKind::Script,
    );
    assert_eq!(
        set.verdict(&other, RequestKind::Script),
        None,
        "an entity-scoped rule must not block on another site"
    );
}

#[test]
fn an_exception_rule_puts_the_request_back_in_scope() {
    let set = rules(
        "*$script,domain=example.*\n@@*$script,domain=example.*\n",
    );
    let probe = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://example.com/"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&probe, RequestKind::Script), Some(false));
}

#[test]
fn a_line_without_an_entity_entry_is_ignored() {
    let set = rules(
        "||ads.example^\n\
         *$script,domain=plain.example\n\
         *$script,domain=*|plain.example\n\
         ###ad-banner\n\
         *$third-party\n",
    );
    assert!(set.is_empty(), "{:?}", set.rules());
}

#[test]
fn an_entity_in_a_cosmetic_rule_is_left_to_the_engine() {
    // `testcases.agrd.*##.ad` is a cosmetic rule; adblock handles entity locations on that path
    // correctly (`get_entity_hashes_from_labels`), so it must not be collected here.
    let set = rules("testcases.agrd.*,pages.*###case-1-elemhide > .test-banner\n");
    assert!(set.is_empty());
}

#[test]
fn the_entity_is_the_hostname_without_its_public_suffix() {
    let probe = request_with(
        "https://cdn.example.net/lib.js",
        Some("https://a.b.example.co.uk/"),
        RequestKind::Script,
    );
    assert_eq!(source_entity(&probe).as_deref(), Some("a.b.example"));
}

#[test]
fn an_entity_entry_with_no_dot_star_suffix_is_not_an_entity() {
    // `domain=example` is a plain domain; only the `.*` suffix means entity.
    let set = rules("*$script,domain=example\n");
    assert!(set.is_empty());
}

// -------------------------------------------------------------------------------------------
// Mixed `$domain=` lists (review item 3)
// -------------------------------------------------------------------------------------------

#[test]
fn a_mixed_domain_list_blocks_through_its_entity_half() {
    // Review item 3. The engine keeps `domain=a.com` and matches only sources under it, so without the
    // entity form the `example.*` entry would never fire — and 76 of the 146 entity rules in the five
    // default lists are written this way.
    let set = rules("||x.example^$script,domain=a.com|example.*\n");
    let from_entity = request_with(
        "https://x.example/lib.js",
        Some("https://example.org/page"),
        RequestKind::Script,
    );
    assert_eq!(
        set.verdict(&from_entity, RequestKind::Script),
        Some(true),
        "the entity half of a mixed list must block: {:?}",
        set.rules()
    );

    let from_plain = request_with(
        "https://x.example/lib.js",
        Some("https://a.com/page"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&from_plain, RequestKind::Script), Some(true));

    // Neither entry matches this source, so nothing applies.
    let elsewhere = request_with(
        "https://x.example/lib.js",
        Some("https://other.com/page"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&elsewhere, RequestKind::Script), None);
}

#[test]
fn a_mixed_domain_exception_unblocks_through_its_entity_half() {
    // The `@@` form of the same rule, which the review asked to cover as well. The blocking half lives
    // in the **main** engine (`||ads.example^$script`), so the exception is asked for through
    // `exempts` — the same reason `exempts` exists apart from `verdict`.
    let set = rules("@@||ads.example^$script,domain=a.com|example.*\n");
    for referer in ["https://example.org/page", "https://a.com/page"] {
        let probe = request_with("https://ads.example/lib.js", Some(referer), RequestKind::Script);
        assert!(
            set.exempts(&probe, RequestKind::Script),
            "the exception must fire for referer {referer}"
        );
    }
    let outside = request_with(
        "https://ads.example/lib.js",
        Some("https://other.com/page"),
        RequestKind::Script,
    );
    assert!(!set.exempts(&outside, RequestKind::Script));
}

#[test]
fn a_plain_domain_entry_is_matched_against_the_source_not_the_request_host() {
    // `$domain=` names the page the request came from. Matching it against the request's own host
    // would make `domain=a.com` fire for any request *to* a.com, whatever page it was on.
    let set = rules("||x.example^$script,domain=a.com|example.*\n");
    let to_a_com_from_elsewhere = request_with(
        "https://a.com/lib.js",
        Some("https://other.com/page"),
        RequestKind::Script,
    );
    assert_eq!(
        set.verdict(&to_a_com_from_elsewhere, RequestKind::Script),
        None,
        "a request *to* a plain entry's host is not in its scope"
    );
}

#[test]
fn a_negated_plain_entry_takes_the_source_back_out_on_both_forms() {
    // `~a.com` narrows the whole `$domain=` list, so it has to remove the source from the plain half
    // (the engine does that) and from the entity half (this module does).
    let set = rules("||x.example^$script,domain=a.com|example.*|~a.com\n");
    let excluded = request_with(
        "https://x.example/lib.js",
        Some("https://a.com/page"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&excluded, RequestKind::Script), None);

    let entity_side = request_with(
        "https://x.example/lib.js",
        Some("https://example.org/page"),
        RequestKind::Script,
    );
    assert_eq!(set.verdict(&entity_side, RequestKind::Script), Some(true));
}

#[test]
fn a_rule_outside_the_source_entity_is_never_queried() {
    // The front filter (review item 4): `could_match` is what keeps a request from being run through
    // an engine per stored rule. Its answer has to agree with the engine's, so this asserts the two
    // paths cannot disagree on a rule the request is outside of.
    let set = rules("||x.example^$script,domain=a.com|example.*\n");
    let outside = request_with(
        "https://x.example/lib.js",
        Some("https://other.net/page"),
        RequestKind::Script,
    );
    let scope = RequestScope::of(&outside);
    assert!(
        !set.rules()[0].could_match(&scope),
        "a rule whose entity and plain entries both miss must be skipped"
    );

    let inside = request_with(
        "https://x.example/lib.js",
        Some("https://sub.example.org/page"),
        RequestKind::Script,
    );
    assert!(set.rules()[0].could_match(&RequestScope::of(&inside)));
}


