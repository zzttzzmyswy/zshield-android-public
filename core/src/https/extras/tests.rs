//! Tests for the modifiers this core evaluates itself (`super`).

use super::*;
use crate::dns::filter::LineClass;
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

/// A navigation with the three Fetch Metadata fields a browser sends.
fn navigation(url: &str, referer: &str, site: &str, user: Option<&str>) -> HttpRequest {
    let mut request = request_with(url, Some(referer), RequestKind::Document);
    request.fetch_dest = Some("document".to_string());
    request.fetch_site = Some(site.to_string());
    request.fetch_user = user.map(str::to_string);
    request
}

// ---------------------------------------------------------------------------------------------
// $popup
// ---------------------------------------------------------------------------------------------

fn popup(rules: &str) -> PopupRules {
    let mut set = PopupRules::default();
    set.add_list(rules);
    set.build();
    set
}

#[test]
fn a_popup_rule_matches_only_a_cross_site_user_untriggered_navigation() {
    let rules = popup("||ad.example^$popup\n");

    // All three conditions hold: cross-site, a document, and no user activation.
    assert!(rules.blocks(
        &navigation("https://ad.example/landing", "https://site.example/", "cross-site", None),
        RequestKind::Document
    ));
    // `Sec-Fetch-User: ?1` means the user clicked something: not a popup.
    assert!(!rules.blocks(
        &navigation(
            "https://ad.example/landing",
            "https://site.example/",
            "cross-site",
            Some("?1")
        ),
        RequestKind::Document
    ));
    // Same-site: a site navigating itself is ordinary browsing.
    assert!(!rules.blocks(
        &navigation("https://ad.example/landing", "https://ad.example/", "same-origin", None),
        RequestKind::Document
    ));
    // A subresource is never a popup.
    let mut subresource =
        request_with("https://ad.example/landing", Some("https://site.example/"), RequestKind::Script);
    subresource.fetch_dest = Some("script".to_string());
    subresource.fetch_site = Some("cross-site".to_string());
    assert!(!rules.blocks(&subresource, RequestKind::Script));

    // The same URL reached with no Fetch Metadata at all: the engine cannot tell, so it forwards.
    // Guessing here would put every navigation from an older client at risk.
    let bare = request_with("https://ad.example/landing", None, RequestKind::Document);
    assert!(!rules.blocks(&bare, RequestKind::Document));
}

#[test]
fn a_popup_rule_keeps_the_options_written_beside_it() {
    let rules = popup("||ad.example^$popup,domain=site.example\n");
    assert!(
        rules.blocks(
            &navigation("https://ad.example/x", "https://site.example/", "cross-site", None),
            RequestKind::Document
        ),
        "the popup must fire from the scoped source"
    );
    assert!(
        !rules.blocks(
            &navigation("https://ad.example/x", "https://other.example/", "cross-site", None),
            RequestKind::Document
        ),
        "`$domain=` must keep its meaning: it narrows where the rule applies"
    );
    assert_eq!(rules.len(), 1);
}

#[test]
fn a_popup_rule_with_no_pattern_still_applies_where_its_domain_says() {
    // 1,200+ catalog rules are written `$popup,3p,domain=…` with no pattern: "any popup opened by
    // these sites". They are the form a naive "strip the option" implementation silently loses.
    let rules = popup("$popup,domain=site.example\n");
    assert_eq!(rules.len(), 1);
    assert!(rules.blocks(
        &navigation("https://anything.example/x", "https://site.example/", "cross-site", None),
        RequestKind::Document
    ));
    assert!(!rules.blocks(
        &navigation(
            "https://anything.example/x",
            "https://other.example/",
            "cross-site",
            None
        ),
        RequestKind::Document
    ));
}

#[test]
fn a_popup_rule_the_engine_cannot_match_is_reported_not_silently_lost() {
    // `/regex/` patterns, `$3p`-only rules and similar forms may not survive the rebuild. Either they
    // match or they are listed as rejected — never dropped without a trace.
    let rules = popup("/^https:\\/\\/ad\\.example\\//$popup\n||fine.example^$popup,3p\n");
    assert!(
        rules.len() + rules.rejected().len() >= 2,
        "every `$popup` line must be accounted for: {:?}",
        rules.rejected()
    );
}

// ---------------------------------------------------------------------------------------------
// $denyallow
// ---------------------------------------------------------------------------------------------

fn denyallow(rules: &str) -> DenyAllowRules {
    let mut set = DenyAllowRules::default();
    set.add_list(rules);
    set.build();
    set
}

#[test]
fn a_denyallowed_host_is_exempt_from_the_rule_it_sits_on() {
    let rules = denyallow("*$script,denyallow=cdn.good.example|assets.good.example,domain=site.example\n");
    assert_eq!(rules.len(), 1);
    assert!(rules.rules()[0].allow.contains(&"cdn.good.example".to_string()));

    // A script from the CDN the rule exempts: forwarded.
    assert!(rules.exempts(
        &request_with(
            "https://cdn.good.example/lib.js",
            Some("https://site.example/"),
            RequestKind::Script
        ),
        RequestKind::Script
    ));
    // A subdomain of the exempted host is exempt too (`||` semantics).
    assert!(rules.exempts(
        &request_with(
            "https://x.assets.good.example/lib.js",
            Some("https://site.example/"),
            RequestKind::Script
        ),
        RequestKind::Script
    ));
    // Anywhere else is not exempt: the broad rule keeps blocking.
    assert!(!rules.exempts(
        &request_with(
            "https://evil.example/lib.js",
            Some("https://site.example/"),
            RequestKind::Script
        ),
        RequestKind::Script
    ));
    // A look-alike host is not a subdomain.
    assert!(!rules.exempts(
        &request_with(
            "https://notcdn.good.example/lib.js",
            Some("https://site.example/"),
            RequestKind::Script
        ),
        RequestKind::Script
    ));
}

#[test]
fn a_denyallow_list_does_not_exempt_a_request_the_rule_does_not_match() {
    // The rule is `$script,domain=site.example`, so a script from *another* site that happens to be on
    // the CDN must not be excused: nothing was blocking it in the first place, and an exemption that
    // fired outside the rule's scope would silently disable the rule for everyone.
    let rules = denyallow("*$script,denyallow=cdn.good.example,domain=site.example\n");
    assert!(!rules.exempts(
        &request_with(
            "https://cdn.good.example/lib.js",
            Some("https://other.example/"),
            RequestKind::Script
        ),
        RequestKind::Script
    ));
    // Nor a non-script request, which the `$script` option excludes.
    assert!(!rules.exempts(
        &request_with(
            "https://cdn.good.example/pixel.gif",
            Some("https://site.example/"),
            RequestKind::Image
        ),
        RequestKind::Image
    ));
}

#[test]
fn a_denyallow_rule_that_cannot_be_rebuilt_is_reported() {
    // `$denyallow` combined with an option the engine also refuses leaves nothing matchable; the line
    // must show up as rejected rather than vanishing.
    let rules = denyallow("*$script,denyallow=a.example,replace=/x/y/\n");
    assert!(
        rules.len() + rules.rejected().len() == 1,
        "{:?}",
        rules.rejected()
    );
}

// ---------------------------------------------------------------------------------------------
// $removeparam
// ---------------------------------------------------------------------------------------------

fn removeparam(rules: &str) -> RemoveParamRules {
    let mut set = RemoveParamRules::default();
    set.add_list(rules);
    set.build();
    set
}

#[test]
fn a_regex_removeparam_prunes_the_matching_parameters() {
    let rules = removeparam("||shop.example^$removeparam=/^utm_/\n");
    assert_eq!(rules.len(), 1, "{:?}", rules.rejected());
    let request = request_with(
        "https://shop.example/p?utm_source=x&utm_medium=y&keep=1",
        Some("https://site.example/"),
        RequestKind::Document,
    );
    assert_eq!(
        rules.rewrite(&request, RequestKind::Document),
        Some("https://shop.example/p?keep=1".to_string())
    );
    // A query with nothing to remove must not be rewritten at all: an unchanged URL would still cost
    // the caller a redirect or a re-request.
    let clean = request_with(
        "https://shop.example/p?keep=1",
        Some("https://site.example/"),
        RequestKind::Document,
    );
    assert_eq!(rules.rewrite(&clean, RequestKind::Document), None);
}

#[test]
fn a_regex_removeparam_that_empties_the_query_drops_the_question_mark() {
    let rules = removeparam("||shop.example^$removeparam=/^utm_/\n");
    let request = request_with(
        "https://shop.example/p?utm_source=x#hash",
        None,
        RequestKind::Document,
    );
    assert_eq!(
        rules.rewrite(&request, RequestKind::Document),
        Some("https://shop.example/p#hash".to_string())
    );
}

#[test]
fn the_regex_matches_against_the_decoded_value_the_way_ubo_does() {
    let rules = removeparam("||shop.example^$removeparam=/referrer=appmetrica/\n");
    let request = request_with(
        "https://shop.example/p?referrer=appmetrica_tracking_id&x=1",
        None,
        RequestKind::Document,
    );
    assert_eq!(
        rules.rewrite(&request, RequestKind::Document),
        Some("https://shop.example/p?x=1".to_string())
    );
}

#[test]
fn a_complex_or_oversized_regex_is_refused_rather_than_run() {
    // A pattern with no DFA-representable bound is refused at build time: a subscription must not be
    // able to make every request's query string cost seconds of backtracking.
    let rules = removeparam("||shop.example^$removeparam=/(a+)+$/\n");
    // Either it compiled (bounded) and reports one rule, or it was refused and is reported; what must
    // not happen is a silent drop with no counter.
    assert!(
        rules.len() + rules.rejected().len() == 1,
        "{:?}",
        rules.rejected()
    );
    // A syntactically invalid pattern is definitely refused.
    let broken = removeparam("||shop.example^$removeparam=/[unclosed/\n");
    assert_eq!(broken.len(), 0);
    assert_eq!(broken.rejected().len(), 1);
}

#[test]
fn an_exception_removeparam_cancels_pruning_for_its_scope() {
    // `@@||web.archive.org/*/http$removeparam` exists in real lists: rewriting those URLs breaks the
    // archive. The exception has to be able to stop the block rule.
    let rules = removeparam(
        "||archive.example^$removeparam=/^utm_/\n\
         @@||archive.example/save/*$removeparam\n",
    );
    assert_eq!(rules.len(), 2, "{:?}", rules.rejected());
    assert_eq!(
        rules.rewrite(
            &request_with("https://archive.example/save/http://a?utm_x=1", None, RequestKind::Document),
            RequestKind::Document
        ),
        None,
        "the exception must win inside its scope"
    );
    assert_eq!(
        rules.rewrite(
            &request_with("https://archive.example/other?utm_x=1", None, RequestKind::Document),
            RequestKind::Document
        ),
        Some("https://archive.example/other".to_string()),
        "and the block rule must still fire outside it"
    );
}

#[test]
fn a_plain_removeparam_is_evaluated_here_too() {
    // The plain form parses in the engine, and used to be left to it. It cannot be any more: deciding the
    // modifier needs *every* rule that names a parameter, because two rules can name the same one (a
    // typed rule beside an untyped one) and a finished URL cannot say which of them removed it. So the
    // whole family is collected, and the engine's own rewrite is only a fallback for a rule set this core
    // holds nothing of.
    let rules = removeparam("||shop.example^$removeparam=utm_source\n");
    assert_eq!(rules.len(), 1, "{:?}", rules.rejected());
    assert!(rules.rejected().is_empty());
    assert_eq!(
        rules.rewrite(
            &request_with("https://shop.example/p?utm_source=x&keep=1", None, RequestKind::Document),
            RequestKind::Document
        )
        .as_deref(),
        Some("https://shop.example/p?keep=1")
    );
}

#[test]
fn the_bare_removeparam_form_parses_into_a_whole_query_matcher() {
    // `$removeparam` with no value: on a block rule it means "drop the whole query", on an exception "keep
    // all of it". Both are collected, because the evaluation needs to see the bare blocking form to know a
    // bare exception has something to protect.
    let rules = removeparam("||go.example^$xhr,removeparam\n@@||keep.example^$removeparam\n");
    assert_eq!(rules.len(), 2, "{:?}", rules.rejected());
    assert!(rules.rejected().is_empty());
    assert_eq!(
        rules.rewrite(
            &request_with("https://go.example/p?a=1&b=2", None, RequestKind::Xhr),
            RequestKind::Xhr
        )
        .as_deref(),
        Some("https://go.example/p")
    );
}

#[test]
fn the_bare_removeparam_form_on_an_exception_rule_cancels_pruning() {
    // `@@||wayback.example/*/http$removeparam` is the form the engine refuses, and its meaning is "do
    // not prune the query of these URLs" — the archive breaks when the URL is rewritten.
    let rules = removeparam(
        "||archive.example^$removeparam=/^utm_/\n\
         @@||archive.example/save/*$removeparam\n",
    );
    assert_eq!(rules.len(), 2, "{:?}", rules.rejected());
    assert_eq!(
        rules.rewrite(
            &request_with("https://archive.example/save/http://a?utm_x=1", None, RequestKind::Document),
            RequestKind::Document
        ),
        None,
        "the exception must cancel the pruning inside its scope"
    );
}

// ---------------------------------------------------------------------------------------------
// Collecting from real list text
// ---------------------------------------------------------------------------------------------

#[test]
fn the_three_rule_sets_are_collected_from_one_pass_over_a_list() {
    let modifiers = collect([
        "! a comment\n\
         ||ad.example^$popup\n\
         *$script,denyallow=cdn.example,domain=site.example\n\
         ||shop.example^$removeparam=/^utm_/\n\
         ||plain.example^\n",
    ]);
    assert_eq!(modifiers.popup.len(), 1);
    assert_eq!(modifiers.denyallow.len(), 1);
    assert_eq!(modifiers.removeparam.len(), 1);
    assert_eq!(modifiers.len(), 3);
    assert!(!modifiers.is_empty());
}

#[test]
fn a_rule_without_any_of_these_options_is_not_collected() {
    let modifiers = collect(["||plain.example^\n||other.example^$script\n"]);
    assert!(modifiers.is_empty());
}

// ---------------------------------------------------------------------------------------------
// The "不支持" count and the rules that actually filter must agree
// ---------------------------------------------------------------------------------------------

#[test]
fn a_line_this_core_evaluates_is_not_counted_as_unsupported() {
    // The UI's "不支持" figure exists so a user can trust it. A `$popup`/`$denyallow`/regex
    // `$removeparam` line the engine refuses is *implemented*, so counting it as broken would make
    // 6,484 working rules look like failures. Both answers come from the shipping collector.
    for line in [
        "||ad.example^$popup",
        "$popup,3p,domain=site.example",
        "*$script,denyallow=cdn.example,domain=site.example",
        "||shop.example^$removeparam=/^utm_/",
        "@@||archive.example/*/http$removeparam",
    ] {
        assert!(evaluates(line), "{line} is implemented, not unsupported");
    }
    // A line with none of the three options, and one the collector refuses, stay unsupported.
    for line in [
        "||plain.example^$urlskip=x",
        "||plain.example^$replace=/a/b/",
        "||plain.example^$popup,replace=/a/b/",
    ] {
        assert!(!evaluates(line), "{line} must still count as unsupported");
    }
}

#[test]
fn the_engine_accepts_what_this_core_evaluates_through_the_dns_classifier() {
    // The classifier and the collector are the two halves the "不支持" number is built from; asking
    // `dns::filter::engine_accepts` directly is what proves the two cannot drift.
    use crate::dns::filter::classify_line;
    // `||ad.example^$popup` is a rule this core implements, so it counts as a usable network rule.
    assert_eq!(classify_line("||ad.example^$popup"), LineClass::NetworkOnly);
    // `$urlskip` is not implemented by either layer, so the line is one neither can use. Which
    // bucket a *rejected* line lands in is the DNS parser's own diagnostic (`NetworkOnly` when the
    // engine's parser accepted the line, `Malformed` when it refused too); what matters here is that
    // it is **not** counted as usable while `$popup` is.
    assert_ne!(classify_line("||ad.example^$urlskip=x"), LineClass::Domain);
    assert!(!crate::https::extras::evaluates("||ad.example^$urlskip=x"));
}

// ---------------------------------------------------------------------------------------------
// $removeparam: the forms the engine refuses, and the content-type rule
// ---------------------------------------------------------------------------------------------

/// Build the rule set from one list body and ask for the rewrite of one request.
fn rewrite_of(list: &str, url: &str, kind: RequestKind) -> Option<String> {
    let rules = collect([list]);
    let request = request_with(url, Some("https://page.example/index.html"), kind);
    rules.removeparam.rewrite(&request, kind)
}

#[test]
fn a_regex_removeparam_is_evaluated_here_because_the_engine_refuses_the_form() {
    // `removeparam=/re/` fails the engine's parser (`parse_ok=false`), so nothing else would apply it.
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=/^utm_/",
            "https://shop.example/p?utm_source=x&keep=1",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?keep=1")
    );
}

#[test]
fn a_regex_removeparam_matches_the_name_and_value_pair() {
    // AdGuard's KB: a regexp form removes parameters "normalized to a `name=value` string".
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=/^token=secret$/",
            "https://shop.example/p?token=secret&token=public",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?token=public")
    );
}

#[test]
fn an_inverted_removeparam_keeps_only_the_named_parameter() {
    // `$removeparam=~name` is refused by the engine's parser; keeping one parameter means dropping the
    // rest, which is the opposite of what the plain form does.
    assert_eq!(
        rewrite_of(
            "||shop.example*p1$xmlhttprequest,removeparam=~p2",
            "https://shop.example/p?p1=1&p2=2&p3=3",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?p2=2")
    );
}

#[test]
fn an_inverted_regex_removeparam_keeps_only_what_the_regex_matches() {
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=~/^keep/",
            "https://shop.example/p?keep1=a&drop1=b&keep2=c",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?keep1=a&keep2=c")
    );
}

#[test]
fn a_percent_encoded_parameter_name_is_matched_as_written() {
    // AdGuard's KB: "special characters should be URL-encoded in a rule to correctly match the URL
    // text", and `$removeparam=%24param` removes `?$param`. The name is therefore compared against the
    // wire spelling, not against a decoded one.
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=%24token",
            "https://shop.example/p?%24token=a&token=b",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?token=b")
    );
}

#[test]
fn an_untyped_removeparam_never_fires_for_a_subresource() {
    // AdGuard's KB: "`$removeparam` rules without content type modifiers will only match requests where
    // the content type is `document`". This is the difference the page's cases 11/12 measure.
    assert_eq!(
        rewrite_of(
            "||shop.example^$removeparam=/^p1=/",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        ),
        None,
        "an untyped rule must not touch a fetch()"
    );
    // And the typed form does fire for the type it names.
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=/^p1=/",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?p2=2")
    );
}

#[test]
fn an_exception_names_one_parameter_and_leaves_the_others() {
    // AdGuard's case 5: a global prune of both parameters plus an exception for one of them still drops
    // the other. A whole-request veto would keep both and fail in the opposite direction.
    assert_eq!(
        rewrite_of(
            "$xmlhttprequest,removeparam=/^p1=/\n$xmlhttprequest,removeparam=/^p2=/\n@@||shop.example^$xmlhttprequest,removeparam=/^p2=/",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?p2=2")
    );
}

#[test]
fn a_bare_exception_cancels_every_rule_in_its_scope() {
    // `@@||host^$removeparam` (no value) is the "protect this whole site" form, e.g. for web archives.
    assert_eq!(
        rewrite_of(
            "$xmlhttprequest,removeparam=/^p1=/\n$xmlhttprequest,removeparam=/^p2=/\n@@||shop.example^$xmlhttprequest,removeparam",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        ),
        None
    );
}

#[test]
fn an_important_rule_survives_an_exception_that_names_it() {
    // `$important` is the modifier's whole point: AdGuard's case 6 writes both an important rule and an
    // exception for the same parameter and expects the rule to win. The whole family is evaluated here
    // now, so the precedence is decided on the request's own URL rather than by refusing to restore a
    // parameter in a URL the engine already rewrote.
    assert_eq!(
        rewrite_of(
            "||shop.example$important,xmlhttprequest,removeparam=/^p1=/\n@@||shop.example^$xmlhttprequest,removeparam=/^p1=/",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?p2=2"),
        "the exception must not put back a parameter an `$important` rule removed"
    );
    // The same exception *does* protect a parameter no important rule names.
    assert_eq!(
        rewrite_of(
            "||shop.example$important,xmlhttprequest,removeparam=/^p9=/\n@@||shop.example^$xmlhttprequest,removeparam=/^p1=/",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        ),
        None,
        "an exception still protects the parameter it names, and nothing is pruned"
    );
}

#[test]
fn a_rewrite_keeps_the_fragment_and_the_parameter_order() {
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=/^b=/",
            "https://shop.example/p?a=1&b=2&c=3#frag",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?a=1&c=3#frag")
    );
}

#[test]
fn every_removeparam_rule_survives_a_serialize_and_reload_round_trip() {
    // `extras.txt` is the only thing that survives a restart, so a rule kept solely for the precedence
    // or content-type corrections has to be in it — otherwise the correction works until the next start
    // and then silently stops.
    let list = "\
||shop.example^$removeparam=/^p1=/\n\
||shop.example$important,xmlhttprequest,removeparam=/^p2=/\n\
@@||shop.example^$xmlhttprequest,removeparam=p3";
    let original = collect([list]);
    let serialized = original.serialize_lines();
    let reloaded = collect([serialized.as_str()]);
    assert_eq!(
        reloaded.removeparam.len(),
        original.removeparam.len(),
        "every `$removeparam` rule must survive the reload: the evaluation needs the whole family, \
         including the forms the engine also applies"
    );
    assert!(reloaded.removeparam.rejected().is_empty());
    // And the behaviour is identical, which is the property those two counts exist for. Three rules,
    // three different outcomes, so a lost rule cannot hide behind another:
    //   `p1` — untyped, so it must not fire for a `fetch()` at all;
    //   `p2` — `$xmlhttprequest` + `$important`, so it fires;
    //   `p3` — named by the exception, so it survives even though a rule would prune it.
    let request = request_with(
        "https://shop.example/p?p1=1&p2=2&p3=3",
        Some("https://page.example/index.html"),
        RequestKind::Xhr,
    );
    let fresh = original.removeparam.rewrite(&request, RequestKind::Xhr);
    assert_eq!(
        fresh.as_deref(),
        Some("https://shop.example/p?p1=1&p3=3"),
        "an untyped rule must not fire for a fetch(), the typed one must, and the exception must hold"
    );
    assert_eq!(
        reloaded.removeparam.rewrite(&request, RequestKind::Xhr),
        fresh,
        "the reloaded rule set must decide exactly as the one that came from the list"
    );
}

#[test]
fn an_untyped_exception_still_protects_its_parameter_on_a_subresource() {
    // The document-only rule constrains pruning, not protection. An untyped exception is the *only*
    // spelling the engine refuses, so treating it as inapplicable outside a document would make every
    // exception in a real list stop working for `fetch()`/XHR — which is exactly how AdGuard's case 5
    // regressed once during this iteration.
    assert_eq!(
        rewrite_of(
            "$xmlhttprequest,removeparam=/^p1=/\n$xmlhttprequest,removeparam=/^p2=/\n@@||shop.example^$xmlhttprequest,removeparam=p2",
            "https://shop.example/p?p1=1&p2=2",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?p2=2"),
        "the untyped exception must protect p2 on a fetch()"
    );
}

#[test]
fn the_content_type_and_exception_corrections_apply_together() {
    // AdGuard's page combines the two on one request: an untyped rule and a typed rule prune, an
    // untyped exception protects one parameter, and the request is a `fetch()`. Both corrections have
    // to run — applying only one leaves either cases 11/12 or case 5 wrong, and each ordering of an
    // early-return chain failed one of them during this iteration.
    let rules = collect([
        // Untyped: must not fire for a `fetch()` at all.
        "||shop.example^$removeparam=/^keep=/\
         \n||shop.example^$xmlhttprequest,removeparam=/^drop=/\
         \n@@||shop.example^$xmlhttprequest,removeparam=protect",
    ]);
    let request = request_with(
        "https://shop.example/p?keep=1&drop=2&protect=3",
        Some("https://page.example/index.html"),
        RequestKind::Xhr,
    );
    // `keep` survives because its rule is untyped; `drop` goes because its rule is typed; `protect`
    // survives because the exception names it. The engine's own answer would have dropped all three.
    assert_eq!(
        rules.removeparam.rewrite(&request, RequestKind::Xhr).as_deref(),
        Some("https://shop.example/p?keep=1&protect=3")
    );
}

// ---------------------------------------------------------------------------------------------
// Rule combinations: typed and untyped rules for the same parameter (first-review item 3)
// ---------------------------------------------------------------------------------------------

/// What the whole family decides for one list and one request, through the shipping evaluator.
fn rewrite_for(list: &str, url: &str, kind: RequestKind) -> Option<String> {
    let rules = collect([list]);
    let request = request_with(url, Some("https://shop.example/"), kind);
    rules.removeparam.rewrite(&request, kind)
}

#[test]
fn a_typed_rule_keeps_its_parameter_removed_next_to_an_untyped_one() {
    // The second review's second reproduction. On a `fetch()`, the untyped rule must not fire at all, so
    // a parameter the *typed* rule removed stays removed — restoring it would resurrect tracking the list
    // explicitly asked to strip, and would make adding a broad rule *weaken* a narrow one.
    let url = "https://shop.example/p?track=1&keep=2";
    assert_eq!(
        rewrite_for(
            "||shop.example^$xmlhttprequest,removeparam=track",
            url,
            RequestKind::Xhr
        )
        .as_deref(),
        Some("https://shop.example/p?keep=2"),
        "the typed rule alone removes `track`"
    );
    assert_eq!(
        rewrite_for(
            "||shop.example^$xmlhttprequest,removeparam=track\n||shop.example^$removeparam=track",
            url,
            RequestKind::Xhr
        )
        .as_deref(),
        Some("https://shop.example/p?keep=2"),
        "adding the untyped rule must not undo the typed one"
    );
}

#[test]
fn a_parameter_only_an_untyped_rule_names_survives_on_a_subresource() {
    // The other half of the same rule, and the second review's first reproduction: an untyped rule must
    // not remove anything from a `fetch()`, while a typed rule on a *different* parameter still does.
    assert_eq!(
        rewrite_for(
            "||shop.example^$xmlhttprequest,removeparam=track\n||shop.example^$removeparam=other",
            "https://shop.example/p?track=1&other=2&keep=3",
            RequestKind::Xhr
        )
        .as_deref(),
        Some("https://shop.example/p?other=2&keep=3"),
        "`other` is only covered by the untyped rule so it survives; `track` stays removed"
    );
}

/// The **production** entry: `HttpsModifiers::edits`, which is what the HTTP/1.1 relay and the HTTP/2
/// relay both call for a decrypted request.
///
/// Every regression in this file's second-review suite goes through this and not through
/// `RemoveParamRules::rewrite` directly, because the failure the review found was precisely a
/// disagreement about *which* answer is authoritative: the engine's finished URL or this core's. Testing
/// the evaluator alone could not see it.
fn end_to_end(list: &str, url: &str, kind: RequestKind) -> Option<String> {
    use crate::http::rewrite::ModifierSource;
    let mut set = adblock::lists::FilterSet::new(false);
    set.add_filter_list(list.to_string(), adblock::lists::ParseOptions::default());
    // `HttpsModifiers` reads the rule set from the filter, which is what makes a hot reload reach the
    // decrypted path; the extras therefore have to be *installed on the filter*, exactly as
    // `compile`'s reload does.
    let extras = std::sync::Arc::new(collect([list]));
    let filter = std::sync::Arc::new(
        crate::http::decision::HttpFilter::new(adblock::Engine::new_with_filter_set(set))
            .with_extras(extras),
    );
    let modifiers = crate::https::modifiers::HttpsModifiers::new(
        std::sync::Arc::clone(&filter),
        std::sync::Arc::new(crate::https::modifiers::collect_removeheader(std::iter::empty())),
        std::sync::Arc::clone(&filter.extras_arc()),
    );
    let request = request_with(url, Some("https://shop.example/"), kind);
    modifiers.edits(&request, kind).and_then(|edits| edits.url)
}

#[test]
fn a_regex_and_a_simple_rule_on_the_same_request_both_apply() {
    // Two rules of different forms, both typed. The engine parses the plain one and this core evaluates
    // the regex one, so this only works if the two halves are **composed** rather than chosen between —
    // which is exactly what a list writing both expects, and what AdGuard does.
    assert_eq!(
        end_to_end(
            "$xmlhttprequest,removeparam=/^track_/\n||shop.example^$xmlhttprequest,removeparam=session",
            "https://shop.example/p?track_a=1&track_b=2&session=3&keep=4",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?keep=4")
    );
}

#[test]
fn a_typed_regex_rule_is_not_undone_by_an_untyped_simple_rule() {
    // The mixed-form version of the review's case: the typed rule is a regex, the untyped one is a plain
    // name that happens to name the same parameter.
    assert_eq!(
        rewrite_for(
            "||shop.example^$xmlhttprequest,removeparam=/^tr/\n||shop.example^$removeparam=track",
            "https://shop.example/p?track=1&keep=2",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?keep=2")
    );
}

#[test]
fn an_exception_still_wins_over_a_typed_rule_but_not_over_an_important_one() {
    // The exception and important halves of the same matrix. `@@…$removeparam=track` protects the
    // parameter from a *typed* rule; `$important` is not exceptionable and keeps removing it.
    let list = "||shop.example^$xmlhttprequest,removeparam=track\n\
                @@||shop.example^$xmlhttprequest,removeparam=track";
    assert_eq!(
        rewrite_for(list, "https://shop.example/p?track=1&keep=2", RequestKind::Xhr),
        None,
        "the exception restores what the typed rule removed"
    );

    let important = "||shop.example^$important,xmlhttprequest,removeparam=track\n\
                     @@||shop.example^$xmlhttprequest,removeparam=track";
    assert_eq!(
        rewrite_for(important, "https://shop.example/p?track=1&keep=2", RequestKind::Xhr).as_deref(),
        Some("https://shop.example/p?keep=2"),
        "`$important` outranks the exception"
    );
}

#[test]
fn duplicate_parameters_with_different_values_are_matched_individually() {
    // A regex that names a value removes only the matching occurrence, which the per-pair evaluation in
    // `rewrite` has to preserve rather than collapsing on the name.
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=/^tag=drop$/",
            "https://shop.example/p?tag=drop&tag=keep&keep=1",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?tag=keep&keep=1")
    );
    // And a name-form rule removes every occurrence, which is what a name means.
    assert_eq!(
        rewrite_of(
            "||shop.example^$xmlhttprequest,removeparam=/^tag=/",
            "https://shop.example/p?tag=drop&tag=keep&keep=1",
            RequestKind::Xhr,
        )
        .as_deref(),
        Some("https://shop.example/p?keep=1")
    );
}

// ---------------------------------------------------------------------------------------------
// The second review's five reproductions, through the production entry
// ---------------------------------------------------------------------------------------------

/// The production answer for one request: the URL `HttpsModifiers::edits` produces, or the unchanged URL.
///
/// This is the harness the reviewer's `examples/review_i2.rs` uses, and the reason the five cases below
/// exist: they failed 5/5 through this entry while the evaluator's own unit tests passed, because the
/// evaluator was only *one* of the inputs and the engine's finished URL was the other.
fn production_url(list: &str, url: &str, kind: RequestKind) -> String {
    end_to_end(list, url, kind).unwrap_or_else(|| url.to_string())
}

#[test]
fn review_case_1_an_untyped_only_rule_leaves_a_fetch_alone() {
    // `$removeparam` with no content type only matches a `document`. A `fetch()` must come out untouched,
    // which the previous version got wrong the other way: the engine applies such a rule to
    // `xmlhttprequest` too, and the repair pass could not put the parameter back because it had no way to
    // know which rule removed it.
    assert_eq!(
        production_url(
            "||shop.example^$removeparam=track",
            "https://shop.example/p?track=1&keep=2",
            RequestKind::Xhr,
        ),
        "https://shop.example/p?track=1&keep=2"
    );
}

#[test]
fn review_case_2_a_typed_and_an_untyped_rule_on_one_name_remove_it_once() {
    // Both rules are in force for a `fetch()` through the typed one, so `track` goes; adding a *third*
    // typed rule for another parameter removes that one too. The previous version restored `track` here,
    // resurrecting tracking the list explicitly asked to strip.
    assert_eq!(
        production_url(
            "||shop.example^$xmlhttprequest,removeparam=track\n\
             ||shop.example^$removeparam=track\n\
             ||shop.example^$xmlhttprequest,removeparam=other",
            "https://shop.example/p?track=1&other=2&keep=3",
            RequestKind::Xhr,
        ),
        "https://shop.example/p?keep=3"
    );
}

#[test]
fn review_case_3_a_domain_scoped_untyped_rule_does_not_fire_on_a_fetch() {
    // `$domain=` narrows *where* a rule applies; it does not make it typed. So the untyped rule still only
    // matches a document, and only the typed rule for `other` prunes anything here.
    assert_eq!(
        production_url(
            "||shop.example^$domain=shop.example,removeparam=track\n\
             ||shop.example^$xmlhttprequest,removeparam=other",
            "https://shop.example/p?track=1&other=2&keep=3",
            RequestKind::Xhr,
        ),
        "https://shop.example/p?track=1&keep=3"
    );
}

#[test]
fn review_case_4_a_value_sensitive_regex_removes_only_the_occurrence_it_names() {
    // `?tag=drop&tag=keep` with `$removeparam=/^tag=drop$/`: one occurrence goes, the other stays. The
    // previous version compared *names* only, so it could not tell the two apart and left both — and the
    // untyped `unused` rule beside it made the difference invisible in the passing tests.
    assert_eq!(
        production_url(
            "||shop.example^$xmlhttprequest,removeparam=/^tag=drop$/\n\
             ||shop.example^$removeparam=unused\n\
             ||shop.example^$xmlhttprequest,removeparam=other",
            "https://shop.example/p?tag=drop&tag=keep&other=2&keep=1",
            RequestKind::Xhr,
        ),
        "https://shop.example/p?tag=keep&keep=1"
    );
}

#[test]
fn review_case_5_a_value_sensitive_typed_regex_is_not_cancelled_by_an_untyped_rule() {
    // The typed regex names `track=1` and is in force for a `fetch()`; the untyped rule on `track` is not.
    // The occurrence has to go, which needs the *value* to decide: a name-only comparison sees "a typed
    // rule and an untyped rule both name `track`" and restores it.
    assert_eq!(
        production_url(
            "||shop.example^$xmlhttprequest,removeparam=/^track=1$/\n\
             ||shop.example^$removeparam=track\n\
             ||shop.example^$xmlhttprequest,removeparam=other",
            "https://shop.example/p?track=1&other=2&keep=3",
            RequestKind::Xhr,
        ),
        "https://shop.example/p?keep=3"
    );
}

// ---------------------------------------------------------------------------------------------
// The combination matrix the task card asks for
// ---------------------------------------------------------------------------------------------

/// One request, one list, through the production entry.
fn matrix(list: &str, url: &str, kind: RequestKind) -> Option<String> {
    end_to_end(list, url, kind)
}

#[test]
fn every_matcher_form_removes_what_it_names() {
    // The five matcher shapes, each on its own, on a document request so the content-type rule does not
    // interfere. Percent-encoded names are compared as they appear on the wire (AdGuard's rule); an
    // inverted form keeps only what it matches.
    for (list, url, expected) in [
        (
            "||shop.example^$removeparam=utm_source",
            "https://shop.example/p?utm_source=x&keep=1",
            Some("https://shop.example/p?keep=1"),
        ),
        (
            "||shop.example^$removeparam",
            "https://shop.example/p?a=1&b=2",
            Some("https://shop.example/p"),
        ),
        (
            "||shop.example^$removeparam=/^utm_/i",
            "https://shop.example/p?UTM_source=x&keep=1",
            Some("https://shop.example/p?keep=1"),
        ),
        (
            "||shop.example^$removeparam=~keep",
            "https://shop.example/p?keep=1&drop=2&more=3",
            Some("https://shop.example/p?keep=1"),
        ),
        (
            "||shop.example^$removeparam=~/^keep/",
            "https://shop.example/p?keep=1&drop=2",
            Some("https://shop.example/p?keep=1"),
        ),
        (
            "||shop.example^$removeparam=%24token",
            "https://shop.example/p?%24token=a&token=b",
            Some("https://shop.example/p?token=b"),
        ),
    ] {
        assert_eq!(
            matrix(list, url, RequestKind::Document).as_deref(),
            expected,
            "{list} on {url}"
        );
    }
}

#[test]
fn a_typed_rule_only_fires_for_the_types_it_names() {
    // The typed half of the matrix: `$xmlhttprequest` on an XHR, nothing on a script or a document, and
    // `$~image` (a negation) on everything but an image. Each is the engine's own scope answer, asked for
    // the rule alone.
    let list = "||shop.example^$xmlhttprequest,removeparam=track";
    assert_eq!(
        matrix(list, "https://shop.example/p?track=1&keep=2", RequestKind::Xhr).as_deref(),
        Some("https://shop.example/p?keep=2")
    );
    for kind in [RequestKind::Script, RequestKind::Document, RequestKind::Image] {
        assert_eq!(
            matrix(list, "https://shop.example/p?track=1&keep=2", kind),
            None,
            "{kind:?} must not be touched by an `$xmlhttprequest` rule"
        );
    }

    let negated = "||shop.example^$~image,removeparam=track";
    assert_eq!(
        matrix(negated, "https://shop.example/p?track=1&keep=2", RequestKind::Xhr).as_deref(),
        Some("https://shop.example/p?keep=2"),
        "`$~image` applies to an XHR"
    );
    assert_eq!(
        matrix(negated, "https://shop.example/p?track=1&keep=2", RequestKind::Image),
        None,
        "`$~image` excludes an image"
    );
}

#[test]
fn a_domain_scoped_rule_only_fires_for_the_sources_it_names() {
    // `$domain=` names the **source**, so the same target URL behaves differently depending on the
    // referer. Both directions, plus the "no referer" case, which the engine treats as no match.
    let list = "||shop.example^$document,removeparam=track,domain=site.example";
    let applies = request_with(
        "https://shop.example/p?track=1&keep=2",
        Some("https://site.example/page"),
        RequestKind::Document,
    );
    let subdomain = request_with(
        "https://shop.example/p?track=1&keep=2",
        Some("https://www.site.example/page"),
        RequestKind::Document,
    );
    let elsewhere = request_with(
        "https://shop.example/p?track=1&keep=2",
        Some("https://other.example/page"),
        RequestKind::Document,
    );
    let no_source = request_with(
        "https://shop.example/p?track=1&keep=2",
        None,
        RequestKind::Document,
    );
    let rules = collect([list]);
    assert_eq!(
        rules.removeparam.rewrite(&applies, RequestKind::Document).as_deref(),
        Some("https://shop.example/p?keep=2")
    );
    assert_eq!(
        rules.removeparam.rewrite(&subdomain, RequestKind::Document).as_deref(),
        Some("https://shop.example/p?keep=2"),
        "a subdomain of a `$domain=` entry is in scope"
    );
    assert_eq!(rules.removeparam.rewrite(&elsewhere, RequestKind::Document), None);
    assert_eq!(rules.removeparam.rewrite(&no_source, RequestKind::Document), None);
}

#[test]
fn a_third_party_rule_only_fires_across_sites() {
    // `$third-party` is another scope the engine answers; it must survive the hop through the per-rule
    // query. The target is the same in both cases, so only the party differs.
    let list = "||shop.example^$third-party,removeparam=track";
    let cross = request_with(
        "https://shop.example/p?track=1&keep=2",
        Some("https://elsewhere.example/"),
        RequestKind::Document,
    );
    let first = request_with(
        "https://shop.example/p?track=1&keep=2",
        Some("https://www.shop.example/"),
        RequestKind::Document,
    );
    let rules = collect([list]);
    assert_eq!(
        rules.removeparam.rewrite(&cross, RequestKind::Document).as_deref(),
        Some("https://shop.example/p?keep=2")
    );
    assert_eq!(rules.removeparam.rewrite(&first, RequestKind::Document), None);
}

#[test]
fn a_matching_and_a_non_matching_pattern_both_behave() {
    // Pattern matching is the engine's, so the checks that matter are that a non-matching pattern prunes
    // nothing (a path, a host, a wildcard) and that a matching one does.
    for (pattern, url, expected) in [
        ("||shop.example^", "https://shop.example/p?track=1&keep=2", true),
        ("||shop.example^", "https://other.example/p?track=1&keep=2", false),
        ("||shop.example/api", "https://shop.example/api?track=1", true),
        ("||shop.example/api", "https://shop.example/other?track=1", false),
        ("||shop.example/*?track=", "https://shop.example/p?track=1", true),
        ("||shop.example/*?track=", "https://shop.example/p?keep=1", false),
        ("||sub.shop.example^", "https://sub.shop.example/p?track=1", true),
        ("||sub.shop.example^", "https://shop.example/p?track=1", false),
    ] {
        let list = format!("{pattern}$document,removeparam=track");
        assert_eq!(
            matrix(&list, url, RequestKind::Document).is_some(),
            expected,
            "{pattern} on {url}"
        );
    }
}

#[test]
fn name_regex_and_bare_exceptions_each_protect_what_they_name() {
    // Three exception spellings, one blocking rule, one request. Each keeps exactly what it names and
    // leaves the rest to be pruned.
    for (exception, expected) in [
        (
            "@@||shop.example^$document,removeparam=keep",
            "https://shop.example/p?keep=1",
        ),
        (
            "@@||shop.example^$document,removeparam=/^keep/",
            "https://shop.example/p?keep=1",
        ),
        (
            "@@||shop.example^$document,removeparam",
            "https://shop.example/p?a=1&b=2&keep=1",
        ),
    ] {
        let list = format!("||shop.example^$document,removeparam=/./\n{exception}");
        assert_eq!(
            matrix(&list, "https://shop.example/p?a=1&b=2&keep=1", RequestKind::Document).as_deref(),
            (expected != "https://shop.example/p?a=1&b=2&keep=1").then_some(expected),
            "{exception}"
        );
    }
}

#[test]
fn an_important_rule_beats_every_exception_spelling() {
    // `$important` is not exceptionable, which is AdGuard's case 6. Both rules name the same parameter,
    // and the exception must not put it back.
    for exception in [
        "@@||shop.example^$document,removeparam=track",
        "@@||shop.example^$document,removeparam=/^track$/",
        "@@||shop.example^$document,removeparam",
    ] {
        let list = format!("||shop.example^$important,document,removeparam=track\n{exception}");
        assert_eq!(
            matrix(&list, "https://shop.example/p?track=1&keep=2", RequestKind::Document).as_deref(),
            Some("https://shop.example/p?keep=2"),
            "{exception} must not override `$important`"
        );
    }
    // And without `$important` the very same exception does protect it.
    let list = "||shop.example^$document,removeparam=track\n@@||shop.example^$document,removeparam=track";
    assert_eq!(
        matrix(list, "https://shop.example/p?track=1&keep=2", RequestKind::Document),
        None
    );
}

#[test]
fn duplicate_parameters_keep_their_values_order_and_encoding() {
    // The four properties the task card names, on one URL: repeated parameters with different values, the
    // original order, percent-encoding inside a value, and the difference between `?a=` and `?a`.
    let rules = collect(["||shop.example^$document,removeparam=/^tag=drop$/"]);
    let request = request_with(
        "https://shop.example/p?tag=drop&a=%E4%B8%AD&tag=keep&empty=&novalue#frag",
        None,
        RequestKind::Document,
    );
    assert_eq!(
        rules.removeparam.rewrite(&request, RequestKind::Document).as_deref(),
        Some("https://shop.example/p?a=%E4%B8%AD&tag=keep&empty=&novalue#frag"),
        "the surviving occurrence keeps its own value, the order is the site's, the escapes and the \
         empty/absent distinction are reproduced, and the fragment survives"
    );
}

#[test]
fn a_name_rule_removes_every_occurrence_of_that_name() {
    // The counterpart of the value-sensitive case: a name means every occurrence, whatever its value.
    let rules = collect(["||shop.example^$document,removeparam=tag"]);
    let request = request_with(
        "https://shop.example/p?tag=drop&keep=1&tag=also&tag=",
        None,
        RequestKind::Document,
    );
    assert_eq!(
        rules.removeparam.rewrite(&request, RequestKind::Document).as_deref(),
        Some("https://shop.example/p?keep=1")
    );
}

#[test]
fn the_rule_order_in_the_list_does_not_change_the_answer() {
    // "规则次序置换结果相同": the same rules written in another order must decide the same URL. Every
    // combination the matrix uses is permuted, so an accidental order dependency shows up as one
    // mismatching permutation rather than as a subtle behaviour nobody tested.
    let rules = [
        "||shop.example^$document,removeparam=track",
        "||shop.example^$xmlhttprequest,removeparam=/^track=1$/",
        "@@||shop.example^$document,removeparam=keep",
        "||shop.example^$important,document,removeparam=drop",
        "||shop.example^$removeparam=/^unused=/",
    ];
    let url = "https://shop.example/p?track=1&keep=2&drop=3&unused=4&other=5";
    let permutations: [[usize; 5]; 4] = [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [3, 1, 4, 0, 2]];
    let mut answers: Vec<Option<String>> = Vec::new();
    for order in permutations {
        let list: Vec<&str> = order.iter().map(|index| rules[*index]).collect();
        answers.push(end_to_end(&list.join("\n"), url, RequestKind::Document));
    }
    assert_eq!(
        answers[0].as_deref(),
        Some("https://shop.example/p?keep=2&other=5"),
        "the shared expectation, spelled out once"
    );
    for (permutation, answer) in permutations.iter().zip(&answers) {
        assert_eq!(answer, &answers[0], "order {permutation:?} decided differently");
    }
}

#[test]
fn a_serialized_and_reloaded_rule_set_decides_exactly_the_same() {
    // `extras.txt` is what survives a restart, so every rule the evaluation needs has to be in it — and
    // the reloaded set has to produce the same URL, not merely hold the same rule count.
    let list = "\
||shop.example^$document,removeparam=/^utm_/\n\
||shop.example^$xmlhttprequest,removeparam=track\n\
||shop.example^$important,document,removeparam=drop\n\
@@||shop.example^$document,removeparam=keep\n\
@@||shop.example^$xmlhttprequest,removeparam=/^safe=/";
    let original = collect([list]);
    let reloaded = collect([original.serialize_lines().as_str()]);
    assert_eq!(reloaded.removeparam.len(), original.removeparam.len());

    let cases = [
        (
            "https://shop.example/p?utm_source=x&track=1&drop=3&keep=4&safe=5",
            RequestKind::Document,
        ),
        (
            "https://shop.example/p?utm_source=x&track=1&drop=3&keep=4&safe=5",
            RequestKind::Xhr,
        ),
        ("https://other.example/p?utm_source=x&track=1", RequestKind::Document),
    ];
    for (url, kind) in cases {
        let request = request_with(url, Some("https://shop.example/"), kind);
        assert_eq!(
            reloaded.removeparam.rewrite(&request, kind),
            original.removeparam.rewrite(&request, kind),
            "{url} as {kind:?} decided differently after the reload"
        );
    }
}

#[test]
fn a_hot_reload_swaps_the_whole_family_under_the_decrypted_path() {
    // The decrypted path reads the live rule set (`HttpFilter::extras`), so a compile that lands new rules
    // has to change the answer without the tunnel being rebuilt. Checked through the production entry, and
    // in both directions: a rule added and a rule removed.
    use crate::http::rewrite::ModifierSource;
    let mut set = adblock::lists::FilterSet::new(false);
    set.add_filter_list(
        "||shop.example^$document,removeparam=first".to_string(),
        adblock::lists::ParseOptions::default(),
    );
    let filter = std::sync::Arc::new(
        crate::http::decision::HttpFilter::new(adblock::Engine::new_with_filter_set(set))
            .with_extras(std::sync::Arc::new(collect([
                "||shop.example^$document,removeparam=first",
            ]))),
    );
    let modifiers = crate::https::modifiers::HttpsModifiers::new(
        std::sync::Arc::clone(&filter),
        std::sync::Arc::new(crate::https::modifiers::collect_removeheader(std::iter::empty())),
        std::sync::Arc::clone(&filter.extras_arc()),
    );
    let target = request_with(
        "https://shop.example/p?first=1&second=2&keep=3",
        None,
        RequestKind::Document,
    );
    assert_eq!(
        modifiers.edits(&target, RequestKind::Document).and_then(|edits| edits.url).as_deref(),
        Some("https://shop.example/p?second=2&keep=3")
    );
    filter.replace_extras(std::sync::Arc::new(collect([
        "||shop.example^$document,removeparam=second",
    ])));
    assert_eq!(
        modifiers.edits(&target, RequestKind::Document).and_then(|edits| edits.url).as_deref(),
        Some("https://shop.example/p?first=1&keep=3"),
        "the new rule set must be in force, including the rule the old one had"
    );
}

#[test]
fn the_host_shortcut_agrees_with_the_engine() {
    // `||host^` with no options is the one rule shape evaluated without an engine. Its comparison has to be
    // the engine's exactly, or a host-scoped rule would fire where a per-rule query would not. Each host
    // below is asked of both.
    let engine = {
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list(
            "||a.shop.example^".to_string(),
            adblock::lists::ParseOptions::default(),
        );
        adblock::Engine::new_with_filter_set(set)
    };
    for (host, expected) in [
        ("a.shop.example", true),
        ("x.a.shop.example", true),
        ("shop.example", false),
        ("b.shop.example", false),
        ("a.shop.example.evil.test", false),
        ("nota.shop.example", false),
        ("A.SHOP.EXAMPLE", true),
    ] {
        let url = format!("https://{host}/p");
        let request = request_with(&url, None, RequestKind::Document);
        let by_engine = engine
            .check_network_request(&crate::http::decision::to_adblock_request(
                &request,
                RequestKind::Document,
            ))
            .should_block();
        assert_eq!(by_engine, expected, "the engine's own answer for {host}");
        assert_eq!(
            host_matches(&host.to_ascii_lowercase(), "a.shop.example"),
            expected,
            "the shortcut's answer for {host}"
        );
    }
}

#[test]
fn the_scope_engine_cache_is_bounded_and_shared_by_the_rule_set() {
    // The delivery note has to state the bound, so the bound is a property under test: a rule set with far
    // more scope forms than the cap must not grow the cache past it, and must still decide each request.
    let mut list = String::new();
    for index in 0..(MAX_REMOVEPARAM_SCOPE_ENGINES + 8) {
        list.push_str(&format!(
            "||host{index}.example/path$document,removeparam=track\n"
        ));
    }
    let rules = collect([list.as_str()]);
    assert_eq!(rules.removeparam.len(), MAX_REMOVEPARAM_SCOPE_ENGINES + 8);
    // The cap is on *cached* engines, and each of these is its own form, so asking them in turn fills the
    // map, then clears it and starts again. **The documented behaviour is clear-then-insert, not
    // "stop caching"**: an earlier report claimed entries beyond the cap were simply not remembered, while
    // the code dropped the whole map. This pins the code's actual behaviour so the report cannot drift from
    // it again.
    for index in 0..(MAX_REMOVEPARAM_SCOPE_ENGINES + 8) {
        let request = request_with(
            &format!("https://host{index}.example/path?track=1&keep=2"),
            None,
            RequestKind::Document,
        );
        let expected = format!("https://host{index}.example/path?keep=2");
        assert_eq!(
            rules.removeparam.rewrite(&request, RequestKind::Document).as_deref(),
            Some(expected.as_str()),
            "host{index} must still be decided while the cache is at its cap"
        );
        assert!(
            rules.removeparam.cached_engines() <= MAX_REMOVEPARAM_SCOPE_ENGINES,
            "the cache grew past its cap at host{index}: {}",
            rules.removeparam.cached_engines()
        );
    }
    // One past the cap the map was cleared rather than left full, so the count is far below the cap — that
    // is the clear-then-insert behaviour, visible as a number rather than only as a bound.
    assert!(
        rules.removeparam.cached_engines() < MAX_REMOVEPARAM_SCOPE_ENGINES / 2,
        "after {} forms the map should have been cleared and refilled, not held at the cap: {}",
        MAX_REMOVEPARAM_SCOPE_ENGINES + 8,
        rules.removeparam.cached_engines()
    );
}


#[test]
fn an_explicit_all_scope_is_typed_and_keeps_the_subresources_it_names() {
    // `$all` states the type scope explicitly, which is what makes a `$removeparam` rule typed. Reading it
    // as "no type option" would narrow the rule to `document` — the opposite of what it says — and the
    // `fetch()` the list author meant to cover would keep its parameter.
    let list = "||shop.example^$all,removeparam=track";
    for kind in [RequestKind::Document, RequestKind::Xhr, RequestKind::Script] {
        assert_eq!(
            matrix(list, "https://shop.example/p?track=1&keep=2", kind).as_deref(),
            Some("https://shop.example/p?keep=2"),
            "`$all` must cover {kind:?}"
        );
    }
}

#[test]
fn the_type_option_spellings_adguard_accepts_are_all_recognised_as_typed() {
    // The question `has_content_type` answers is only "did the list author state a type scope", so every
    // spelling that states one has to be in the list. A miss silently turns a typed rule into a
    // document-only one.
    for option in [
        "document", "doc", "subdocument", "frame", "script", "stylesheet", "css", "image", "media",
        "font", "object", "other", "ping", "beacon", "websocket", "xmlhttprequest", "xhr", "webrtc",
        "object-subrequest", "all",
    ] {
        assert!(
            has_content_type(&[option]),
            "`${option}` states a type scope and must count as typed"
        );
        // The negated spelling narrows a rule to a set of types too, so it is not the untyped form.
        assert!(
            has_content_type(&[&format!("~{option}")]),
            "`$~{option}` states a type scope and must count as typed"
        );
    }
    for option in ["important", "third-party", "3p", "domain=a.example", "removeparam=x"] {
        assert!(
            !has_content_type(&[option]),
            "`${option}` states no type scope"
        );
    }
}

#[test]
fn the_pattern_screen_only_rejects_what_the_engine_cannot_match() {
    // The screen exists so a host-anchored form costs no engine query. It is a *superset* of the engine's
    // answer by construction, and this pins the direction that matters: a `false` here has to be a proof
    // the engine would have said no. A pattern that is not a whole host is the case that broke an earlier
    // version — `||google.` matches `www.google.com`, because `||` anchors at a label boundary and the
    // pattern continues into the hostname rather than ending at it.
    for (anchor, host, must_admit) in [
        ("google.com", "google.com", true),
        ("google.com", "www.google.com", true),
        ("google.com", "a.b.google.com", true),
        ("google.com", "notgoogle.com", false),
        // A *superset*, not an equality: `google.com.evil.test` starts with `google.com` at a label
        // boundary, so the screen admits it and the engine rejects it. That direction costs one query and
        // is safe; the reverse would drop a rule.
        ("google.com", "google.com.evil.test", true),
        ("google.", "www.google.com", true),
        ("google.", "google.com", true),
        ("google.", "notgoogle.com", false),
        ("shop.example", "shop.example", true),
        ("shop.example", "sub.shop.example", true),
        ("shop.example", "notshop.example", false),
        ("shop.example", "unrelated.test", false),
        ("a.b", "c.a.b", true),
        ("a.b", "a.b", true),
        ("a.b", "xa.b", false),
    ] {
        assert_eq!(
            pattern_screen_admits(host, anchor),
            must_admit,
            "screen for ||{anchor} against {host}"
        );
    }
    // And the screen is not vacuous: it has to actually reject the hosts the engine rejects.
    let mut rejected = 0;
    let mut total = 0;
    for anchor in ["google.com", "google.", "shop.example", "a.b"] {
        for host in ["notgoogle.com", "unrelated.test", "xa.b"] {
            total += 1;
            if !pattern_screen_admits(host, anchor) {
                rejected += 1;
            }
        }
    }
    assert_eq!(rejected, total, "every one of these must be screened out");
}

// ---------------------------------------------------------------------------------------------
// $badfilter: a disabled rule must not participate, in any later stage
// ---------------------------------------------------------------------------------------------

/// The production answer for one request against **several** list bodies, in the order given.
///
/// `$badfilter` has to be resolved across lists — a list routinely disables a rule another list shipped —
/// so every case in this section is built from more than one body, and one of them permutes the order.
fn production_url_lists(lists: &[&str], url: &str, kind: RequestKind) -> String {
    use crate::http::rewrite::ModifierSource;
    let joined = lists.join("\n");
    let mut set = adblock::lists::FilterSet::new(false);
    for list in lists {
        set.add_filter_list((*list).to_string(), adblock::lists::ParseOptions::default());
    }
    let filter = std::sync::Arc::new(
        crate::http::decision::HttpFilter::new(adblock::Engine::new_with_filter_set(set))
            .with_extras(std::sync::Arc::new(collect(lists.iter().copied()))),
    );
    let modifiers = crate::https::modifiers::HttpsModifiers::new(
        std::sync::Arc::clone(&filter),
        std::sync::Arc::new(crate::https::modifiers::collect_removeheader(std::iter::empty())),
        std::sync::Arc::clone(&filter.extras_arc()),
    );
    let request = request_with(url, Some("https://shop.example/"), kind);
    let _ = joined;
    modifiers
        .edits(&request, kind)
        .and_then(|edits| edits.url)
        .unwrap_or_else(|| url.to_string())
}

#[test]
fn a_disabled_rule_does_not_disable_another_rule_that_strips_a_different_parameter() {
    // The stage-1 review's first case. `$badfilter` cancels **one rule identified by its whole original
    // text**, and `removeparam=track` is a different rule from `removeparam=other`. The previous version
    // resolved the disable relationship *after* stripping the option, so both became
    // `||shop.example^$document` — the same text — and disbling `track` silently disabled `other` too.
    for lists in [
        // The badfilter in the same body...
        &[
            "||shop.example^$removeparam=track\n||shop.example^$removeparam=track,badfilter",
            "||shop.example^$removeparam=other",
        ][..],
        // ...and in a body read *before* the rule it disables, which is the cross-list direction.
        &[
            "||shop.example^$removeparam=track,badfilter",
            "||shop.example^$removeparam=track\n||shop.example^$removeparam=other",
        ][..],
        // ...and with the badfilter written before the option it names.
        &[
            "||shop.example^$badfilter,removeparam=track",
            "||shop.example^$removeparam=track\n||shop.example^$removeparam=other",
        ][..],
    ] {
        assert_eq!(
            production_url_lists(lists, "https://shop.example/p?track=1&other=2&keep=3", RequestKind::Document),
            "https://shop.example/p?track=1&keep=3",
            "`track` is disabled, `other` must still be stripped; lists {lists:?}"
        );
    }
}

#[test]
fn a_disabled_rule_stays_disabled_when_another_rule_opens_the_gate() {
    // The stage-1 review's second case, and the reason a per-rule check is not enough: the gate engine is
    // built from every blocking stripped form, and a disabled rule's form is *also* another rule's form.
    // A disabled rule must never be reachable through any of the derived structures — the gate, the host
    // shortcut index, the name index, or a per-form engine.
    assert_eq!(
        production_url_lists(
            &[
                "||shop.example^$removeparam=track\n||shop.example^$removeparam=track,badfilter",
                "*$document,removeparam=other",
            ],
            "https://shop.example/p?track=1&other=2&keep=3",
            RequestKind::Document,
        ),
        "https://shop.example/p?track=1&keep=3",
        "the unscoped rule opens the gate for `other`, but `track` stays disabled"
    );
}

#[test]
fn a_disabled_exception_stops_protecting() {
    // The stage-1 review's third case, which the baseline got wrong too. An exception is as disableable as
    // a block: `@@…$removeparam=track,badfilter` cancels the exception, so `track` is stripped again.
    assert_eq!(
        production_url_lists(
            &[
                "||shop.example^$document,removeparam=track",
                "@@||shop.example^$document,removeparam=track\n@@||shop.example^$document,removeparam=track,badfilter",
            ],
            "https://shop.example/p?track=1&keep=3",
            RequestKind::Document,
        ),
        "https://shop.example/p?keep=3",
        "a disabled exception must not protect the parameter"
    );
    // And the same list *without* the badfilter keeps protecting it, so the case cannot pass by accident.
    assert_eq!(
        production_url_lists(
            &[
                "||shop.example^$document,removeparam=track",
                "@@||shop.example^$document,removeparam=track",
            ],
            "https://shop.example/p?track=1&keep=3",
            RequestKind::Document,
        ),
        "https://shop.example/p?track=1&keep=3",
        "an enabled exception still protects it"
    );
}

#[test]
fn a_badfilter_cancels_only_the_rule_spelling_it_repeats() {
    // The identity the engine uses, and therefore the one this must use: the whole original rule,
    // including the `removeparam` value and any content type, with option order irrelevant. `$badfilter`
    // is not a wildcard — a rule that differs in its value or its type scope is a different rule.
    // (Asked of the engine directly by `the_badfilter_identity_matches_the_engine`.)
    //
    // Every request here is a `Document`, so a `$xmlhttprequest` rule is out of scope and a `$document`
    // one is in scope; each case picks the pair that makes the cancellation *observable*.
    for (what, lists, expected) in [
        (
            "a different value is a different rule: `track` keeps working when `other` is cancelled",
            &[
                "||shop.example^$removeparam=track\n||shop.example^$removeparam=other",
                "||shop.example^$removeparam=other,badfilter",
            ][..],
            "https://shop.example/p?other=2&keep=3",
        ),
        (
            "a different type scope is a different rule: the `$document` rule survives its untyped twin's cancellation",
            &[
                "||shop.example^$document,removeparam=track\n||shop.example^$document,removeparam=track,badfilter",
                "||shop.example^$removeparam=track",
            ][..],
            // The untyped rule is untyped, so it is document-only here and still in force: `track` goes.
            "https://shop.example/p?other=2&keep=3",
        ),
        (
            "the same rule spelled with another option in between is still the same rule",
            &[
                "||shop.example^$removeparam=track",
                "||shop.example^$domain=shop.example,removeparam=track\n||shop.example^$removeparam=track,domain=shop.example,badfilter",
            ][..],
            // The domain-scoped copy is cancelled; the unscoped rule is a different line and stays.
            "https://shop.example/p?other=2&keep=3",
        ),
        (
            "cancelling the only rule that names a parameter leaves it alone",
            &[
                "||shop.example^$removeparam=track\n||shop.example^$removeparam=other",
                "||shop.example^$removeparam=track,badfilter",
            ][..],
            "https://shop.example/p?track=1&keep=3",
        ),
        (
            "an untyped rule is cancelled for a document too, which is where it would have fired",
            &[
                "||shop.example^$removeparam=track\n||shop.example^$removeparam=track,badfilter\n||shop.example^$removeparam=other",
            ][..],
            "https://shop.example/p?track=1&keep=3",
        ),
    ] {
        assert_eq!(
            production_url_lists(lists, "https://shop.example/p?track=1&other=2&keep=3", RequestKind::Document),
            expected,
            "{what}; lists {lists:?}"
        );
    }
}

#[test]
fn a_badfilter_works_for_every_matcher_form_and_keeps_the_order_irrelevant() {
    // The regex, inverted and bare forms are all this core's own, so their disable relationship is
    // resolved here too — and the answer must not depend on which list was read first.
    let rules = [
        "||shop.example^$document,removeparam=track",
        "||shop.example^$document,removeparam=/^unused/",
        "||shop.example^$document,removeparam=~keep",
        "||shop.example^$document,removeparam,badfilter",
        "@@||shop.example^$document,removeparam=safe",
    ];
    // Disabling the bare rule leaves the other two in force: `track` goes by name, `unused_x` by regex,
    // `safe` is protected by the exception and `keep` survives the inversion because it is named.
    let url = "https://shop.example/p?track=1&unused_x=2&keep=3&safe=4";
    let expected = "https://shop.example/p?keep=3&safe=4";
    for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 4, 0, 3, 1], [3, 0, 4, 1, 2]] {
        let lists: Vec<&str> = order.iter().map(|index| rules[*index]).collect();
        assert_eq!(
            production_url_lists(&lists, url, RequestKind::Document),
            expected,
            "order {order:?}"
        );
    }
    // With an *active* bare rule the query is emptied apart from what the exception protects. Spelled as
    // its own list because the rule above is cancelled by its `$badfilter`, and a cancelled rule is not a
    // rule: leaving the line out entirely would be a different (and weaker) check.
    let mut active = rules.to_vec();
    active.retain(|rule| !rule.contains("badfilter"));
    active.push("||shop.example^$document,removeparam");
    assert_eq!(
        production_url_lists(&active, url, RequestKind::Document),
        "https://shop.example/p?safe=4",
        "the bare rule prunes everything the exception does not name"
    );
}

#[test]
fn a_disabled_rule_stays_disabled_across_a_serialize_reload_and_a_hot_reload() {
    // A `$badfilter` line has to travel in `extras.txt` beside the rules it cancels, or the correction
    // would work until the next process start and then silently stop.
    let lists = [
        "||shop.example^$removeparam=track\n||shop.example^$removeparam=track,badfilter",
        "||shop.example^$removeparam=other\n@@||shop.example^$document,removeparam=other",
        "@@||shop.example^$document,removeparam=other,badfilter",
    ];
    let url = "https://shop.example/p?track=1&other=2&keep=3";
    // `track`'s own rule is cancelled, so `track` survives; `other`'s exception is cancelled, so `other`
    // goes. Two different outcomes in one request, which is what makes a lost `$badfilter` visible.
    let before = production_url_lists(&lists, url, RequestKind::Document);
    assert_eq!(before, "https://shop.example/p?track=1&keep=3");

    // Serialize the whole container and rebuild from that text alone.
    let serialized = collect(lists.iter().copied()).serialize_lines();
    let reloaded = production_url_lists(&[serialized.as_str()], url, RequestKind::Document);
    assert_eq!(reloaded, before, "the reloaded rule set must decide the same URL");

    // And the same through a hot reload of a live filter.
    use crate::http::rewrite::ModifierSource;
    let mut set = adblock::lists::FilterSet::new(false);
    for list in lists {
        set.add_filter_list(list.to_string(), adblock::lists::ParseOptions::default());
    }
    let filter = std::sync::Arc::new(
        crate::http::decision::HttpFilter::new(adblock::Engine::new_with_filter_set(set))
            .with_extras(std::sync::Arc::new(collect(lists.iter().copied()))),
    );
    let modifiers = crate::https::modifiers::HttpsModifiers::new(
        std::sync::Arc::clone(&filter),
        std::sync::Arc::new(crate::https::modifiers::collect_removeheader(std::iter::empty())),
        std::sync::Arc::clone(&filter.extras_arc()),
    );
    let request = request_with(url, Some("https://shop.example/"), RequestKind::Document);
    assert_eq!(
        modifiers.edits(&request, RequestKind::Document).and_then(|edits| edits.url).as_deref(),
        Some("https://shop.example/p?track=1&keep=3")
    );
    filter.replace_extras(std::sync::Arc::new(collect([serialized.as_str()])));
    assert_eq!(
        modifiers.edits(&request, RequestKind::Document).and_then(|edits| edits.url).as_deref(),
        Some("https://shop.example/p?track=1&keep=3"),
        "a reload through the production entry must decide the same URL"
    );
}

#[test]
fn the_badfilter_identity_matches_the_engine() {
    // The disable relationship is decided here, but it has to be the engine's relationship — otherwise a
    // rule the engine still applies would be skipped, or one it cancelled would fire. Each pair below is
    // asked of the engine's own parser (`get_id`, which excludes only the badfilter bit) and of this
    // core, and the two must agree.
    for (base, other, same) in [
        ("||shop.example^$removeparam=track", "||shop.example^$removeparam=track,badfilter", true),
        ("||shop.example^$removeparam=track", "||shop.example^$badfilter,removeparam=track", true),
        ("||shop.example^$removeparam=track", "||shop.example^$removeparam=other,badfilter", false),
        ("||shop.example^$removeparam=track", "||shop.example^$xmlhttprequest,removeparam=track,badfilter", false),
        ("@@||shop.example^$removeparam=track", "@@||shop.example^$removeparam=track,badfilter", true),
        ("@@||shop.example^$removeparam=track", "||shop.example^$removeparam=track,badfilter", false),
        ("||shop.example^$removeparam", "||shop.example^$removeparam,badfilter", true),
        ("||shop.example^$removeparam=track,domain=a.example", "||shop.example^$domain=a.example,removeparam=track,badfilter", true),
    ] {
        let engine_id = |line: &str| {
            let (filters, _) = adblock::lists::parse_filters([line], false, adblock::lists::ParseOptions::default());
            filters.first().map(|filter| filter.get_id())
        };
        // This core always has an opinion — including for an `@@…$removeparam=…` line, which the engine's
        // parser refuses outright and therefore cannot identify at all. Where the engine *does* parse both
        // lines its identity is the reference; where it parses neither, only our own consistency is
        // checkable (and the behavioural tests above are the real check).
        assert_eq!(
            badfilter_key(base) == badfilter_key(other),
            same,
            "this core's view of {base} vs {other}"
        );
        if let (Some(base_id), Some(other_id)) = (engine_id(base), engine_id(other)) {
            assert_eq!(
                base_id == other_id,
                same,
                "the engine's view of {base} vs {other}"
            );
        }
    }
}

#[test]
fn the_reported_rule_count_excludes_directives_and_cancelled_rules() {
    // "N removeparam rules" in the compile log, the stats JSON and the stats screen all come from `len`.
    // Advertising a rule that a `$badfilter` disabled is how a device log once reported 198 rules while
    // 178 were in force, so the count has to mean "rules that decide a request".
    let rules = collect(["\n\
||shop.example^$removeparam=track\n\
||shop.example^$removeparam=track,badfilter\n\
||shop.example^$removeparam=other\n\
@@||shop.example^$removeparam=other\n\
@@||shop.example^$removeparam=other,badfilter"]);
    // Four lines name a parameter; two of them are cancelled; one is a directive. `other` remains.
    assert_eq!(rules.removeparam.len(), 1, "only the still-valid `other` rule is in force");
    // Cancelled rules and the directive are still held (they are what a reload needs), and `rules()` says so.
    assert_eq!(rules.removeparam.rules().len(), 5);
    assert!(!rules.removeparam.is_empty());

    // Every collected rule cancelled: nothing is in force, and the report has to show zero.
    let rules = collect(["||a.example^$removeparam=x\n||a.example^$removeparam=x,badfilter"]);
    assert_eq!(rules.removeparam.len(), 0);
    assert!(rules.removeparam.is_empty());
}

#[test]
fn a_badfilter_directive_does_not_consume_a_rule_slot() {
    // The cap bounds rules that will be evaluated. If a directive counted, a subscription of 4,096
    // directives would exhaust the cap and leave no room for the rules they were meant to disable.
    let mut body = String::new();
    for index in 0..(MAX_REMOVEPARAM_RULES + 32) {
        body.push_str(&format!("||d{index}.example^$removeparam=track,badfilter\n"));
    }
    let rules = collect([body.as_str()]);
    assert_eq!(rules.removeparam.len(), 0, "directives are not rules");
    assert!(
        rules.removeparam.rejected().is_empty(),
        "no directive may be refused for the cap: {:?}",
        rules.removeparam.rejected().first()
    );
    // And the rules that follow still fit.
    let with_rules = format!("{body}||shop.example^$removeparam=track\n");
    let rules = collect([with_rules.as_str()]);
    assert_eq!(rules.removeparam.len(), 1);
}

#[test]
fn one_badfilter_cancels_every_copy_of_the_rule_it_names() {
    // The engine collects the `$badfilter` ids and then drops **every** rule carrying one of them, so a
    // duplicate identical line is cancelled too — `$badfilter` disables a rule, not an occurrence of it.
    // Two copies in the list therefore behave exactly like one, which is the answer the reference evaluator
    // and the engine both give.
    let users = "\
||shop.example^$removeparam=track\n\
||shop.example^$removeparam=track\n\
||shop.example^$removeparam=track,badfilter\n\
||shop.example^$removeparam=other";
    assert_eq!(
        production_url_lists(&[users], "https://shop.example/p?track=1&other=2&keep=3", RequestKind::Document),
        "https://shop.example/p?track=1&keep=3",
        "both copies of the cancelled rule are gone, so `track` survives"
    );
    let rules = collect([users]);
    assert_eq!(rules.removeparam.len(), 1, "only the `other` rule is in force");
    assert_eq!(rules.removeparam.rules().len(), 4, "every line is still held for the reload");
}

#[test]
fn badfilter_preserves_matcher_case_and_normalises_type_aliases_in_production() {
    for (rules, url, expected, kind) in [
        ("||shop.example^$removeparam=TRACK\n||shop.example^$removeparam=track,badfilter\n||shop.example^$removeparam=other",
         "https://shop.example/p?TRACK=1&other=2&keep=3", "https://shop.example/p?keep=3", RequestKind::Document),
        ("||shop.example^$removeparam=/^TAG=/\n||shop.example^$removeparam=/^tag=/,badfilter\n||shop.example^$removeparam=other",
         "https://shop.example/p?TAG=1&other=2&keep=3", "https://shop.example/p?keep=3", RequestKind::Document),
        ("||shop.example^$xmlhttprequest,removeparam=track\n||shop.example^$xhr,removeparam=track,badfilter\n||shop.example^$xmlhttprequest,removeparam=other",
         "https://shop.example/p?track=1&other=2&keep=3", "https://shop.example/p?track=1&keep=3", RequestKind::Xhr),
        (r"||shop.example^$removeparam=/^tag=\D+$/
||shop.example^$removeparam=/^tag=\d+$/,badfilter
||shop.example^$removeparam=other",
         "https://shop.example/p?tag=abc&tag=123&other=2&keep=3", "https://shop.example/p?tag=123&keep=3", RequestKind::Document),
    ] {
        assert_eq!(production_url_lists(&[rules], url, kind), expected, "{rules}");
        let serialized = collect([rules]).serialize_lines();
        assert_eq!(production_url_lists(&[&serialized], url, kind), expected, "reloaded {rules}");
    }
}

#[test]
fn badfilter_identity_uses_parsed_scope_and_exact_modifier_bytes() {
    let pairs = [
        ("||shop.example^$removeparam=TRACK", "||shop.example^$removeparam=track,badfilter", false),
        ("||shop.example^$removeparam=/^TAG=/", "||shop.example^$removeparam=/^tag=/,badfilter", false),
        (r"||shop.example^$removeparam=/\D/", r"||shop.example^$removeparam=/\d/,badfilter", false),
        ("||shop.example^$xmlhttprequest,removeparam=track", "||shop.example^$xhr,removeparam=track,badfilter", true),
        ("||shop.example^$document,removeparam=track", "||shop.example^$doc,removeparam=track,badfilter", true),
        ("||shop.example^$third-party,removeparam=track", "||shop.example^$3p,removeparam=track,badfilter", true),
        ("||shop.example^$domain=a.example|b.example,removeparam=track", "||shop.example^$domain=b.example|a.example,removeparam=track,badfilter", true),
        ("||shop.example/PATH$removeparam=track", "||shop.example/path$removeparam=track,badfilter", true),
        ("||shop.example/PATH$match-case,removeparam=track", "||shop.example/path$match-case,removeparam=track,badfilter", false),
        ("||shop.example^$removeparam=track", "||shop.example^$document,removeparam=track,badfilter", false),
    ];
    for (original, disabling, equal) in pairs {
        assert_eq!(badfilter_key(original) == badfilter_key(disabling), equal, "{original} / {disabling}");
        let id = |line: &str| {
            let (filters, _) = adblock::lists::parse_filters([line], false, adblock::lists::ParseOptions::default());
            filters.first().map(|filter| filter.get_id())
        };
        if let (Some(a), Some(b)) = (id(original), id(disabling)) {
            assert_eq!(a == b, equal, "engine: {original} / {disabling}");
        }
    }
}

#[test]
fn a_badfilter_naming_a_rule_that_is_not_in_force_changes_nothing() {
    // The directive is inert when no rule matches it. Resolving it must not accidentally cancel anything
    // else, which is the failure mode of comparing the wrong identity (a stripped form shared by several
    // rules).
    assert_eq!(
        production_url_lists(
            &[
                "||shop.example^$removeparam=track,badfilter",
                "||shop.example^$removeparam=track\n||shop.example^$removeparam=other",
            ],
            "https://shop.example/p?track=1&other=2&keep=3",
            RequestKind::Document,
        ),
        // The directive *is* followed by the rule it names, so `track` is cancelled and `other` is not.
        "https://shop.example/p?track=1&keep=3"
    );
    assert_eq!(
        production_url_lists(
            &[
                "||shop.example^$removeparam=absent,badfilter",
                "||shop.example^$removeparam=track",
            ],
            "https://shop.example/p?track=1&keep=3",
            RequestKind::Document,
        ),
        "https://shop.example/p?keep=3",
        "a directive naming no rule must leave the rule set untouched"
    );
}
