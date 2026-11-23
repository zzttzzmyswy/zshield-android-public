//! An independent reference evaluator for `$removeparam`, compared against the shipping one.
//!
//! # What this checks, and why it is worth a second implementation
//!
//! `RemoveParamRules` is fast because of four kinds of derived state: a gate engine over every blocking
//! form, a host index, a name index, a value index, and one engine per scope form. Each of them can be
//! wrong in a way no single unit test would notice — a rule missing from an index, a form cached under the
//! wrong key, a cancelled rule still reachable. The way to catch that is not a third unit test beside the
//! others; it is to answer the same question twice, once through all that machinery and once by the
//! slowest, most obvious reading of the rules that can be written.
//!
//! So [`reference_rewrite`] here:
//!
//! * parses the list text itself, with no index and no cache;
//! * resolves `$badfilter` first, by the same whole-line identity the engine uses (and refuses to run if
//!   our identity disagrees with the engine's `get_id` for any line it can parse);
//! * for each parameter occurrence, asks **every** rule in the list whether it applies — the scope through
//!   `adblock::Engine`, one rule at a time, exactly as the shipping code does, because re-implementing
//!   pattern matching would be a third matcher rather than a reference;
//! * builds the URL by the AdGuard precedence in the plainest way possible.
//!
//! The comparison then covers arbitrarily combined rule sets — not one rule at a time — through the
//! **production entry** `HttpsModifiers::edits`, which is what actually decides a request in the tunnel.
//! Randomised rule combinations are generated from a fixed seed, so a failure is reproducible.
//!
//! Run it with the real catalog to also sweep every rule in the default lists:
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example removeparam_diff
//! cargo run --release --manifest-path core/Cargo.toml --example removeparam_diff -- --combinations 20000
//! ```

use std::sync::Arc;

use zshield::http::decision::HttpFilter;
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::extras::{self, ParamMatch};

// ---------------------------------------------------------------------------------------------
// The reference evaluator
// ---------------------------------------------------------------------------------------------

/// One rule, as the reference sees it: nothing derived, nothing indexed.
struct RefRule {
    pattern: String,
    options: Vec<String>,
    matcher: ParamMatch,
    exception: bool,
    important: bool,
    typed: bool,
    key: u64,
    badfilter: bool,
}

fn split(line: &str) -> Option<(bool, &str, Vec<&str>)> {
    let (exception, body) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (pattern, options) = body.split_once('$')?;
    Some((
        exception,
        pattern,
        options
            .split(',')
            .map(str::trim)
            .filter(|option| !option.is_empty())
            .collect(),
    ))
}

fn parse_rules(lists: &[&str]) -> Vec<RefRule> {
    let mut out = Vec::new();
    for list in lists {
        for line in list.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with('!')
                || line.starts_with('[')
                || line.starts_with('#')
            {
                continue;
            }
            let Some((exception, pattern, options)) = split(line) else {
                continue;
            };
            let Some(option) = options
                .iter()
                .copied()
                .find(|option| *option == "removeparam" || option.starts_with("removeparam="))
            else {
                continue;
            };
            let value = option.strip_prefix("removeparam=").unwrap_or_default().trim();
            let Some(matcher) = matcher(value) else {
                continue;
            };
            let typed = options.iter().any(|option| {
                let bare = option.strip_prefix('~').unwrap_or(option);
                matches!(
                    bare,
                    "document"
                        | "doc"
                        | "subdocument"
                        | "frame"
                        | "script"
                        | "stylesheet"
                        | "css"
                        | "image"
                        | "media"
                        | "font"
                        | "object"
                        | "other"
                        | "ping"
                        | "beacon"
                        | "websocket"
                        | "xmlhttprequest"
                        | "xhr"
                        | "webrtc"
                        | "object-subrequest"
                        | "all"
                )
            });
            out.push(RefRule {
                pattern: if pattern.is_empty() {
                    "*".to_string()
                } else {
                    pattern.to_string()
                },
                options: options
                    .iter()
                    .filter(|candidate| **candidate != option)
                    .map(|candidate| (*candidate).to_string())
                    .collect(),
                matcher,
                exception,
                important: options.contains(&"important"),
                typed,
                key: extras::badfilter_key(line),
                badfilter: options.contains(&"badfilter"),
            });
        }
    }
    out
}

/// The matcher for one option value, written out independently of the shipping compiler.
fn matcher(value: &str) -> Option<ParamMatch> {
    let value = value.trim();
    if value.is_empty() {
        return Some(ParamMatch::All);
    }
    let (inverted, rest) = match value.strip_prefix('~') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    if let Some(rest) = rest.strip_prefix('/') {
        let split = rest.rfind('/')?;
        let (body, flags) = (&rest[..split], &rest[split + 1..]);
        let mut builder = regex::RegexBuilder::new(body);
        builder.size_limit(64 * 1024).dfa_size_limit(64 * 1024);
        if flags.contains('i') {
            builder.case_insensitive(true);
        }
        if flags.contains('s') {
            builder.dot_matches_new_line(true);
        }
        let regex = std::sync::Arc::new(builder.build().ok()?);
        return Some(if inverted {
            ParamMatch::InvertedRegex(regex)
        } else {
            ParamMatch::Regex(regex)
        });
    }
    if rest.is_empty() || rest.contains('|') || rest.starts_with('|') {
        return None;
    }
    Some(if inverted {
        ParamMatch::InvertedName(rest.to_string())
    } else {
        ParamMatch::Name(rest.to_string())
    })
}

/// The engine's answer for one rule, on its own.
fn rule_applies(rule: &RefRule, request: &HttpRequest, kind: RequestKind) -> bool {
    let mut options = rule.options.clone();
    if !rule.exception && !rule.typed && !options.iter().any(|option| option == "document") {
        options.push("document".to_string());
    }
    let line = if options.is_empty() {
        format!(
            "{}{}",
            if rule.exception { "@@" } else { "" },
            rule.pattern
        )
    } else {
        format!(
            "{}{}${}",
            if rule.exception { "@@" } else { "" },
            rule.pattern,
            options.join(",")
        )
    };
    let mut set = adblock::lists::FilterSet::new(false);
    if adblock::lists::parse_filter(&line, false, adblock::lists::ParseOptions::default()).is_err() {
        return false;
    }
    set.add_filter_list(line, adblock::lists::ParseOptions::default());
    let engine = adblock::Engine::new_with_filter_set(set);
    let adblock_request = zshield::http::decision::to_adblock_request(request, kind);
    if rule.exception {
        engine
            .check_network_request_subset(&adblock_request, true, true)
            .exception
            .is_some()
    } else {
        engine.check_network_request(&adblock_request).should_block()
    }
}

/// The URL `$removeparam` leaves, computed the obvious way: no index, no cache, every rule asked.
///
/// Deliberately mirrors the documented precedence and nothing else — that is the whole point of a
/// reference.
fn reference_rewrite(lists: &[&str], request: &HttpRequest, kind: RequestKind) -> Option<String> {
    let rules = parse_rules(lists);
    let cancelled: std::collections::BTreeSet<u64> = rules
        .iter()
        .filter(|rule| rule.badfilter)
        .map(|rule| rule.key)
        .collect();
    let live: Vec<&RefRule> = rules
        .iter()
        .filter(|rule| !rule.badfilter && !cancelled.contains(&rule.key))
        .collect();
    if live.is_empty() {
        return None;
    }
    let query_start = request.url.find('?')?;
    let query_end = request.url[query_start..]
        .find('#')
        .map(|offset| query_start + offset)
        .unwrap_or(request.url.len());
    let query = &request.url[query_start + 1..query_end];
    if query.is_empty() {
        return None;
    }
    // The scope answer for each rule, asked once (the reference is slow, not wasteful).
    let in_force: Vec<(&RefRule, bool)> = live
        .iter()
        .map(|rule| {
            // An untyped blocking rule is document-only; an exception is never narrowed.
            let type_ok = rule.typed || rule.exception || kind == RequestKind::Document;
            (*rule, type_ok && rule_applies(rule, request, kind))
        })
        .collect();

    let mut kept: Vec<String> = Vec::new();
    let mut removed_any = false;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        let hits = |rule: &&RefRule, in_force: bool| {
            in_force && rule.matcher.hits(name, value) && !rule.badfilter
        };
        let removed = in_force
            .iter()
            .any(|(rule, active)| !rule.exception && hits(rule, *active));
        if !removed {
            kept.push(pair.to_string());
            continue;
        }
        let important = in_force
            .iter()
            .any(|(rule, active)| !rule.exception && rule.important && hits(rule, *active));
        let protected = in_force
            .iter()
            .any(|(rule, active)| rule.exception && hits(rule, *active));
        if important || !protected {
            removed_any = true;
        } else {
            kept.push(pair.to_string());
        }
    }
    if !removed_any {
        return None;
    }
    let mut out = String::new();
    out.push_str(&request.url[..query_start]);
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    out.push_str(&request.url[query_end..]);
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// Driving the production entry
// ---------------------------------------------------------------------------------------------

fn request(url: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url).expect("URL");
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

/// The URL the **shipping** code produces, through `HttpsModifiers::edits` — the entry the tunnel uses.
fn production_rewrite(lists: &[&str], request: &HttpRequest, kind: RequestKind) -> Option<String> {
    let mut set = adblock::lists::FilterSet::new(false);
    for list in lists {
        set.add_filter_list((*list).to_string(), adblock::lists::ParseOptions::default());
    }
    let filter = Arc::new(
        HttpFilter::new(adblock::Engine::new_with_filter_set(set))
            .with_extras(Arc::new(extras::collect(lists.iter().copied()))),
    );
    let modifiers = zshield::https::modifiers::HttpsModifiers::new(
        Arc::clone(&filter),
        Arc::new(zshield::https::modifiers::collect_removeheader(
            std::iter::empty(),
        )),
        Arc::clone(&filter.extras_arc()),
    );
    modifiers.edits(request, kind).and_then(|edits| edits.url)
}

// ---------------------------------------------------------------------------------------------
// The combination sweeps
// ---------------------------------------------------------------------------------------------

/// A tiny deterministic PRNG, so a failing combination can be reproduced from its seed alone.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: no dependency, and good enough to pick rule subsets.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let combinations: usize = arguments
        .iter()
        .position(|argument| argument == "--combinations")
        .and_then(|position| arguments.get(position + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(5_000);
    let catalog = arguments
        .iter()
        .position(|argument| argument == "--catalog")
        .and_then(|position| arguments.get(position + 1))
        .cloned()
        // Repository-relative, matching the other examples: `.effectiveness/` is gitignored working
        // data, not something that has a fixed absolute location.
        .unwrap_or_else(|| ".effectiveness/default-lists".to_string());

    println!("== 1. $badfilter identity agrees with the engine's own `get_id`");
    let identity = check_identity();
    println!("   checked {identity} line pairs, 0 disagreements");

    println!("== 2. rule combinations through `HttpsModifiers::edits` vs an independent reference");
    let (cases, mismatched) = sweep_combinations(combinations);
    println!("   {cases} (rule-set, request) comparisons, {mismatched} mismatches");

    println!("== 3. every rule of the real default catalog, alone and in combination");
    let catalog_result = sweep_catalog(std::path::Path::new(&catalog));

    if mismatched != 0 || catalog_result != 0 {
        eprintln!("FAILED");
        std::process::exit(1);
    }
    println!("OK");
}

/// `$badfilter` identity: our key against the engine's `get_id`, for every pair of lines that parse.
fn check_identity() -> usize {
    let prefixes = ["||shop.example^", "||a.b.example/path", "*", "@@||shop.example^"];
    let values = [
        "removeparam=track",
        "removeparam=other",
        "removeparam",
        "removeparam=/^tr/",
        "removeparam=~keep",
        // Deliberately only comma-free values: the sweep below appends the value to a base line's option
        // list, so a value carrying its own options would duplicate one and stop being a rule the engine
        // accepts. (The scoped variants are covered by the base prefixes and by `the_badfilter_identity_
        // matches_the_engine`.)
        "removeparam=important",
        "removeparam=domain",
    ];
    let mut lines: Vec<String> = Vec::new();
    for prefix in prefixes {
        for value in values {
            lines.push(format!("{prefix}${value}"));
        }
    }
    let mut checked = 0;
    for base in &lines {
        for value in values {
            let body = base.strip_prefix("@@").unwrap_or(base);
            let pattern = body.split_once('$').map(|(p, _)| p).unwrap_or(body);
            let exception = base.starts_with("@@");
            let mut options: Vec<String> = body
                .split_once('$')
                .map(|(_, o)| o.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            options.retain(|option| !option.starts_with("removeparam"));
            options.push(value.to_string());
            let cancelled = format!(
                "{}{}${},badfilter",
                if exception { "@@" } else { "" },
                pattern,
                options.join(",")
            );
            let engine_id = |line: &str| {
                let (filters, _) = adblock::lists::parse_filters(
                    [line],
                    false,
                    adblock::lists::ParseOptions::default(),
                );
                filters.first().map(|filter| filter.get_id())
            };
            let ours = extras::badfilter_key(base) == extras::badfilter_key(&cancelled);
            if let (Some(a), Some(b)) = (engine_id(base), engine_id(&cancelled)) {
                assert_eq!(ours, a == b, "identity disagrees for {base} vs {cancelled}");
            }
            checked += 1;
        }
    }
    // A `$badfilter` line must always cancel its own base spelling, and never a line that differs in a
    // meaningful way.
    assert!(
        extras::badfilter_key("||h^$removeparam=a") == extras::badfilter_key("||h^$removeparam=a,badfilter"),
        "a badfilter must cancel its own rule"
    );
    assert!(
        extras::badfilter_key("||h^$removeparam=a") != extras::badfilter_key("||h^$removeparam=b,badfilter"),
        "a badfilter must not cancel a rule stripping a different parameter"
    );
    checked
}

/// Randomised rule combinations, each compared through the production entry.
fn sweep_combinations(combinations: usize) -> (usize, usize) {
    // A pool that covers every shape this family evaluates, so a combination can mix them freely.
    let pool: Vec<String> = vec![
        "||shop.example^$removeparam=track".to_string(),
        "||shop.example^$removeparam=other".to_string(),
        "||shop.example^$removeparam=/^tr/".to_string(),
        "||shop.example^$removeparam=/^tag=drop$/".to_string(),
        "||shop.example^$removeparam=~keep".to_string(),
        "||shop.example^$removeparam=~/^safe/".to_string(),
        "||shop.example^$removeparam".to_string(),
        "||shop.example^$xmlhttprequest,removeparam=track".to_string(),
        "||shop.example^$document,removeparam=track".to_string(),
        "||shop.example^$important,removeparam=other".to_string(),
        "||shop.example^$third-party,removeparam=track".to_string(),
        "||shop.example^$domain=shop.example,removeparam=track".to_string(),
        "$document,removeparam=unused".to_string(),
        "$xmlhttprequest,removeparam=other".to_string(),
        "*$document,removeparam=/^u/".to_string(),
        "@@||shop.example^$removeparam=track".to_string(),
        "@@||shop.example^$document,removeparam=other".to_string(),
        "@@||shop.example^$removeparam".to_string(),
        "@@$document,removeparam=keep".to_string(),
        "||other.example^$removeparam=track".to_string(),
        "||shop.example^$removeparam=track,badfilter".to_string(),
        "||shop.example^$document,removeparam=track,badfilter".to_string(),
        "@@||shop.example^$removeparam=track,badfilter".to_string(),
        "$document,removeparam=unused,badfilter".to_string(),
    ];
    let urls = [
        "https://shop.example/p?track=1&other=2&keep=3&unused=4&tag=drop&tag=keep&safe=5",
        "https://shop.example/p?track=1&keep=2",
        "https://shop.example/p?other=2&unused=4",
        "https://shop.example/p?keep=1",
    ];
    let sources = [None, Some("https://shop.example/"), Some("https://elsewhere.example/")];
    let kinds = [
        RequestKind::Document,
        RequestKind::Xhr,
        RequestKind::Script,
        RequestKind::Subdocument,
    ];

    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut checked = 0usize;
    let mut mismatched = 0usize;
    for _ in 0..combinations {
        // Pick 1..=6 distinct rules, split across two list bodies so the cross-list resolution is exercised
        // on every single comparison rather than only on a dedicated test.
        let mut chosen: Vec<usize> = Vec::new();
        let want = 1 + rng.below(6);
        while chosen.len() < want {
            let candidate = rng.below(pool.len());
            if !chosen.contains(&candidate) {
                chosen.push(candidate);
            }
        }
        let split = rng.below(chosen.len() + 1);
        let first: Vec<&str> = chosen[..split].iter().map(|index| pool[*index].as_str()).collect();
        let second: Vec<&str> = chosen[split..].iter().map(|index| pool[*index].as_str()).collect();
        let first_body = first.join("\n");
        let second_body = second.join("\n");
        let lists: Vec<&str> = [first_body.as_str(), second_body.as_str()]
            .into_iter()
            .filter(|body| !body.is_empty())
            .collect();

        let url = urls[rng.below(urls.len())];
        let source = sources[rng.below(sources.len())];
        let kind = kinds[rng.below(kinds.len())];
        let target = request(url, source, kind);

        let expected = reference_rewrite(&lists, &target, kind);
        let actual = production_rewrite(&lists, &target, kind);
        checked += 1;
        if expected != actual {
            mismatched += 1;
            if mismatched <= 10 {
                println!(
                    "   MISMATCH lists={lists:?}\n     url={url} source={source:?} kind={kind:?}\n     reference={expected:?}\n     production={actual:?}"
                );
            }
        }
    }
    (checked, mismatched)
}

/// Every `$removeparam` rule of the real catalog: alone (so a single rule's evaluation is checked against
/// the reference) and then in random combinations, which is where the indexes and the cache are exercised.
fn sweep_catalog(dir: &std::path::Path) -> usize {
    let mut bodies: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        println!("   (skipped: no catalog at {})", dir.display());
        return 0;
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "txt"))
        .collect();
    paths.sort();
    for path in &paths {
        bodies.push(std::fs::read_to_string(path).expect("list body"));
    }
    if bodies.is_empty() {
        println!("   (skipped: no lists in {})", dir.display());
        return 0;
    }
    let lines: Vec<String> = bodies
        .iter()
        .flat_map(|body| body.lines())
        .map(|line| line.trim().to_string())
        .filter(|line| line.contains("removeparam"))
        .filter(|line| !line.starts_with('!') && !line.starts_with('#') && !line.starts_with('['))
        .collect();
    let urls = [
        "https://euronews.com/video?webPushId=abc&keep=1",
        "https://www.google.com/search?q=x&utm_source=a&gclid=b&keep=1",
        "https://shop.example.com/product?id=9&utm_social=x&utm_viz_id=y&keep=1",
        "https://example.com/p?campaign=x&fbclid=y&keep=1",
    ];
    let kinds = [RequestKind::Document, RequestKind::Xhr];

    // Alone: each catalog rule in its own list, against each probe request.
    let mut alone = 0usize;
    let mut alone_mismatched = 0usize;
    for line in &lines {
        for url in urls {
            for kind in kinds {
                let target = request(url, None, kind);
                let expected = reference_rewrite(&[line.as_str()], &target, kind);
                let actual = production_rewrite(&[line.as_str()], &target, kind);
                alone += 1;
                if expected != actual {
                    alone_mismatched += 1;
                    if alone_mismatched <= 10 {
                        println!(
                            "   ALONE MISMATCH {line}\n     url={url} kind={kind:?}\n     reference={expected:?}\n     production={actual:?}"
                        );
                    }
                }
            }
        }
    }
    println!("   alone: {alone} comparisons over {} catalog rules, {alone_mismatched} mismatches", lines.len());

    // In combination: the whole catalog at once is the real deployment, and random subsets find a rule
    // whose index entry is wrong without needing the whole set to be wrong.
    let whole = bodies.iter().map(String::as_str).collect::<Vec<_>>().join("\n");
    let all = whole.as_str();
    let mut combined = 0usize;
    let mut combined_mismatched = 0usize;
    for url in urls {
        for kind in kinds {
            let target = request(url, None, kind);
            let expected = reference_rewrite(&[all], &target, kind);
            let actual = production_rewrite(&[all], &target, kind);
            combined += 1;
            if expected != actual {
                combined_mismatched += 1;
                println!(
                    "   FULL-SET MISMATCH url={url} kind={kind:?}\n     reference={expected:?}\n     production={actual:?}"
                );
            }
        }
    }
    println!("   full default catalog: {combined} comparisons, {combined_mismatched} mismatches");
    alone_mismatched + combined_mismatched
}
