//! Per-request cost of the **decrypted-path** entry point, `HttpsModifiers::edits`.
//!
//! Why not `entity_perf`
//! --------------------
//! `entity_perf` measures the HTTP/2 pipeline's entity/extra-modifier lookup. It never builds an
//! `HttpsModifiers`, so it cannot say anything about the code path the I2 change actually touched:
//! the `$removeparam`/`$removeheader`/`$csp` evaluation applied to a decrypted request. A benchmark
//! that skips the new path reports "no regression" by construction. This one calls exactly the trait
//! method the h1 relay and the h2 stream task call (`ModifierSource::edits`), so a regression in it
//! shows up here.
//!
//! What is measured, per list configuration
//! ---------------------------------------
//!   * a request **no rule names** — the common case, and the number that matters for battery
//!   * a request carrying a parameter the set removes (a **hit**)
//!   * a request carrying a parameter nothing names (a **miss**, but with a query, so the query
//!     parsing runs)
//!   * a request with **no query at all**, the cheapest path
//!   * a **POST document** whose URL is rewritten, exercising the navigation branch
//!
//! Two configurations, both built from the same downloaded files so they are comparable:
//!
//!   5 lists — the historical PSS baseline set (`docs/EFFECTIVENESS.md` §13.8)
//!   9 lists — what the catalog actually enables by default
//!
//! Usage
//! -----
//!     cargo run --release --manifest-path core/Cargo.toml --example rebuild_edits_perf -- \
//!         .effectiveness/catalog-lists 5,9
//!
//! The first argument is a directory of `<id>.txt` lists; the second is a comma-separated list of
//! how many of the nine defaults to compile.

use std::sync::Arc;
use std::time::Instant;

use zshield::http::decision::HttpFilter;
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::{extras, modifiers};

/// The nine lists the catalog enables, in the order the app compiles them.
///
/// The first five are the historical PSS baseline set; a run with `5` takes exactly those, which is
/// what makes the two configurations comparable rather than merely similar.
const DEFAULT_ORDER: [&str; 9] = [
    "adguard-base",
    "adguard-tracking",
    "adguard-mobile",
    "adguard-url-tracking",
    "adguard-chinese",
    "adguard-dns",
    "easylist-china",
    "ublock-unbreak",
    "ublock-quick-fixes",
];

fn request(url: &str, method: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url).expect("benchmark URL");
    let hostname = parsed.hostname().to_ascii_lowercase();
    // `target` is the request-target as it appears on the request line: path plus query. It is the
    // string the rewrite reads, so a benchmark that left it empty would measure a different path.
    let target = match url.find("://") {
        Some(index) => {
            let after_scheme = &url[index + 3..];
            match after_scheme.find('/') {
                Some(slash) => after_scheme[slash..].to_string(),
                None => "/".to_string(),
            }
        }
        None => url.to_string(),
    };
    HttpRequest {
        method: method.to_string(),
        target,
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

/// One measured case: a label, the request, its resource kind, and whether an edit is expected.
struct Case<'a> {
    label: &'a str,
    request: HttpRequest,
    kind: RequestKind,
}

fn main() {
    let directory = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".effectiveness/catalog-lists".to_string());
    // A third argument narrows the comparison to the shapes the pre-I2 build could compile. Without
    // it, "candidate is slower on hits" conflates two things: the same work done slower, and 27x
    // more rules actually being evaluated. `--legacy-only` isolates the first.
    let legacy_only = std::env::args().any(|argument| argument == "--legacy-only");
    // Print what each case actually rewrote, as a URL, so two builds can be compared rule-for-rule
    // instead of by timing alone. The stage-4 review's objection to the earlier comparison was that
    // "25 vs 0 rules" proved the two builds were doing different work, not that either was slower:
    // a timing is only attributable when the *outcome* of the work is identical.
    let show_rewrites = std::env::args().any(|argument| argument == "--show-rewrites");
    let counts: Vec<usize> = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "5,9".to_string())
        .split(',')
        .filter_map(|value| value.trim().parse().ok())
        .collect();
    let dir = std::path::Path::new(&directory);
    if !dir.is_dir() {
        eprintln!("{} is not a directory of `<id>.txt` lists", dir.display());
        std::process::exit(2);
    }

    println!("# HttpsModifiers::edits — release build, per-request cost");
    println!(
        "# lists from {}; configurations: {:?}",
        dir.display(),
        counts
    );

    for count in counts {
        let selected = &DEFAULT_ORDER[..count.min(DEFAULT_ORDER.len())];
        let mut bodies = Vec::new();
        let mut names = Vec::new();
        let mut bytes = 0usize;
        let mut missing = Vec::new();
        for id in selected {
            let path = dir.join(format!("{id}.txt"));
            match std::fs::read_to_string(&path) {
                Ok(body) => {
                    bytes += body.len();
                    names.push(*id);
                    bodies.push(body);
                }
                Err(_) => missing.push(*id),
            }
        }
        if !missing.is_empty() {
            eprintln!("missing lists for the {count}-list run: {missing:?}");
            std::process::exit(2);
        }

        let refs: Vec<&str> = bodies.iter().map(String::as_str).collect();

        // Build the two halves exactly as `compile.rs` does: the `FilterSet`/`Engine` for the block
        // decisions, and the extras collector for the modifiers the engine does not implement.
        let started = Instant::now();
        let mut set = adblock::lists::FilterSet::new(false);
        for body in &bodies {
            set.add_filter_list(body.clone(), adblock::lists::ParseOptions::default());
        }
        let engine = adblock::Engine::new_with_filter_set(set);
        let engine_ms = started.elapsed().as_secs_f64() * 1e3;

        // The filter the old build effectively applied: only the option forms its parser accepted.
        // A rule is kept when it has **no** value, or a value that is not a regex, not inverted and
        // not percent-encoded — exactly the four forms the review found the engine rejects.
        let narrowed: Vec<String> = if legacy_only {
            bodies
                .iter()
                .map(|body| {
                    body.lines()
                        .filter(|line| {
                            let Some(position) = line.find("$removeparam") else {
                                return true;
                            };
                            let tail = &line[position + "$removeparam".len()..];
                            let value = tail.split(',').next().unwrap_or("").trim_start_matches('=');
                            value.is_empty()
                                || (!value.starts_with('/')
                                    && !value.starts_with('~')
                                    && !value.contains("%24"))
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .collect()
        } else {
            bodies.clone()
        };
        let narrowed_refs: Vec<&str> = narrowed.iter().map(String::as_str).collect();

        let started = Instant::now();
        let collected = extras::collect(narrowed_refs.iter().copied());
        let extras_ms = started.elapsed().as_secs_f64() * 1e3;
        let removeparam = collected.removeparam.len();
        let rejected = collected.removeparam.rejected().len();
        let removeheader = modifiers::collect_removeheader(refs.iter().copied()).len();

        let filter = Arc::new(HttpFilter::new(engine).with_extras(Arc::new(collected)));
        let source = modifiers::HttpsModifiers::new(
            Arc::clone(&filter),
            Arc::new(modifiers::collect_removeheader(narrowed_refs.iter().copied())),
            filter.extras_arc(),
        );

        println!();
        println!("## {count} lists: {}", names.join(", "));
        println!(
            "##   {bytes} B of list text, {removeparam} $removeparam ({rejected} rejected), \
             {removeheader} $removeheader; engine {engine_ms:.0} ms, extras {extras_ms:.0} ms"
        );

        // The cases. `track=` and `utm_source=` are the shapes real lists use; the "no rule names"
        // cases are what almost every subresource looks like.
        let cases = [
            Case {
                label: "no rule names it (no query)",
                request: request(
                    "https://cdn.example.com/assets/app.js",
                    "GET",
                    Some("https://www.example.com/"),
                    RequestKind::Script,
                ),
                kind: RequestKind::Script,
            },
            Case {
                label: "no rule names it (with query)",
                request: request(
                    "https://cdn.example.com/assets/app.js?v=3&build=8123",
                    "GET",
                    Some("https://www.example.com/"),
                    RequestKind::Script,
                ),
                kind: RequestKind::Script,
            },
            Case {
                label: "xhr, no rule names it",
                request: request(
                    "https://api.example.com/v1/items?page=2&sort=new",
                    "GET",
                    Some("https://www.example.com/"),
                    RequestKind::Xhr,
                ),
                kind: RequestKind::Xhr,
            },
            Case {
                label: "document, no rule names it",
                request: request(
                    "https://www.example.com/page?page=2&sort=new",
                    "GET",
                    None,
                    RequestKind::Document,
                ),
                kind: RequestKind::Document,
            },
            Case {
                // Measured to NOT rewrite with these lists: `utm_source` is not removed by an
                // unscoped rule here. The label says what it is, not what it was hoped to be —
                // the `edited` column is the authority.
                label: "utm_source (no matching rule)",
                request: request(
                    "https://shop.example.com/product?id=9&utm_source=news&keep=1",
                    "GET",
                    None,
                    RequestKind::Document,
                ),
                kind: RequestKind::Document,
            },
            Case {
                label: "pjclid (unscoped hit)",
                request: request(
                    "https://news.example.com/story?pjclid=abc123&keep=1",
                    "GET",
                    Some("https://news.example.com/"),
                    RequestKind::Xhr,
                ),
                kind: RequestKind::Xhr,
            },
            Case {
                label: "host-scoped hit (zhihu)",
                request: request(
                    "https://www.zhihu.com/question/1?share_code=xyz&utm_psn=2&keep=1",
                    "GET",
                    None,
                    RequestKind::Document,
                ),
                kind: RequestKind::Document,
            },
            Case {
                // Matches `$removeparam=/^weekend-reading-link-\d{6}$/`, which the engine rejects
                // and the core evaluates itself — the path I2 added. Measured to NOT rewrite here
                // (the rule carries a host/type scope this URL does not satisfy), so it is a
                // control for "a regex rule that does not apply costs the scan, not a rewrite".
                label: "regex rule, does not apply",
                request: request(
                    "https://www.example.com/a?weekend-reading-link-260101=1&keep=1",
                    "GET",
                    None,
                    RequestKind::Document,
                ),
                kind: RequestKind::Document,
            },
            Case {
                label: "POST document, rewrite expected",
                request: request(
                    "https://euronews.com/video?webPushId=abc&keep=1",
                    "POST",
                    Some("https://www.example.com/"),
                    RequestKind::Document,
                ),
                kind: RequestKind::Document,
            },
            Case {
                label: "image, no rule names it",
                request: request(
                    "https://img.example.com/a.png?w=640&h=480",
                    "GET",
                    Some("https://www.example.com/"),
                    RequestKind::Image,
                ),
                kind: RequestKind::Image,
            },
        ];

        let rounds = 20_000u32;
        println!(
            "##   {:<34} {:>10} {:>8}  note",
            "case", "us/request", "edited"
        );
        for case in &cases {
            // Warm the per-form caches the way the first requests of a session do, so the number is
            // steady-state rather than first-call.
            for _ in 0..16 {
                let _ = source.edits(&case.request, case.kind);
            }
            let mut edited = 0u32;
            let mut samples = Vec::with_capacity(5);
            // Five interleaved rounds, reporting the **median**: a single timing on a machine that
            // also runs an emulator and a build is otherwise dominated by scheduling noise.
            for _ in 0..5 {
                let started = Instant::now();
                for _ in 0..rounds {
                    if let Some(edits) = source.edits(&case.request, case.kind) {
                        if edits.url.is_some() {
                            edited += 1;
                        }
                    }
                }
                samples.push(started.elapsed().as_secs_f64() * 1e6 / f64::from(rounds));
            }
            samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let median = samples[samples.len() / 2];
            println!(
                "   {:34} {median:>10.3} {:>8}  min {:.3} max {:.3}",
                case.label,
                edited / 5,
                samples[0],
                samples[samples.len() - 1]
            );
            if show_rewrites {
                // The exact outcome, so a comparison across builds is about the same edit and not
                // merely about two numbers produced by different rule sets.
                let outcome = match source.edits(&case.request, case.kind) {
                    None => "None (no edit)".to_string(),
                    Some(edits) => match &edits.url {
                        Some(url) => format!("url -> {url}"),
                        None => "Some(no url change)".to_string(),
                    },
                };
                println!("   {:34} {outcome}", "  rewrite");
            }
        }
    }
}
