//! What one rule costs, one rule at a time (MYS-2826).
//!
//! # Why this exists next to `edits_cost_matrix`
//!
//! `edits_cost_matrix` answers "how expensive is this rule *set*", which is the right question for a
//! regression verdict and the wrong one for an explanation: a rule set differs along a dozen axes at
//! once. This example varies **exactly one** axis — a rule's *shape* — and holds the request, the
//! parameter matcher and the outcome fixed, so the number it reports can be attributed to that axis
//! and nothing else.
//!
//! The shapes are the ones the evaluator in `core/src/https/extras.rs` distinguishes, because each
//! takes a different path through it:
//!
//! | shape | how it is evaluated | what it can cost per request |
//! |---|---|---|
//! | `$removeparam=name`, no pattern | `Scope::Any` — always in force, matcher tested per occurrence | one matcher test |
//! | `$removeparam=/regex/`, no pattern | `Scope::Any` — always in force | one regex test per occurrence, or one engine query |
//! | `\|\|host^$removeparam=/regex/` | `Scope::Host` — hostname comparison, no engine | nothing when the host differs |
//! | `\|\|host/path$removeparam=/regex/` | `Scope::Engine` — one engine query per distinct form | one engine query, cached after the first |
//! | `\|\|host^$script,removeparam=/regex/` | `Scope::Engine`, typed | one engine query, and it applies to a script request |
//! | `@@\|\|host^$removeparam=name` | exception, never narrowed to `document` | one engine query |
//!
//! # The two controls that make a number mean something
//!
//! * **empty** — a rule file with no `$removeparam` rule at all. Whatever this costs is the floor the
//!   entry point pays before looking at any rule, so every other row is `measured − empty`.
//! * **inert** — a rule anchored at a host the request does not use. It is in the same rule set and the
//!   same code path, so if its cost matches `empty`, the cost of the shapes above is attributable to
//!   *evaluation*, not to "the rule set is bigger".
//!
//! # Usage
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example removeparam_rule_shapes -- \
//!     --build-id candidate --rounds 7 --iters 40000
//! ```
//!
//! Output is one JSON object per line, so the A/B driver can concatenate two builds' logs.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use zshield::http::decision::HttpFilter;
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::extras;

/// One measured shape: a label, the rule text, the request it is measured against, and whether the
/// rule is expected to rewrite that request.
struct Shape {
    id: &'static str,
    rule: &'static str,
    url: &'static str,
    kind: RequestKind,
    expectation: &'static str,
}

/// A document request whose query carries one parameter nothing removes, so a rule that matches costs
/// only what it costs to *decide*, not to rebuild a URL.
const DOC: &str = "https://www.example.com/page?page=2&sort=new";
/// The same shape as a subresource, for the typed rules.
const SCRIPT: &str = "https://www.example.com/app.js?page=2&sort=new";

fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            id: "empty",
            rule: "! a rule file with no $removeparam rule at all",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "no rewrite: the entry point returns before looking at any rule",
        },
        Shape {
            // The cheapest possible "there is a rule" case: a `Scope::Host` rule for a host this
            // request is not, so it is screened out with a string comparison and never reaches an
            // engine query of its own. What remains is the gate (`gate_open`), which is one engine
            // query over every blocking form — the price of *having* a rule set at all.
            id: "gate-only",
            rule: "||other.example^$removeparam=zzz",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "no rewrite: scope is a hostname comparison, so only the gate is paid",
        },
        Shape {
            id: "inert-other-parameter",
            rule: "||www.example.com^$document,removeparam=zzz",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "no rewrite: the parameter name is indexed and this URL does not carry it",
        },
        Shape {
            // A plain parameter name **whose pattern is not the `\|\|host^` shortcut**. It is indexed
            // by name, so a request that does not carry the name never looks at it — but when it *is*
            // asked, its scope cannot be screened, so it costs one engine query. This is the shape
            // 564 rules in `adguard-url-tracking` have, and the reason "indexed by name" is not the
            // same as "free".
            id: "name-indexed-engine-form",
            rule: "||www.example.com/page$document,removeparam=page",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "rewrite: indexed by name, but the pattern is not the host shortcut, so the \
                          scope is one engine query",
        },
        Shape {
            id: "name-indexed-hit",
            rule: "||www.example.com^$document,removeparam=page",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "rewrite: page removed by name lookup, no engine query",
        },
        Shape {
            id: "no-pattern-name",
            rule: "$removeparam=page",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "rewrite: applies to every document, no pattern to screen it",
        },
        Shape {
            // A rule with **no pattern** is `Scope::Any`: it cannot be screened by host or by
            // `$domain=`, so `in_force` asks it on every request that opens the gate. Seven of these
            // exist in the five-table set and 397 in `adguard-url-tracking` alone — this shape is the
            // one that decides whether a document request pays per rule or per set.
            id: "no-pattern-regex",
            rule: "$removeparam=/^page=/",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "rewrite: applies to every document, its regex tested against every occurrence",
        },
        Shape {
            id: "no-pattern-bare",
            rule: "$removeparam",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "rewrite: the whole query is dropped, and no screen can rule it out",
        },
        Shape {
            id: "anchored-regex",
            rule: "||www.example.com^$document,removeparam=/^page=/",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "rewrite: host anchor matches, one engine query for the form",
        },
        Shape {
            id: "typed-script-regex",
            rule: "||www.example.com^$script,removeparam=/^page=/",
            url: SCRIPT,
            kind: RequestKind::Script,
            expectation: "rewrite: a typed form is a Scope::Engine form, one engine query",
        },
        Shape {
            id: "exception",
            rule: "@@||www.example.com^$removeparam=page",
            url: DOC,
            kind: RequestKind::Document,
            expectation: "no rewrite on its own: an exception with nothing to cancel removes nothing",
        },
    ]
}

fn request(url: &str, kind: RequestKind) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url).expect("benchmark URL");
    let hostname = parsed.hostname().to_ascii_lowercase();
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
        method: "GET".to_string(),
        target,
        version: Version::Http11,
        url: parsed.url.clone(),
        host: hostname.clone(),
        hostname,
        referer: None,
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

struct Options {
    build_id: String,
    rounds: usize,
    iterations: u32,
    load: usize,
}

fn options() -> Options {
    let mut parsed = Options {
        build_id: "unknown".to_string(),
        rounds: 7,
        iterations: 40_000,
        // How many copies of the shape's rule to put in the set. One answers "does this shape cost
        // anything"; N answers "is the cost per rule or once per set", which is the difference between
        // a scan and a cache.
        load: 1,
    };
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].clone();
        let mut take = |name: &str| -> String {
            index += 1;
            arguments
                .get(index)
                .cloned()
                .unwrap_or_else(|| panic!("{name} needs a value"))
        };
        match argument.as_str() {
            "--build-id" => parsed.build_id = take("--build-id"),
            "--rounds" => parsed.rounds = take("--rounds").parse().expect("--rounds is a number"),
            "--iters" => parsed.iterations = take("--iters").parse().expect("--iters is a number"),
            "--load" => parsed.load = take("--load").parse().expect("--load is a number"),
            other => match other.strip_prefix("--load=") {
                Some(value) => parsed.load = value.parse().expect("--load is a number"),
                None => panic!("unknown argument {other}"),
            },
        }
        index += 1;
    }
    parsed
}

/// `count` copies of one rule, each textually distinct so the compiler cannot merge them and the
/// evaluator cannot answer them with one index entry.
///
/// The `#n` suffix goes in a comment, so the *rule that is evaluated* is identical every time while the
/// file still holds `count` rules. A distinct rule text is what makes N copies cost N rules.
fn repeated(rule: &str, count: usize) -> String {
    let mut out = String::new();
    for index in 0..count {
        out.push_str(&format!("! copy {index}\n{rule}\n"));
    }
    out
}

fn main() {
    let options = options();
    let mut out = String::new();
    for shape in shapes() {
        // `--load` copies of the rule. `empty` is the one shape where a copy is meaningless, so it is
        // measured once regardless.
        let count = if shape.id == "empty" { 1 } else { options.load };
        let text = if shape.id == "empty" {
            shape.rule.to_string() + "\n"
        } else {
            repeated(shape.rule, count)
        };
        let collected = Arc::new(extras::collect([text.as_str()]));
        // The filter and the modifier object exist so the composition is measured too: `edits` is what
        // the relay calls, and it wraps the same evaluator this example prices directly.
        let filter = Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set({
            let mut set = adblock::lists::FilterSet::new(false);
            set.add_filter_list(text.clone(), adblock::lists::ParseOptions::default());
            set
        }))
        .with_extras(Arc::clone(&collected)));
        let modifiers = zshield::https::modifiers::HttpsModifiers::new(
            Arc::clone(&filter),
            Arc::new(zshield::https::modifiers::collect_removeheader([])),
            Arc::clone(&collected),
        );
        let request = request(shape.url, shape.kind);

        // Warm the caches a session warms before its first request.
        for _ in 0..256 {
            black_box(collected.removeparam.rewrite(&request, shape.kind));
        }

        let mut samples = Vec::with_capacity(options.rounds);
        let mut edit_samples = Vec::with_capacity(options.rounds);
        for _ in 0..options.rounds {
            let started = Instant::now();
            for _ in 0..options.iterations {
                black_box(collected.removeparam.rewrite(black_box(&request), shape.kind));
            }
            samples.push(started.elapsed().as_secs_f64() * 1e6 / f64::from(options.iterations));

            let started = Instant::now();
            for _ in 0..options.iterations {
                black_box(modifiers.edits(black_box(&request), shape.kind));
            }
            edit_samples.push(started.elapsed().as_secs_f64() * 1e6 / f64::from(options.iterations));
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        edit_samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let outcome = collected.removeparam.rewrite(&request, shape.kind);

        out.push_str(&format!(
            "{}\n",
            serde_json::json!({
                "record": "shape",
                "build": options.build_id,
                "id": shape.id,
                "rule": shape.rule,
                "rules_in_set": collected.removeparam.len(),
                "rejected": collected.removeparam.rejected().len(),
                "copies": count,
                "iterations": options.iterations,
                "rounds": options.rounds,
                // The floor over rounds: a migration to a busy core can only add time, so the minimum
                // is the cleanest estimate of what the work costs (`docs/reviews/i2-edits-cost.md`).
                "min_us": samples[0],
                "median_us": if samples.len() % 2 == 0 {
                    (samples[samples.len() / 2 - 1] + samples[samples.len() / 2]) / 2.0
                } else {
                    samples[samples.len() / 2]
                },
                "max_us": samples[samples.len() - 1],
                "edits_min_us": edit_samples[0],
                "edits_median_us": if edit_samples.len() % 2 == 0 {
                    (edit_samples[edit_samples.len() / 2 - 1] + edit_samples[edit_samples.len() / 2]) / 2.0
                } else {
                    edit_samples[edit_samples.len() / 2]
                },
                "outcome": outcome,
                "expectation": shape.expectation,
            })
        ));
    }
    print!("{out}");
}
