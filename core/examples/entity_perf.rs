//! Measure what the entity-`$domain` front filter costs on a real request stream.
//!
//! Acceptance criterion (review item 4): "with the 5 default lists, the average extra cost of
//! `decide_full` (µs/request, `--release`)". The set is the five default-enabled AdGuard lists
//! (`adguard-base`, `-tracking`, `-mobile`, `-url-tracking`, `-chinese`); `docs/EFFECTIVENESS.md` §11.5
//! records the rule counts they contribute.
//!
//! # What is measured
//!
//! The same request stream is decided twice against the same engine, once with an empty
//! [`ExtraModifiers`](zshield::https::extras::ExtraModifiers) and once with the one collected from
//! the five lists. The difference is the cost this iteration added — the engine query, the cosmetic
//! path and the request construction are identical in both runs, so they cancel.
//!
//! Two request shapes are measured, because the front filter's job is to *skip* rules:
//!
//! - **outside**: a source in no entity any rule names (the common case, and the one the front filter
//!   exists for — it should cost almost nothing);
//! - **inside**: a source inside an entity the lists do name (the expensive case: rules are actually
//!   queried).
//!
//! Usage:
//!
//!     cargo run --release --manifest-path core/Cargo.toml --example entity_perf -- <list-dir>

use std::sync::Arc;
use std::time::Instant;

use zshield::http::decision::HttpFilter;
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::https::extras::ExtraModifiers;

/// Build one request against `url`, from `referer`.
fn request(url: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url).expect("probe URL");
    HttpRequest {
        method: "GET".to_string(),
        target: "/".to_string(),
        version: Version::Http11,
        url: parsed.url.clone(),
        host: parsed.hostname().to_string(),
        hostname: parsed.hostname().to_string(),
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

/// Median of a sample, for a number that is not assumed to be symmetric.
fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".effectiveness/default-lists".to_string());
    let mut bodies: Vec<String> = Vec::new();
    for id in [
        "adguard-base",
        "adguard-tracking",
        "adguard-mobile",
        "adguard-url-tracking",
        "adguard-chinese",
    ] {
        let path = format!("{dir}/{id}.txt");
        match std::fs::read_to_string(&path) {
            Ok(text) => bodies.push(text),
            Err(error) => {
                eprintln!("cannot read {path}: {error}");
                std::process::exit(2);
            }
        }
    }

    // The same rule text goes into the engine, so both runs see identical blocking rules; only the
    // set this core evaluates itself differs.
    let mut set = adblock::lists::FilterSet::new(false);
    for body in &bodies {
        set.add_filter_list(body.clone(), adblock::lists::ParseOptions::default());
    }
    let engine = Arc::new(adblock::Engine::new_with_filter_set(set));

    let started = Instant::now();
    let mut populated = ExtraModifiers::default();
    for body in &bodies {
        populated.add_list(body);
    }
    populated.build();
    let collect = started.elapsed();

    let entity_rules = populated.entity_domain.len();
    let entity_forms = populated.entity_domain.rules().len();
    println!(
        "lists: {entity_rules} entity rules ({entity_forms} parsed), {} popup, {} denyallow, {} removeparam",
        populated.popup.len(),
        populated.denyallow.len(),
        populated.removeparam.len()
    );
    println!("collect+build: {:.1} ms", collect.as_secs_f64() * 1000.0);

    let empty = HttpFilter::from_engine(Arc::clone(&engine))
        .with_extras(Arc::new(ExtraModifiers::default()));
    let full = HttpFilter::from_engine(Arc::clone(&engine)).with_extras(Arc::new(populated));

    // The entity one of the lists names, so the "inside" case really is inside.
    let named_entity = full
        .extras()
        .entity_domain
        .rules()
        .iter()
        .find_map(|rule| rule.included.first().map(|entity| entity.name.clone()))
        .unwrap_or_else(|| "example".to_string());

    // Per-family cost of the same probe request, so the total can be attributed rather than guessed
    // at: the number a reader needs is "which of the four rule families costs what".
    {
        let probe = request(
            "https://cdn.example/asset.js",
            Some("https://unrelated-probe.test/page"),
            RequestKind::Script,
        );
        let extras = full.extras();
        let time = |label: &str, f: &dyn Fn()| {
            for _ in 0..50 {
                f();
            }
            let mut samples = Vec::new();
            for _ in 0..15 {
                let started = Instant::now();
                for _ in 0..200 {
                    f();
                }
                samples.push(started.elapsed().as_secs_f64() * 1e6 / 200.0);
            }
            println!("  {label}: {:.3} µs/req", median(&mut samples));
        };
        println!("per-family, source outside every entity:");
        time("entity exempts", &|| {
            extras.entity_domain.exempts(&probe, RequestKind::Script);
        });
        time("entity verdict", &|| {
            extras.entity_domain.verdict(&probe, RequestKind::Script);
        });
        time("denyallow verdict", &|| {
            extras.denyallow.verdict(&probe, RequestKind::Script);
        });
        time("popup blocks", &|| {
            extras.popup.blocks(&probe, RequestKind::Script);
        });
        time("request construction", &|| {
            zshield::http::decision::to_adblock_request(&probe, RequestKind::Script);
        });
    }

    let cases: [(&str, Option<String>); 2] = [
        ("outside any entity", Some("https://unrelated-probe.test/page".to_string())),
        ("inside a named entity", Some(format!("https://{named_entity}.com/page"))),
    ];

    for (label, referer) in cases {
        // A stream of distinct URLs, so no cache can flatter the numbers.
        let requests: Vec<(HttpRequest, RequestKind)> = (0..200)
            .map(|index| {
                let url = format!("https://cdn{index}.example/{index}/asset.js");
                (request(&url, referer.as_deref(), RequestKind::Script), RequestKind::Script)
            })
            .collect();

        let measure = |filter: &HttpFilter| -> f64 {
            // Warm up: the first call pays for lazily built engine state.
            for (probe, kind) in requests.iter().take(20) {
                filter.decide_full(probe, *kind);
            }
            let mut samples = Vec::new();
            for _ in 0..25 {
                let started = Instant::now();
                for (probe, kind) in &requests {
                    filter.decide_full(probe, *kind);
                }
                samples.push(started.elapsed().as_secs_f64() * 1e6 / requests.len() as f64);
            }
            median(&mut samples)
        };

        let base = measure(&empty);
        let with_extras = measure(&full);
        println!(
            "{label}: engine only {base:.3} µs/req, with extras {with_extras:.3} µs/req, \
             added {:+.3} µs/req ({:+.1}%)",
            with_extras - base,
            (with_extras - base) / base * 100.0
        );
    }
}
