//! Per-request cost of the `$removeparam` evaluation on the real default catalog.
//!
//! Run with `--release`. The point of the benchmark is the **common** case — a request no rule names —
//! because that is what the tunnel pays for almost every subresource; the interesting case (a URL
//! carrying a tracked parameter) is measured beside it so a regression in either is visible.
use std::sync::Arc;
use std::time::Instant;

use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::{extras, modifiers};

fn request(url: &str, referer: Option<&str>, kind: RequestKind) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url).expect("benchmark URL");
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

fn main() {
    // Repository-relative: the catalog lives in the gitignored `.effectiveness/` directory, so a
    // build machine's absolute path has no meaning on anyone else's checkout.
    let argument = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".effectiveness/default-lists".to_string());
    let dir = std::path::Path::new(&argument);
    let mut bodies: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    if dir.is_dir() {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("list dir")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "txt"))
            .collect();
        entries.sort();
        for path in entries {
            names.push(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string(),
            );
            bodies.push(std::fs::read_to_string(&path).expect("list body"));
        }
    }
    if bodies.is_empty() {
        eprintln!("no lists found in {}; pass the directory as the first argument", dir.display());
        std::process::exit(2);
    }
    let refs: Vec<&str> = bodies.iter().map(String::as_str).collect();

    let started = Instant::now();
    let modifiers = extras::collect(refs.iter().copied());
    let build = started.elapsed();
    eprintln!(
        "compiled {} lists ({}), {} `$removeparam` rules in {} ms, {} rejected",
        bodies.len(),
        names.join(", "),
        modifiers.removeparam.len(),
        build.as_millis(),
        modifiers.removeparam.rejected().len()
    );

    // A whole engine too, so the harness measures the same call the tunnel makes (`edits` asks the main
    // engine for the block decision before this family is consulted).
    let mut set = adblock::lists::FilterSet::new(false);
    for body in &bodies {
        set.add_filter_list(body.clone(), adblock::lists::ParseOptions::default());
    }
    let modifiers = Arc::new(modifiers);
    let filter = Arc::new(
        zshield::http::decision::HttpFilter::new(adblock::Engine::new_with_filter_set(set))
            .with_extras(Arc::clone(&modifiers)),
    );
    let source = modifiers::HttpsModifiers::new(
        Arc::clone(&filter),
        Arc::new(modifiers::collect_removeheader(std::iter::empty())),
        Arc::clone(&filter.extras_arc()),
    );

    // The common case: an ordinary subresource with a query nothing names.
    let cases: Vec<(&str, HttpRequest, RequestKind)> = vec![
        (
            "untouched xhr",
            request(
                "https://cdn.example.com/assets/app.js?v=3&build=8123",
                Some("https://www.example.com/"),
                RequestKind::Xhr,
            ),
            RequestKind::Xhr,
        ),
        (
            "untouched document",
            request(
                "https://www.example.com/page?page=2&sort=new",
                None,
                RequestKind::Document,
            ),
            RequestKind::Document,
        ),
        (
            "tracked document (unscoped rules)",
            request(
                "https://shop.example.com/product?id=9&utm_social=x&utm_viz_id=y&keep=1",
                None,
                RequestKind::Document,
            ),
            RequestKind::Document,
        ),
        (
            "tracked document (host rule)",
            request(
                "https://euronews.com/video?webPushId=abc&keep=1",
                Some("https://www.example.com/"),
                RequestKind::Document,
            ),
            RequestKind::Document,
        ),
        (
            "tracked document, subdomain",
            request(
                "https://sub.euronews.com/video?webPushId=abc&keep=1",
                Some("https://www.example.com/"),
                RequestKind::Document,
            ),
            RequestKind::Document,
        ),
    ];

    let rounds = 20_000u32;
    for (label, target, kind) in &cases {
        // Warm the per-form cache exactly as the first few requests of a session would.
        for _ in 0..16 {
            let _ = source.edits(target, *kind);
        }
        let started = Instant::now();
        let mut rewrites = 0u32;
        for _ in 0..rounds {
            if let Some(edits) = source.edits(target, *kind) {
                if edits.url.is_some() {
                    rewrites += 1;
                }
            }
        }
        let elapsed = started.elapsed();
        println!(
            "{label:26} {:>8.3} us/request  ({} rewrote of {})",
            elapsed.as_secs_f64() * 1e6 / f64::from(rounds),
            rewrites,
            rounds
        );
    }
    println!(
        "cached per-form engines after the run: {} (cap {})",
        modifiers.removeparam.cached_engines(),
        extras::MAX_REMOVEPARAM_SCOPE_ENGINES
    );
}
