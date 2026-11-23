//! What the `$removeparam` rule set costs in memory, and how far its per-form cache actually grows.
//!
//! The delivery note has to state the capacity and ownership of every cache this family adds, so this
//! measures them on the real catalog rather than quoting a bound: resident memory for the compiled set, the
//! number of per-form engines a realistic request stream builds, and the point at which the cache is
//! cleared.
//!
//! Run with the default five-list catalog:
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example removeparam_footprint
//! ```
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::https::extras;

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")
                    .map(|rest| rest.trim().trim_end_matches(" kB").trim().parse().unwrap_or(0))
            })
        })
        .unwrap_or(0)
}

fn request(url: &str, kind: RequestKind) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url).expect("URL");
    let hostname = parsed.hostname().to_ascii_lowercase();
    HttpRequest {
        method: "GET".to_string(),
        target: "/".to_string(),
        version: Version::Http11,
        url: parsed.url.clone(),
        host: hostname.clone(),
        hostname,
        referer: Some("https://www.example.com/".to_string()),
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
    // Relative to the repository root, like every other example here: the catalog is produced by
    // `scripts/effectiveness/run.sh` into `.effectiveness/`, which is gitignored, so an absolute path
    // from one machine would be wrong everywhere else.
    let argument = std::env::args()
        .nth(1)
        .unwrap_or_else(|| ".effectiveness/default-lists".to_string());
    let dir = std::path::Path::new(&argument);
    let mut bodies: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!("no catalog at {}", dir.display());
        std::process::exit(2);
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
    let refs: Vec<&str> = bodies.iter().map(String::as_str).collect();

    let before = rss_kb();
    let started = std::time::Instant::now();
    let modifiers = extras::collect(refs);
    let elapsed = started.elapsed();
    let after = rss_kb();
    let rules = &modifiers.removeparam;
    println!(
        "compile: {} ms, RSS +{} KiB",
        elapsed.as_millis(),
        after.saturating_sub(before)
    );
    println!(
        "rules in force: {}, collected (incl. directives/cancelled): {}, distinct scope forms: {}, rejected: {}",
        rules.len(),
        rules.rules().len(),
        rules.scope_form_count(),
        rules.rejected().len()
    );
    println!(
        "cache: {} engines after compile, cap {} (~{} KiB each measured, so <= ~{} MiB)",
        rules.cached_engines(),
        extras::MAX_REMOVEPARAM_SCOPE_ENGINES,
        24,
        extras::MAX_REMOVEPARAM_SCOPE_ENGINES * 24 / 1024
    );

    // A realistic stream: ordinary subresources (no rule names them) and documents carrying tracked
    // parameters, across hosts that the catalog's anchored forms name.
    let base = rss_kb();
    let urls = [
        ("https://cdn.example.com/assets/app.js?v=3&build=8123", RequestKind::Xhr),
        ("https://www.example.com/page?page=2&sort=new", RequestKind::Document),
        ("https://euronews.com/video?webPushId=abc&keep=1", RequestKind::Document),
        ("https://sub.euronews.com/video?webPushId=abc&keep=1", RequestKind::Document),
        ("https://shop.example.com/p?utm_social=x&utm_viz_id=y&keep=1", RequestKind::Document),
        ("https://www.google.com/search?q=x&gclid=b&keep=1", RequestKind::Document),
    ];
    let mut peak_cache = 0;
    for round in 0..500 {
        for (url, kind) in urls {
            let _ = rules.rewrite(&request(url, kind), kind);
        }
        peak_cache = peak_cache.max(rules.cached_engines());
        if round == 0 {
            println!("after the first pass over {urls:?}", urls = urls.len());
        }
    }
    println!(
        "after 500 passes over {} request shapes: peak cached engines {}, now {}, RSS +{} KiB",
        urls.len(),
        peak_cache,
        rules.cached_engines(),
        rss_kb().saturating_sub(base)
    );

    // Push the cache towards its cap: every anchored form in the catalog, reached by a request to its own
    // host carrying the parameter the rule names. This is the worst case a rule set of this size can
    // produce, and it is what the cap has to hold.
    let cap_base = rss_kb();
    let mut probes = 0usize;
    for body in &bodies {
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            if !line.contains("removeparam") || line.contains("badfilter") {
                continue;
            }
            let body_part = line.strip_prefix("@@").unwrap_or(line);
            let Some((pattern, options)) = body_part.split_once('$') else {
                continue;
            };
            let Some(anchor) = pattern.strip_prefix("||") else {
                continue;
            };
            let end = anchor
                .find(['/', '^', '?', '|', '&', '='])
                .unwrap_or(anchor.len());
            let host = &anchor[..end];
            if host.is_empty() || host.contains('*') {
                continue;
            }
            let Some(value) = options
                .split(',')
                .find_map(|option| option.trim().strip_prefix("removeparam="))
            else {
                continue;
            };
            let name = value.trim_start_matches(['~', '/']);
            let name = name.split(['/', '=', '^', '$']).next().unwrap_or("");
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
                continue;
            }
            // A `$xmlhttprequest`/`$script` form needs a matching request type, so both are probed; the
            // point is to reach every form, not to model a browser.
            let url = format!("https://{host}/p?{name}=1&keep=2");
            let _ = rules.rewrite(&request(&url, RequestKind::Document), RequestKind::Document);
            let _ = rules.rewrite(&request(&url, RequestKind::Xhr), RequestKind::Xhr);
            probes += 1;
        }
    }
    println!(
        "after probing {probes} catalog-anchored forms: cached engines {} (cap {}), RSS +{} KiB",
        rules.cached_engines(),
        extras::MAX_REMOVEPARAM_SCOPE_ENGINES,
        rss_kb().saturating_sub(cap_base)
    );
    assert!(
        rules.cached_engines() <= extras::MAX_REMOVEPARAM_SCOPE_ENGINES,
        "the cache exceeded its cap"
    );
    println!("cap holds: cache is {} of {}", rules.cached_engines(), extras::MAX_REMOVEPARAM_SCOPE_ENGINES);
}
