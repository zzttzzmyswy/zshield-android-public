//! Same-input cost matrix for the decrypted-path entry point `HttpsModifiers::edits` (MYS-2826).
//!
//! # Why a second benchmark
//!
//! `rebuild_edits_perf` produces one timing number per case, and the stage-4 comparison used it to
//! claim "1.4–2.3× slower" from a **single batch each**. That number cannot be attributed: it does not
//! say which stage of `edits` grew, whether the two builds did the same work, or whether the difference
//! is larger than the noise of a machine that also runs an emulator and a Gradle build.
//!
//! This example is built **from this one source file against both revisions**, so the code that
//! measures is identical and only the library under test differs. It answers four questions separately:
//!
//! 1. **What did each build decide?** (`--mode=rewrites`) — the whole `Edits` value per case as JSON,
//!    so a separate program can assert the two builds agree instead of a human comparing numbers.
//! 2. **Where does the time go?** (`--mode=timing`) — the whole `edits` call plus the five public
//!    stages it is composed of, each measured separately, so the parts can be checked against the whole.
//! 3. **How much does it allocate?** (`--mode=alloc`) — allocation count and bytes per call, the part
//!    of cost that does not depend on the host's clock or on its load.
//! 4. **Does a reload decide the same?** (`--mode=reload`) — after a round trip through the serialized
//!    text, after a hot swap of identical content, and after a hot swap of different content.
//!
//! # Inputs
//!
//! Rule text and the request matrix are files given on the command line, so both builds are fed
//! byte-identical input and the input's SHA-256 can be recorded with the result:
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example edits_cost_matrix -- \
//!     --rules scripts/perf/rules/equal-core.txt \
//!     --matrix scripts/perf/matrix.json \
//!     --build-id candidate --mode=timing --rounds 9 --iters 2000
//! ```
//!
//! Output is one JSON object per line (`jsonl`), so the driver concatenates both builds' logs and
//! compares them field by field without parsing prose.
//!
//! # What each stage is
//!
//! | stage | call | what it prices |
//! |---|---|---|
//! | `parse_url` | `adblock::url_parser::parse_url(&url)` | one URL parse, the unit the others pay for |
//! | `adblock_request` | `decision::to_adblock_request(req, kind)` | one request-model construction (source host + party) |
//! | `decide` | `decision::decide_full(&engine, req, kind)` | the engine query: blocking, `$csp`, engine-side `$removeparam` |
//! | `removeheader` | `removeheader.headers_to_remove(req, kind)` | the per-header-name engine queries |
//! | `removeparam` | `extras.removeparam.rewrite(req, kind)` | this core's own `$removeparam` evaluation |
//! | `edits` | `ModifierSource::edits(req, kind)` | the entry point the relays actually call |
//!
//! `edits` is deliberately **not** the sum of the others: it composes them, and a build that builds
//! extra intermediate values inside that composition shows up as a gap between the sum and the whole.
//! Reporting both is what makes that visible instead of guessed.

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use zshield::http::decision::{decide_full, to_adblock_request, HttpFilter};
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::{extras, modifiers};

// ---------------------------------------------------------------------------------------------
// Allocation counter
// ---------------------------------------------------------------------------------------------
//
// A wrapper around the system allocator, so `--mode=alloc` can report allocations per call without a
// profiler, without root, and without touching the library. The counters are only read between
// measurement windows, so their atomic increments add a fixed per-allocation cost to **every** build
// equally and cannot manufacture a difference between them.

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Whether the counters are on.
///
/// Off for every mode but `alloc`, because two relaxed `fetch_add`s per allocation are enough to
/// distort a measurement of a 2 µs call — and the whole point of the timing mode is that its numbers
/// are not distorted by the instrument. Both builds are measured with it in the same state, so it
/// cannot manufacture a difference either way; turning it off simply removes noise.
static COUNTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(
        &self,
        pointer: *mut u8,
        layout: std::alloc::Layout,
        new_size: usize,
    ) -> *mut u8 {
        // A `realloc` that grew a `String` is work the request paid for, so it counts as an allocation
        // (with the new size, which is what the caller now holds).
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            ALLOCATED_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        }
        unsafe { std::alloc::System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocation_mark() -> (u64, u64) {
    (
        ALLOCATIONS.load(Ordering::Relaxed),
        ALLOCATED_BYTES.load(Ordering::Relaxed),
    )
}

// ---------------------------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------------------------

/// One request of the matrix, as `scripts/perf/matrix.json` writes it.
#[derive(Clone)]
struct Case {
    id: String,
    label: String,
    method: String,
    url: String,
    referer: Option<String>,
    /// `document`, `xhr`, `image`, … — the same spelling `RequestKind::as_str` uses, so the matrix file
    /// names the request type the way the decision does.
    kind: String,
}

impl Case {
    fn request_kind(&self) -> RequestKind {
        match self.kind.as_str() {
            "document" => RequestKind::Document,
            "subdocument" => RequestKind::Subdocument,
            "script" => RequestKind::Script,
            "stylesheet" => RequestKind::Stylesheet,
            "image" => RequestKind::Image,
            "media" => RequestKind::Media,
            "font" => RequestKind::Font,
            "xmlhttprequest" => RequestKind::Xhr,
            "websocket" => RequestKind::Websocket,
            "ping" => RequestKind::Ping,
            "object" => RequestKind::Object,
            "other" => RequestKind::Other,
            other => panic!("unknown request kind {other:?} in the matrix"),
        }
    }

    /// The request model the production relay builds: `target` is the request-line target (path plus
    /// query), `hostname` is the lowercased host, and `fetch_dest` is the kind's `Sec-Fetch-Dest` value.
    fn request(&self) -> HttpRequest {
        build_request(&self.url, &self.method, self.referer.as_deref(), &self.kind)
    }
}

fn build_request(url: &str, method: &str, referer: Option<&str>, kind: &str) -> HttpRequest {
    let parsed = adblock::url_parser::parse_url(url)
        .unwrap_or_else(|| panic!("URL does not parse: {url}"));
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
        method: method.to_string(),
        target,
        version: Version::Http11,
        url: parsed.url.clone(),
        host: hostname.clone(),
        hostname,
        referer: referer.map(str::to_string),
        fetch_dest: Some(kind.to_string()),
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

fn read_matrix(path: &str) -> Vec<Case> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read matrix {path}: {error}"));
    let json: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("matrix {path} is not JSON: {error}"));
    let cases = json["cases"]
        .as_array()
        .unwrap_or_else(|| panic!("matrix {path} has no `cases` array"));
    cases
        .iter()
        .map(|case| Case {
            id: case["id"].as_str().expect("case.id").to_string(),
            label: case["label"].as_str().unwrap_or("").to_string(),
            method: case["method"].as_str().unwrap_or("GET").to_string(),
            url: case["url"].as_str().expect("case.url").to_string(),
            referer: case["referer"].as_str().map(str::to_string),
            kind: case["kind"].as_str().unwrap_or("document").to_string(),
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The build under test
// ---------------------------------------------------------------------------------------------

/// Everything one build needs to decide the matrix, assembled the way `compile.rs` assembles it: one
/// engine over the whole list text, and the self-evaluated rule sets over the same text.
struct Build {
    filter: Arc<HttpFilter>,
    modifiers: modifiers::HttpsModifiers,
    removeheader: Arc<modifiers::RemoveHeaderRules>,
    extras: Arc<extras::ExtraModifiers>,
    engine: Arc<adblock::Engine>,
}

fn engine_over(list_texts: &[String]) -> adblock::Engine {
    let mut set = adblock::lists::FilterSet::new(false);
    for text in list_texts {
        set.add_filter_list(text.clone(), adblock::lists::ParseOptions::default());
    }
    adblock::Engine::new_with_filter_set(set)
}

impl Build {
    fn new(list_texts: &[String]) -> Self {
        let engine = Arc::new(engine_over(list_texts));
        let refs: Vec<&str> = list_texts.iter().map(String::as_str).collect();
        let collected = Arc::new(extras::collect(refs.iter().copied()));
        let removeheader = Arc::new(modifiers::collect_removeheader(refs.iter().copied()));
        let filter = Arc::new(
            HttpFilter::new(engine_over(list_texts)).with_extras(Arc::clone(&collected)),
        );
        let extras_in_filter = filter.extras_arc();
        let modifiers = modifiers::HttpsModifiers::new(
            Arc::clone(&filter),
            Arc::clone(&removeheader),
            Arc::clone(&extras_in_filter),
        );
        Self {
            filter,
            modifiers,
            removeheader,
            extras: extras_in_filter,
            engine,
        }
    }
}

/// The timed stages, in the order they are reported.
///
/// A name plus a `match` rather than a table of closures: a closure borrowing `build` cannot outlive
/// the function that builds the table, and the indirection would hide nothing — the dispatch cost is
/// one branch against a call that takes microseconds.
const STAGES: [&str; 6] = [
    "parse_url",
    "adblock_request",
    "decide",
    "removeheader",
    "removeparam",
    "edits",
];

fn run_stage(build: &Build, stage: &str, case: &Case, request: &HttpRequest) {
    let kind = case.request_kind();
    match stage {
        "parse_url" => {
            black_box(adblock::url_parser::parse_url(black_box(&case.url)));
        }
        "adblock_request" => {
            black_box(to_adblock_request(black_box(request), kind));
        }
        "decide" => {
            black_box(decide_full(&build.engine, black_box(request), kind));
        }
        "removeheader" => {
            black_box(build.removeheader.headers_to_remove(black_box(request), kind));
        }
        "removeparam" => {
            black_box(build.extras.removeparam.rewrite(black_box(request), kind));
        }
        "edits" => {
            black_box(build.modifiers.edits(black_box(request), kind));
        }
        other => panic!("unknown stage {other}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Outcome capture
// ---------------------------------------------------------------------------------------------

/// The complete answer for one case, as JSON.
///
/// Everything a build can decide about a request is here — the block decision, the engine's own
/// rewritten URL, the final URL, both header lists and the CSP — because comparing only "was a URL
/// produced" is what let an earlier comparison call two different outcomes equal.
fn outcome(build: &Build, case: &Case) -> serde_json::Value {
    let request = case.request();
    let kind = case.request_kind();
    let (decision, engine_url, csp) = decide_full(&build.engine, &request, kind);
    let edits = build.modifiers.edits(&request, kind);
    let headers = build.removeheader.headers_to_remove(&request, kind);
    let self_url = build.extras.removeparam.rewrite(&request, kind);
    let reloaded = extras::collect([build.extras.serialize_lines().as_str()]);
    let reloaded_url = reloaded.removeparam.rewrite(&request, kind);
    serde_json::json!({
        "id": case.id,
        "label": case.label,
        "kind": case.kind,
        "method": case.method,
        "url_in": case.url,
        "referer": case.referer,
        "block": decision.block,
        "engine_rewritten_url": engine_url,
        "edits_url": edits.as_ref().and_then(|edits| edits.url.clone()),
        "edits_csp": edits.as_ref().and_then(|edits| edits.csp.clone()),
        "edits_drop_request_headers": edits
            .as_ref()
            .map(|edits| edits.drop_request_headers.clone())
            .unwrap_or_default(),
        "edits_drop_response_headers": edits
            .as_ref()
            .map(|edits| edits.drop_response_headers.clone())
            .unwrap_or_default(),
        "removeheader_direct": headers,
        "csp_from_decision": csp,
        "removeparam_self": self_url,
        "removeparam_after_serialized_reload": reloaded_url,
        "edits_present": edits.is_some(),
    })
}

// ---------------------------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------------------------

struct Stats {
    median: f64,
    mean: f64,
    min: f64,
    max: f64,
    stddev: f64,
    p90: f64,
}

fn stats(samples: &mut [f64]) -> Stats {
    if samples.is_empty() {
        return Stats {
            median: 0.0,
            mean: 0.0,
            min: 0.0,
            max: 0.0,
            stddev: 0.0,
            p90: 0.0,
        };
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let count = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / count;
    let variance = samples.iter().map(|value| (value - mean).powi(2)).sum::<f64>() / count;
    let median = if samples.len() % 2 == 0 {
        // The mean of the two middle samples, so an A/B pair a fraction of a microsecond apart is not
        // rounded onto one of the two.
        (samples[samples.len() / 2 - 1] + samples[samples.len() / 2]) / 2.0
    } else {
        samples[samples.len() / 2]
    };
    let p90_index = ((samples.len() as f64 * 0.9).ceil() as usize)
        .saturating_sub(1)
        .min(samples.len() - 1);
    Stats {
        median,
        mean,
        min: samples[0],
        max: samples[samples.len() - 1],
        stddev: variance.sqrt(),
        p90: samples[p90_index],
    }
}

fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|raw| raw.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|_| "unknown".to_string())
}

// ---------------------------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------------------------

fn mode_rewrites(build: &Build, matrix: &[Case]) {
    for case in matrix {
        println!(
            "{}",
            serde_json::to_string(&outcome(build, case)).expect("serialisable outcome")
        );
    }
}

fn mode_timing(
    build: &Build,
    matrix: &[Case],
    build_id: &str,
    rules_path: &str,
    rounds: usize,
    iterations: u32,
    stages: &[&'static str],
) {
    for case in matrix {
        let request = case.request();
        let kind = case.request_kind();
        // Warm what a session warms before its first request: the per-form engines, the thread-local
        // stores, the allocator's size classes. Without this the first round measures construction.
        for _ in 0..256 {
            black_box(build.modifiers.edits(&request, kind));
            black_box(build.extras.removeparam.rewrite(&request, kind));
        }
        for stage in stages.iter().copied() {
            let mut samples = Vec::with_capacity(rounds);
            for _ in 0..rounds {
                let started = Instant::now();
                for _ in 0..iterations {
                    run_stage(build, stage, case, &request);
                }
                samples.push(started.elapsed().as_secs_f64() * 1e6 / f64::from(iterations));
            }
            let stats = stats(&mut samples);
            println!(
                "{}",
                serde_json::json!({
                    "record": "timing",
                    "build": build_id,
                    "rules": rules_path,
                    "id": case.id,
                    "kind": case.kind,
                    "stage": stage,
                    "iterations": iterations,
                    "rounds": rounds,
                    "median_us": stats.median,
                    "mean_us": stats.mean,
                    "min_us": stats.min,
                    "max_us": stats.max,
                    "p90_us": stats.p90,
                    "stddev_us": stats.stddev,
                    "cv": if stats.mean > 0.0 { stats.stddev / stats.mean } else { 0.0 },
                    "loadavg": load_average(),
                })
            );
        }
    }
}

fn mode_alloc(
    build: &Build,
    matrix: &[Case],
    build_id: &str,
    rules_path: &str,
    stages: &[&'static str],
) {
    for case in matrix {
        let request = case.request();
        for stage in stages.iter().copied() {
            // One warm call, so a cache built on first use is not billed to this case.
            run_stage(build, stage, case, &request);
            let iterations = 200u32;
            let (count_before, bytes_before) = allocation_mark();
            for _ in 0..iterations {
                run_stage(build, stage, case, &request);
            }
            let (count_after, bytes_after) = allocation_mark();
            println!(
                "{}",
                serde_json::json!({
                    "record": "alloc",
                    "build": build_id,
                    "rules": rules_path,
                    "id": case.id,
                    "kind": case.kind,
                    "stage": stage,
                    "iterations": iterations,
                    // Per call, so a stage that allocates on a hit and not on a miss is not averaged
                    // into a number nobody can attribute.
                    "allocations_per_call":
                        (count_after - count_before) as f64 / f64::from(iterations),
                    "bytes_per_call": (bytes_after - bytes_before) as f64 / f64::from(iterations),
                })
            );
        }
    }
}

/// Reload controls (task card criterion 4).
///
/// Three properties must hold of a rule set that decides by content rather than by build order:
///
/// 1. `collect(serialize_lines())` — the text that becomes `extras.txt` and comes back at the next
///    start — decides every case exactly as the in-memory set does;
/// 2. swapping that set into a **live** filter (`replace_extras`, which is what a list or user-rule
///    edit does) changes nothing while the content is the same;
/// 3. after a swap to **different** content, later decisions follow the new content.
///
/// The third is reported per case rather than asserted: a build that snapshots the rule set when the
/// modifier object is constructed cannot satisfy it, and reporting which build does is the point.
fn mode_reload(build: &Build, matrix: &[Case], build_id: &str, rules_path: &str) {
    let before: Vec<(String, Option<String>)> = matrix
        .iter()
        .map(|case| {
            let request = case.request();
            (
                case.id.clone(),
                build
                    .modifiers
                    .edits(&request, case.request_kind())
                    .and_then(|edits| edits.url),
            )
        })
        .collect();
    let before_of = |id: &str| -> Option<String> {
        before
            .iter()
            .find(|(candidate, _)| candidate == id)
            .and_then(|(_, url)| url.clone())
    };

    let serialized = build.extras.serialize_lines();
    let serialize_sha = sha256_hex(serialized.as_bytes());
    let reloaded = extras::collect([serialized.as_str()]);
    let mut round_trip_mismatches = Vec::new();
    for case in matrix {
        let request = case.request();
        let after = reloaded.removeparam.rewrite(&request, case.request_kind());
        if after != before_of(&case.id) {
            round_trip_mismatches.push(serde_json::json!({
                "id": case.id,
                "before": before_of(&case.id),
                "after_serialized_reload": after,
            }));
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "record": "reload",
            "check": "serialized_round_trip",
            "build": build_id,
            "rules": rules_path,
            "identical": round_trip_mismatches.is_empty(),
            "mismatches": round_trip_mismatches,
            "serialized_lines": serialized.lines().count(),
            "serialized_bytes": serialized.len(),
            "serialized_sha256": serialize_sha,
        })
    );

    build
        .filter
        .replace_extras(Arc::new(extras::collect([serialized.as_str()])));
    let mut same_content_mismatches = Vec::new();
    for case in matrix {
        let request = case.request();
        let after = build
            .modifiers
            .edits(&request, case.request_kind())
            .and_then(|edits| edits.url);
        if after != before_of(&case.id) {
            same_content_mismatches.push(serde_json::json!({
                "id": case.id,
                "before": before_of(&case.id),
                "after_hot_swap": after,
            }));
        }
    }
    println!(
        "{}",
        serde_json::json!({
            "record": "reload",
            "check": "hot_swap_same_content",
            "build": build_id,
            "rules": rules_path,
            "identical": same_content_mismatches.is_empty(),
            "mismatches": same_content_mismatches,
        })
    );

    // One extra rule that names a parameter the matrix's `keep=` occurrences carry: a build that reads
    // the live set must start removing it, a build that snapshotted the set must not.
    let widened = format!("{serialized}\n||shop.example.com^$removeparam=keep\n");
    build
        .filter
        .replace_extras(Arc::new(extras::collect([widened.as_str()])));
    let followed: Vec<serde_json::Value> = matrix
        .iter()
        .map(|case| {
            let request = case.request();
            let after = build
                .modifiers
                .edits(&request, case.request_kind())
                .and_then(|edits| edits.url);
            serde_json::json!({
                "id": case.id,
                "before": before_of(&case.id),
                "after": after,
                "followed_new_content": before_of(&case.id) != after,
            })
        })
        .filter(|value| value["followed_new_content"].as_bool().unwrap_or(false))
        .collect();
    println!(
        "{}",
        serde_json::json!({
            "record": "reload",
            "check": "hot_swap_new_content",
            "build": build_id,
            "rules": rules_path,
            "cases_that_changed": followed,
            "follows_live_rule_set": !followed.is_empty(),
        })
    );
}

/// First-use and warmed request costs for query misses, navigation hits and POST.
/// Each sample uses a new thread as well as a new Build: v0.1.2 caches rule engines
/// in thread-local storage, so rebuilding Build alone does not reset its cache.
/// Compilation is outside the timer. Ratios alone do not identify construction
/// frequency; they describe these inputs and do not prove absence of cache churn.
fn mode_cache(_build: &Build, matrix: &[Case], build_id: &str, rules_path: &str,
              rounds: usize, iterations: u32) {
    for case in matrix.iter().filter(|case| matches!(case.id.as_str(),
        "miss-document" | "hit-document-navigation" | "hit-document-post")) {
        let mut cold_samples = Vec::with_capacity(rounds);
        let mut warm_first_samples = Vec::with_capacity(rounds);
        let mut warm_samples = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            let (cold, warm_first, warm) = std::thread::scope(|scope| {
                scope.spawn(|| {
                    let lists = vec![std::fs::read_to_string(rules_path).expect("rules file")];
                    let fresh = Build::new(&lists);
                    let request = case.request();
                    let kind = case.request_kind();
                    let started = Instant::now();
                    black_box(fresh.modifiers.edits(&request, kind));
                    let cold = started.elapsed().as_secs_f64() * 1e6;
                    for _ in 0..256 {
                        black_box(fresh.modifiers.edits(&request, kind));
                    }
                    let started = Instant::now();
                    black_box(fresh.modifiers.edits(&request, kind));
                    let warm_first = started.elapsed().as_secs_f64() * 1e6;
                    let started = Instant::now();
                    for _ in 0..iterations {
                        black_box(fresh.modifiers.edits(&request, kind));
                    }
                    (cold, warm_first, started.elapsed().as_secs_f64() * 1e6 / f64::from(iterations))
                }).join().expect("cache sample thread")
            });
            cold_samples.push(cold);
            warm_first_samples.push(warm_first);
            warm_samples.push(warm);
        }
        let cold = stats(&mut cold_samples);
        let first = stats(&mut warm_first_samples);
        let warm = stats(&mut warm_samples);
        println!("{}", serde_json::json!({
            "record": "cache", "build": build_id, "rules": rules_path,
            "id": case.id, "kind": case.kind, "rounds": rounds,
            "warmup_calls": 256, "iterations": iterations,
            "cache_reset": "fresh thread and Build per sample; compilation excluded",
            "cold_median_us": cold.median, "cold_min_us": cold.min,
            "cold_max_us": cold.max, "cold_samples_us": cold_samples,
            "warm_first_call_median_us": first.median,
            "warm_first_call_samples_us": warm_first_samples,
            "warm_median_us": warm.median, "warm_min_us": warm.min,
            "warm_samples_us": warm_samples,
            "cold_over_warm": cold.median / warm.median,
        }));
    }
}

/// SHA-256, so the serialized text's identity is in the log rather than asserted. The core already
/// depends on `sha2` for its artifacts (see `core/src/compiled.rs`).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

struct Options {
    rules: String,
    matrix: String,
    build_id: String,
    mode: String,
    rounds: usize,
    iterations: u32,
    /// Restrict timing/alloc to one stage, so a profiler can be pointed at exactly the stage under
    /// investigation instead of at a mixed workload whose samples cannot be attributed.
    only_stage: Option<String>,
    /// Restrict to one case id, for the same reason.
    only_case: Option<String>,
}

fn options() -> Options {
    let mut parsed = Options {
        rules: "scripts/perf/rules/equal-engine-name.txt".to_string(),
        matrix: "scripts/perf/matrix.json".to_string(),
        build_id: "unknown".to_string(),
        mode: "rewrites".to_string(),
        rounds: 9,
        iterations: 2_000,
        only_stage: None,
        only_case: None,
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
            "--rules" => parsed.rules = take("--rules"),
            "--matrix" => parsed.matrix = take("--matrix"),
            "--build-id" => parsed.build_id = take("--build-id"),
            "--rounds" => parsed.rounds = take("--rounds").parse().expect("--rounds is a number"),
            "--iters" => {
                parsed.iterations = take("--iters").parse().expect("--iters is a number");
            }
            "--only-stage" => parsed.only_stage = Some(take("--only-stage")),
            "--only-case" => parsed.only_case = Some(take("--only-case")),
            other => match other.strip_prefix("--mode=") {
                Some(name) => parsed.mode = name.to_string(),
                None => match other.strip_prefix("--only-stage=") {
                    Some(name) => parsed.only_stage = Some(name.to_string()),
                    None => match other.strip_prefix("--only-case=") {
                        Some(name) => parsed.only_case = Some(name.to_string()),
                        None => panic!("unknown argument {other}"),
                    },
                },
            },
        }
        index += 1;
    }
    parsed
}

/// The stages this run reports, honouring `--only-stage`.
fn selected_stages(options: &Options) -> Vec<&'static str> {
    match options.only_stage.as_deref() {
        None => STAGES.to_vec(),
        Some(requested) => {
            if !STAGES.contains(&requested) {
                panic!("--only-stage {requested} is not one of {STAGES:?}");
            }
            vec![STAGES
                .iter()
                .copied()
                .find(|stage| *stage == requested)
                .expect("checked above")]
        }
    }
}

fn main() {
    let options = options();
    let rules = std::fs::read_to_string(&options.rules)
        .unwrap_or_else(|error| panic!("cannot read rules {}: {error}", options.rules));
    let mut matrix = read_matrix(&options.matrix);
    if let Some(only_case) = options.only_case.as_deref() {
        matrix.retain(|case| case.id == only_case);
        if matrix.is_empty() {
            panic!("--only-case {only_case} matched no case");
        }
    }
    let stages = selected_stages(&options);
    let lists = vec![rules];
    let build = Build::new(&lists);

    println!(
        "{}",
        serde_json::json!({
            "record": "header",
            "build": options.build_id,
            "mode": options.mode,
            "rules": options.rules,
            "rules_sha256": sha256_hex(build_rule_bytes(&options.rules)),
            "matrix": options.matrix,
            "matrix_sha256": sha256_hex(&std::fs::read(&options.matrix).expect("matrix bytes")),
            "cases": matrix.len(),
            "removeparam_rules": build.extras.removeparam.len(),
            "removeparam_rejected": build.extras.removeparam.rejected().len(),
            "removeheader_rules": build.removeheader.len(),
            "loadavg": load_average(),
            "profile": "release (opt-level=z, lto=true, codegen-units=1, panic=abort, strip=true)",
            "hardware": hardware(),
        })
    );

    match options.mode.as_str() {
        "rewrites" => mode_rewrites(&build, &matrix),
        "timing" => mode_timing(
            &build,
            &matrix,
            &options.build_id,
            &options.rules,
            options.rounds,
            options.iterations,
            &stages,
        ),
        "alloc" => {
            COUNTING.store(true, Ordering::Relaxed);
            mode_alloc(&build, &matrix, &options.build_id, &options.rules, &stages)
        }
        "reload" => mode_reload(&build, &matrix, &options.build_id, &options.rules),
        "cache" => mode_cache(&build, &matrix, &options.build_id, &options.rules,
                              options.rounds, options.iterations),
        other => panic!("unknown mode {other} (rewrites|timing|alloc|reload|cache)"),
    }
}

fn build_rule_bytes(path: &str) -> &'static [u8] {
    // The bytes are re-read here only to hash them; `read_to_string` above already proved they are
    // valid UTF-8, so the length is the same and the hash names the same file the build read.
    Box::leak(
        std::fs::read(path)
            .unwrap_or_else(|error| panic!("cannot read rules {path}: {error}"))
            .into_boxed_slice(),
    )
}

fn hardware() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|raw| {
            raw.lines()
                .find(|line| line.starts_with("model name"))
                .and_then(|line| line.split(':').nth(1))
                .map(|value| value.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    let cores = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(0);
    format!("{cpu} / {cores} threads")
}
