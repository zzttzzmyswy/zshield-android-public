//! Host attribution of the **complete JNI lifecycle** of the rule set (MYS-2866).
//!
//! Usage:
//!
//! ```text
//! cargo run --release --manifest-path core/Cargo.toml --example i2_jni_memory_profile -- \
//!   --work <dir> --lists <list-bodies-dir> --group five|nine --run 1 [--trim-diagnostic]
//! ```
//!
//! # Why this exists
//!
//! The earlier host probe (`i2_memory_profile.rs`, MYS-2840) is a *component* probe: it loads the
//! three artifacts and reloads the HTTP engine through `http::engine::reload`. It never calls
//! `jni_api::start_engine` / `jni_api::reload_engine`, so it does not exercise the DNS and `extras`
//! swap, the unchanged-artifact fast path, the final allocator trim, or the tunnel's own threads and
//! descriptors. The lead's review of that probe also found its `--ab-trim` arm measuring *after* the
//! rule owners were dropped, which is why the ~35 MiB it reported could not be read as "memory a live
//! tunnel could give back".
//!
//! This example walks the production entry points the Kotlin control plane uses, in the order the app
//! uses them, and observes what each step actually holds:
//!
//! 1. process baseline;
//! 2. `compile_request` (rule set A), with the compile's own temporaries already released;
//! 3. `start_engine` over a registerable `UnixDatagram` pair standing in for the TUN descriptor;
//! 4. twenty **unchanged** `reload_engine` calls (the app compiles on every start, so this is the
//!    common case);
//! 5. `compile_request` (rule set B — one dedicated typed regex `$removeparam` moves from `old` to
//!    `new`, so only `extras.txt` changes);
//! 6. `reload_engine` onto B on the same handle;
//! 7. at least six A/B alternations;
//! 8. `stop_engine` and the release of every end of the socket pair;
//! 9. optionally, an explicitly labelled allocator-trim diagnostic — **not** a production change.
//!
//! # What is measured, and what it is not
//!
//! - **Live heap** is a counting global allocator (`GlobalAlloc`): bytes currently allocated through
//!   Rust's allocator, plus the high-water mark reached inside each phase.
//! - **Residency** is the raw `/proc/self/smaps_rollup` fields, in the kernel's own unit (`kB`). The
//!   field names and values are copied verbatim; nothing is converted, and a missing field stays
//!   missing rather than becoming zero.
//! - **Resources** are `/proc/self/fd` and `/proc/self/task` entry counts.
//!
//! RSS/PSS also contain the executable's mappings, every thread stack, the allocator's own metadata
//! and anything allocated outside Rust's allocator. So `rss − counted_live` is an *upper bound* on
//! "resident but not in a live Rust object", never an arena figure, and never a leak proof.
//!
//! This is a **glibc host**. Android links bionic/scudo, runs a JVM beside the core, and shares pages
//! differently. A number here supports a *mechanism* ("a reload holds two engines at once") and can
//! never be converted into a device PSS prediction. `docs/I2_JNI_MEMORY_PROFILE.md` states that
//! boundary; this example does not claim, and must not be read as, a PSS result.
//!
//! # Why the probe holds no strong reference to the rules
//!
//! An observation that kept an `Arc` to the previous engine would keep the old rule set alive and
//! then report it as "still held by the tunnel". Every read of the live rule objects here goes
//! through the read-only accessors (`handle_http_filter` / `handle_dns_filter` / `handle_rules_state`),
//! is immediately downgraded to a `Weak`, and the strong reference is dropped inside the same
//! function. `Weak::strong_count == 0` after a swap is then evidence that the *tunnel* released the
//! old rules, not that this probe forgot them.
//!
//! # Inputs
//!
//! `--lists` must name a directory holding exactly the canonical bodies of the selected group, with
//! the sizes and SHA-256 of `docs/I2_MEMORY_PROFILE.md` §6. A mismatch is a hard error: a run whose
//! inputs are not the ones the group names cannot be reported as that group's evidence. `selftest`
//! exists so the checker and the delivery can be exercised without the real lists; a `selftest`
//! document says `formal: false` and is never formal evidence.
//!
//! Nothing here reads a device, opens a network connection, writes to the copied list bodies, or
//! touches production code.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use zshield::compiled::{Artifact, PayloadIdentity};
use zshield::dns::filter::Filter;
use zshield::http::decision::HttpFilter;
use zshield::http::head::{HttpRequest, Version};
use zshield::http::resource::RequestKind;
use zshield::http::rewrite::ModifierSource;
use zshield::https::extras::ExtraModifiers;
use zshield::https::modifiers::{collect_removeheader, HttpsModifiers};
use zshield::rules_identity::RulesState;

// ---------------------------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every method forwards to `System` unchanged and only maintains two relaxed counters, which
// is the same pattern `mem_probe.rs` and `i2_memory_profile.rs` use. The counters are not read for
// control flow, so a lost update under concurrency changes a reported number by a layout size, never
// an allocation's correctness.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = System.realloc(ptr, layout, new_size);
        if !out.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            let live = LIVE.fetch_add(new_size, Ordering::Relaxed) + new_size;
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        out
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live_bytes() -> u64 {
    LIVE.load(Ordering::Relaxed) as u64
}

fn peak_bytes() -> u64 {
    PEAK.load(Ordering::Relaxed) as u64
}

/// Start a new phase's high-water mark from the current live total.
fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// One operation's measurement window: a reset before the call and a capture immediately after it.
///
/// The review of the first delivery found `started-a` reporting exactly the compile's peak and
/// `stopped` exactly the A–B peak, because neither step reset the counter nor captured its own high
/// water mark — so the "phase peak" of both was really the previous phase's. A window makes that
/// mistake unrepresentable: `begin` resets, `end` captures, and the value can only be read from the
/// finished window. Everything a phase does that is *not* the measured operation (hashing artifacts,
/// serialising JSON, writing the journal) happens outside the window, on one side or the other.
#[derive(Clone)]
struct Window {
    started_live: u64,
    started_monotonic_ns: u64,
    peak: u64,
    ended_live: u64,
    ended_monotonic_ns: u64,
    closed: bool,
}

impl Window {
    fn begin(started: Instant) -> Self {
        reset_peak();
        Self {
            started_live: live_bytes(),
            started_monotonic_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            peak: 0,
            ended_live: 0,
            ended_monotonic_ns: 0,
            closed: false,
        }
    }

    /// Capture and close. Call this as the first statement after the measured call returns.
    fn end(&mut self, started: Instant) {
        self.peak = peak_bytes();
        self.ended_live = live_bytes();
        self.ended_monotonic_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.closed = true;
    }

    fn json(&self, operation: &str) -> Value {
        debug_assert!(self.closed, "a window must be closed before it is reported");
        json!({
            "operation": operation,
            "started_monotonic_ns": self.started_monotonic_ns,
            "ended_monotonic_ns": self.ended_monotonic_ns,
            "duration_ms": (self.ended_monotonic_ns.saturating_sub(self.started_monotonic_ns)) as f64
                / 1_000_000.0,
            "started_live_bytes": self.started_live,
            "ended_live_bytes": self.ended_live,
            "peak_bytes": self.peak,
            "peak_mib": self.peak as f64 / (1024.0 * 1024.0),
            "retained_bytes": self.ended_live as i64 - self.started_live as i64,
            "scope": "this operation only: the counter was reset immediately before the call and read \
                      immediately after it; artifact hashing, JSON and journal writes happen outside",
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Canonical inputs (docs/I2_MEMORY_PROFILE.md §6)
// ---------------------------------------------------------------------------------------------

/// One list body the compile must be given, with the size and content hash that identify it.
struct ListSpec {
    id: &'static str,
    bytes: u64,
    sha256: &'static str,
}

/// The fixed five-list baseline of the 84.6 MiB acceptance threshold.
const FIVE: &[ListSpec] = &[
    ListSpec {
        id: "adguard-base",
        bytes: 6_458_941,
        sha256: "1ec4df21f05a99e986e8b1c9d1dce18d2075fa8c4c0fdb52602960c3b4c2e693",
    },
    ListSpec {
        id: "adguard-tracking",
        bytes: 15_125_879,
        sha256: "297509825b155280a17d68266b079692149e187bfc642c059863dcf46e532308",
    },
    ListSpec {
        id: "adguard-mobile",
        bytes: 530_861,
        sha256: "f3262a5bb798cf02fe21cdc1720c6a1e43b0b438df83aa967ff84940dc354b61",
    },
    ListSpec {
        id: "adguard-url-tracking",
        bytes: 183_673,
        sha256: "fe84fc5f8f12be9258b3f64353ad95107d8d57b82d4a2ba2f80d4fae500adece",
    },
    ListSpec {
        id: "adguard-chinese",
        bytes: 718_555,
        sha256: "0bf9d26038391b6e7a4c2664f029127e050c27379576cd808dff555020f16e5c",
    },
];

/// The five above plus the four the default catalog also enables. No 84.6 MiB threshold applies.
const NINE_EXTRA: &[ListSpec] = &[
    ListSpec {
        id: "adguard-dns",
        bytes: 4_597_885,
        sha256: "d0edbf143873d060f03ea35891f2c44398d6cc9097d06f9d76b5d3d453ccf713",
    },
    ListSpec {
        id: "easylist-china",
        bytes: 498_597,
        sha256: "e4dade0da96371cad630b9d740d5936ea6b41657f9d98e2d3e42530ef5adc3ae",
    },
    ListSpec {
        id: "ublock-unbreak",
        bytes: 282_165,
        sha256: "91da37caebdcaec0dc111b293c0392dcb7ba5e447f636dd8529803176a825e94",
    },
    ListSpec {
        id: "ublock-quick-fixes",
        bytes: 86_138,
        sha256: "c6b20fd6fbd8f284539140b5bc6b36cbf6e5d99b5f3dff76b95ce21b68b833c9",
    },
];

/// The three list bodies a `selftest` run compiles. Small on purpose, and never formal evidence.
const SELFTEST_LISTS: &[(&str, &str)] = &[
    ("selftest-ads", "||ads.selftest^\n||tracker.selftest^\n"),
    ("selftest-mobile", "||mads.selftest^\n"),
    ("selftest-misc", "||misc.selftest^$third-party\n"),
];

/// The dedicated A/B rule: one typed regex `$removeparam`, and nothing else.
///
/// A regex `$removeparam` is the shape the pinned engine refuses and `https::extras` evaluates, so it
/// lands in `extras.txt` alone and leaves `dns.bin` and `engine.bin` byte-identical. That is asserted
/// from the artifacts of both compiles, not assumed: if a future engine learned the option, the
/// control would fail loudly instead of measuring a different transition.
const RULE_A: &str = "||ab-memory.test^$xmlhttprequest,removeparam=/^old=/";
const RULE_B: &str = "||ab-memory.test^$xmlhttprequest,removeparam=/^new=/";

/// The URL the effect assertions run on: whichever rule is in force removes exactly one parameter.
const EFFECT_URL: &str = "https://ab-memory.test/p?old=1&new=2&keep=3";
const EFFECT_WITH_A: &str = "https://ab-memory.test/p?new=2&keep=3";
const EFFECT_WITH_B: &str = "https://ab-memory.test/p?old=1&keep=3";

const UNCHANGED_RELOADS: usize = 20;

/// The observation points that report a measured operation and must therefore carry that
/// operation's own [`Window`]. Every other point observes a state and must carry `null`.
const OPERATION_PHASES: &[&str] = &[
    "compiled-a",
    "started-a",
    "first-removeparam-evaluation",
    "unchanged-reloads-done",
    "compiled-b",
    "reloaded-b",
    "stopped",
];
const AB_ROUNDS: usize = 12;

// ---------------------------------------------------------------------------------------------
// Observation helpers
// ---------------------------------------------------------------------------------------------

fn sha256_file(path: &Path) -> Result<(String, u64), String> {
    // Streamed: a 41 MB `engine.bin` read into memory would show up in the counting allocator's
    // high-water mark of whatever phase happened to be open. 64 KiB keeps the probe's own footprint
    // out of the numbers it reports.
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        context.update(&buffer[..read]);
        total += read as u64;
    }
    let digest = context.finish();
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    Ok((hex, total))
}

/// One artifact on disk: its file size and hash, and the identity of the payload the loader installs.
///
/// Both are recorded because they answer different questions: the file hash says "this is the byte
/// stream the compile wrote", the payload identity says "this is the rule content the kernel would
/// report as in force" (`rules_identity` hashes the payload, not the envelope).
fn artifact_facts(path: &Path, artifact: Artifact) -> Result<Value, String> {
    let (file_sha256, bytes) = sha256_file(path)?;
    let payload =
        PayloadIdentity::of_file(path, artifact).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(json!({
        "artifact": artifact.file_name(),
        "path": path.display().to_string(),
        "bytes": bytes,
        "file_sha256": file_sha256,
        "payload_sha256": payload.sha256_hex,
        "payload_bytes": payload.bytes,
        "payload_token": payload.token(),
    }))
}

/// The three artifacts of one compiled directory, or an error naming the file that is missing.
fn artifact_set(dir: &Path) -> Result<Value, String> {
    let mut out = serde_json::Map::new();
    for artifact in [Artifact::Dns, Artifact::Engine, Artifact::Extras] {
        let path = dir.join(artifact.file_name());
        if !path.is_file() {
            return Err(format!("missing artifact {}", path.display()));
        }
        out.insert(
            artifact.file_name().to_string(),
            artifact_facts(&path, artifact)?,
        );
    }
    Ok(Value::Object(out))
}

/// One rendered field of `/proc/self/smaps_rollup` is `<Name>: <number> kB`.
///
/// The kernel's own key, value and unit are kept as they are: `Private_Dirty` is not a synonym for
/// anonymous memory, and a probe that renamed it would invite exactly that reading.
fn smaps_rollup() -> Option<BTreeMap<String, u64>> {
    let raw = std::fs::read_to_string("/proc/self/smaps_rollup").ok()?;
    let mut fields = BTreeMap::new();
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let mut words = value.split_whitespace();
        if let (Some(number), Some("kB")) = (words.next(), words.next()) {
            if let Ok(kib) = number.parse::<u64>() {
                fields.insert(key.trim().to_string(), kib);
            }
        }
    }
    if fields.is_empty() {
        None
    } else {
        Some(fields)
    }
}

fn count_entries(path: &str) -> Option<usize> {
    std::fs::read_dir(path).ok().map(|entries| entries.count())
}

/// One `kB` field of `/proc/self/status`, or `None` where the kernel does not print it.
///
/// `VmPeak` is the address space's high-water mark. It is *not* a phase measurement — the kernel has
/// no way to reset it — so the probe reports it only as an independent cross-check on the counted
/// peak, never as a phase's own cost.
fn proc_status_kib(field: &str) -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != field {
            continue;
        }
        let mut words = value.split_whitespace();
        if let (Some(number), Some("kB")) = (words.next(), words.next()) {
            return number.parse().ok();
        }
        return None;
    }
    None
}

/// The four rule objects a live handle has in force, held as `Weak` so the probe never keeps them.
struct Weaks {
    /// The `HttpFilter` itself. Constant for the life of a pipeline; it is the *engine* and *extras*
    /// inside it that a reload replaces.
    filter: Weak<HttpFilter>,
    dns: Weak<Filter>,
    engine: Weak<adblock::Engine>,
    extras: Weak<ExtraModifiers>,
}

impl Weaks {
    fn same_as(&self, other: &Weaks) -> bool {
        Weak::ptr_eq(&self.filter, &other.filter)
            && Weak::ptr_eq(&self.dns, &other.dns)
            && Weak::ptr_eq(&self.engine, &other.engine)
            && Weak::ptr_eq(&self.extras, &other.extras)
    }

    /// True once no `Arc` to any of the three swappable rule sets is alive any more.
    fn released(&self) -> bool {
        self.dns.strong_count() == 0
            && self.engine.strong_count() == 0
            && self.extras.strong_count() == 0
    }

    fn all_released(&self) -> bool {
        self.released() && self.filter.strong_count() == 0
    }

    fn liveness(&self) -> Value {
        json!({
            "filter_strong": self.filter.strong_count(),
            "dns_strong": self.dns.strong_count(),
            "engine_strong": self.engine.strong_count(),
            "extras_strong": self.extras.strong_count(),
        })
    }
}

/// Read the live rule objects through the read-only accessors and immediately downgrade to `Weak`.
///
/// The strong references never leave this function, so a caller can compare identities across a swap
/// without holding the previous rule set alive — the distinction the earlier probe got wrong.
fn capture_weaks(handle: u64) -> Result<Weaks, String> {
    let filter = zshield::jni_api::handle_http_filter(handle)
        .ok_or_else(|| "handle has no HTTP filter".to_string())?;
    let dns = zshield::jni_api::handle_dns_filter(handle)
        .ok_or_else(|| "handle has no DNS filter".to_string())?;
    let engine = filter.engine();
    let extras = filter.extras();
    let weaks = Weaks {
        filter: Arc::downgrade(&filter),
        dns: Arc::downgrade(&dns),
        engine: Arc::downgrade(&engine),
        extras: Arc::downgrade(&extras),
    };
    drop((filter, dns, engine, extras));
    Ok(weaks)
}

/// What `$removeparam` leaves of [`EFFECT_URL`], through the production evaluation path.
///
/// This is `HttpsModifiers::edits` — the call the HTTP/1.1 and HTTP/2 relays make — and not a
/// re-implementation: the reload controls exist to prove the *tunnel's* answer changed, so the answer
/// has to come from the tunnel's own code.
fn removeparam_effect(handle: u64) -> Result<String, String> {
    let filter = zshield::jni_api::handle_http_filter(handle)
        .ok_or_else(|| "handle has no HTTP filter".to_string())?;
    let modifier_source = HttpsModifiers::new(
        filter.clone(),
        Arc::new(collect_removeheader(std::iter::empty())),
        filter.extras_arc(),
    );
    let authority = "ab-memory.test";
    let request = HttpRequest {
        method: "GET".into(),
        target: format!("/{}", EFFECT_URL.splitn(4, '/').nth(3).unwrap_or("")),
        version: Version::Http11,
        url: EFFECT_URL.into(),
        host: authority.into(),
        hostname: authority.into(),
        referer: Some(format!("https://{authority}/")),
        fetch_dest: Some("empty".into()),
        fetch_site: None,
        fetch_user: None,
        accept: None,
        content_length: None,
        chunked: false,
        upgrade: false,
        expect_continue: false,
        head_len: 0,
    };
    let url = modifier_source
        .edits(&request, RequestKind::Xhr)
        .and_then(|edits| edits.url)
        .unwrap_or_else(|| EFFECT_URL.to_string());
    Ok(url)
}

fn monotonic_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

// ---------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------

struct Probe {
    run_id: String,
    group: String,
    formal: bool,
    work: PathBuf,
    compiled_a: PathBuf,
    compiled_b: PathBuf,
    lists: Vec<Value>,
    user_rule_a: String,
    user_rule_b: String,
    /// Observations are **written out as they are taken** and not kept in memory.
    ///
    /// A probe that accumulated one JSON object per observation would grow the very number it is
    /// reporting: the first self-test run of this example showed ~11 KiB of "live heap" growth per
    /// A/B round, all of it the probe's own record list. Serializing each record to this file and
    /// dropping it keeps the counter describing the tunnel rather than the measurement of it. The
    /// file is read back once, after the last observation, to build the report.
    journal: std::io::BufWriter<std::fs::File>,
    journal_path: PathBuf,
    /// Artifact facts are hashed once per compiled directory, not once per observation point: the
    /// probe writes each directory exactly once and never again, and re-hashing 41 MB at every point
    /// would put that I/O inside the phase whose peak has just been recorded.
    artifact_cache: BTreeMap<String, Value>,
    assertion_count: usize,
    point_count: usize,
    failures: Vec<String>,
    /// `"a"`/`"b"` → the directory that role compiled into. Recorded explicitly so a reader never has
    /// to infer from a path name which artifact set is which side of the A/B control.
    roles: BTreeMap<String, String>,
    /// The directory whose artifacts are in force, or `None` before a start / after a stop.
    current_dir: Option<PathBuf>,
    handle: Option<u64>,
    weaks: Option<Weaks>,
    /// The `start_engine` call's own measurement window, stored so the observation point reports the
    /// start rather than whatever ran last.
    start_window: Option<Window>,
    trim_diagnostic: bool,
    started: Instant,
    baseline_fds: Option<usize>,
    baseline_threads: Option<usize>,
}

impl Probe {
    /// Append one record to the journal.
    fn record(&mut self, kind: &str, value: Value) {
        use std::io::Write;
        let line = json!({ "record": kind, "value": value }).to_string();
        // A journal write failure is fatal: the run's own evidence would be incomplete.
        if let Err(error) = writeln!(self.journal, "{line}") {
            panic!("cannot write the observation journal: {error}");
        }
    }

    fn flush_journal(&mut self) {
        use std::io::Write;
        if let Err(error) = self.journal.flush() {
            panic!("cannot flush the observation journal: {error}");
        }
    }

    fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        let detail = detail.into();
        if !ok {
            self.failures.push(format!("{name}: {detail}"));
        }
        self.assertion_count += 1;
        self.record(
            "assertion",
            json!({
                "name": name,
                "ok": ok,
                "detail": detail,
            }),
        );
    }

    /// One observation point.
    ///
    /// The counting allocator is read **first**, before anything else in this function allocates: the
    /// point is meant to describe the phase, not the observation of it. Everything below this line —
    /// the cloned `RulesState`, the payload hashes, the `/proc` reads — is deliberately outside the
    /// measured window.
    /// One observation point.
    ///
    /// The counting allocator is read **first**, before anything else in this function allocates: the
    /// point is meant to describe the state, not the observation of it. Everything below this line —
    /// the cloned `RulesState`, the payload identities, the `/proc` reads, the journal write — is
    /// deliberately outside any measurement window, and the record itself is not retained.
    ///
    /// `window` is the measurement of the operation this point describes (`start_engine`,
    /// `reload_engine`, `stop_engine`) or `None` for a point that observes a state rather than an
    /// operation. A point may not claim an operation's peak without that operation's window: the
    /// first delivery did exactly that and reported the previous phase's high-water mark.
    fn point(&mut self, phase: &str, note: impl Into<String>, window: Option<&Window>) {
        let live = live_bytes();
        let now = monotonic_ns(self.started);

        let mut out = serde_json::Map::new();
        out.insert("phase".into(), json!(phase));
        out.insert("note".into(), json!(note.into()));
        out.insert("monotonic_ns".into(), json!(now));
        out.insert(
            "elapsed_seconds".into(),
            json!(now as f64 / 1_000_000_000.0),
        );
        out.insert("pid".into(), json!(std::process::id()));
        out.insert("run_id".into(), json!(self.run_id));
        out.insert("group".into(), json!(self.group));
        out.insert("formal".into(), json!(self.formal));
        let mut counted = serde_json::Map::new();
        counted.insert("live_bytes".into(), json!(live));
        counted.insert("live_mib".into(), json!(live as f64 / (1024.0 * 1024.0)));
        counted.insert(
            "scope".into(),
            json!("bytes allocated through Rust's global allocator; excludes mappings, stacks and non-Rust allocations"),
        );
        // `peak_bytes` is this operation's own window peak, never a bare counter reading. A state
        // point has no operation, so it has no peak at all rather than one borrowed from elsewhere.
        // Keeping the field mirrors the window so a reader that only looks at `counted` still sees
        // the operation's cost — and so the two can be cross-checked for agreement.
        if let Some(window) = window {
            counted.insert("peak_bytes".into(), json!(window.peak));
            counted.insert(
                "peak_mib".into(),
                json!(window.peak as f64 / (1024.0 * 1024.0)),
            );
            counted.insert("peak_scope".into(), json!("this operation's own window"));
        }
        out.insert("counted".into(), Value::Object(counted));
        // The operation whose cost this point reports. Absent means "this point observes a state, not
        // an operation", and the checker requires exactly that split rather than accepting a stale
        // counter as the phase's peak.
        out.insert(
            "window".into(),
            match window {
                Some(window) => window.json(phase),
                None => Value::Null,
            },
        );
        // An independent, kernel-side high-water mark of the *process* address space. It cannot be
        // reset, so it is not a phase measurement; it is reported because it lets a reader see that
        // the counted peak is not larger than what the kernel recorded, and because a probe that
        // forgot to reset would show a counted peak equal to a much older phase.
        out.insert("vm_peak_kib".into(), json!(proc_status_kib("VmPeak")));

        // The live handle and what it says is in force.
        let state: Option<RulesState> = self.handle.and_then(zshield::jni_api::handle_rules_state);
        match (self.handle, &state) {
            (Some(handle), Some(state)) => {
                out.insert("handle".into(), json!(handle));
                out.insert("handle_state".into(), json!("live"));
                out.insert("generation".into(), json!(state.generation));
                out.insert(
                    "identities".into(),
                    json!({
                        "dns": state.identities.dns.as_ref().map(PayloadIdentity::token),
                        "engine": state.identities.engine.as_ref().map(PayloadIdentity::token),
                        "extras": state.identities.extras.as_ref().map(PayloadIdentity::token),
                    }),
                );
            }
            (Some(handle), None) => {
                // A handle that is registered but reports no rule state is a defect, not an absence.
                out.insert("handle".into(), json!(handle));
                out.insert("handle_state".into(), json!("missing-rules-state"));
                out.insert("generation".into(), Value::Null);
                out.insert("identities".into(), Value::Null);
            }
            _ => {
                out.insert("handle".into(), Value::Null);
                out.insert(
                    "handle_state".into(),
                    json!(if self.point_count == 0 {
                        "no-handle-yet"
                    } else {
                        "released"
                    }),
                );
                out.insert("generation".into(), Value::Null);
                out.insert("identities".into(), Value::Null);
            }
        }

        // The identity of the payloads on disk *right now*, so "the generation the handle reports" can
        // be compared with "the bytes in the directory in force" rather than trusted. Served from the
        // per-directory cache: each directory is written once, and re-reading 41 MB here would
        // allocate inside the phase whose peak was just taken.
        let ondisk = match self.current_dir.clone() {
            Some(dir) => self.cached_artifacts(&dir).ok(),
            None => None,
        };
        if let Some(dir) = &self.current_dir {
            out.insert("rule_dir".into(), json!(dir.display().to_string()));
        }
        out.insert("ondisk_identity".into(), ondisk.unwrap_or(Value::Null));

        // Residency, exactly as the kernel prints it.
        out.insert("smaps_source".into(), json!("/proc/self/smaps_rollup"));
        out.insert("smaps_unit".into(), json!("kB"));
        out.insert(
            "smaps".into(),
            match smaps_rollup() {
                Some(fields) => json!(fields),
                None => Value::Null,
            },
        );

        out.insert("fd_count".into(), json!(count_entries("/proc/self/fd")));
        out.insert(
            "thread_count".into(),
            json!(count_entries("/proc/self/task")),
        );
        out.insert(
            "weaks".into(),
            match &self.weaks {
                Some(weaks) => weaks.liveness(),
                None => Value::Null,
            },
        );

        self.point_count += 1;
        self.record("point", Value::Object(out));
    }

    /// The point after `stop`, plus the resource-settle evidence that only exists once it is polled.
    ///
    /// Split from [`point`](Self::point) so the settle wait — which sleeps — happens *before* the
    /// counting allocator is sampled, not inside the observation.
    fn point_after_stop(
        &mut self,
        fds: Option<usize>,
        threads: Option<usize>,
        waited_ms: u64,
        window: Option<&Window>,
    ) {
        self.point(
            "stopped",
            "stop_engine returned, the peer end closed and the loop's resources were polled to rest",
            window,
        );
        self.record(
            "resource_settle",
            json!({
                "waited_ms": waited_ms,
                "fd_count": fds,
                "thread_count": threads,
                "baseline_fd_count": self.baseline_fds,
                "baseline_thread_count": self.baseline_threads,
            }),
        );
    }

    /// The two slots an observation must never leave empty, checked while the journal is read back.
    ///
    /// This is a check *over the journal*, not over an in-memory list, so it verifies the document a
    /// reviewer will read rather than a parallel copy that could diverge from it.
    fn require_observations(&mut self, points: &[Value]) {
        let mut missing = Vec::new();
        for point in points {
            let phase = point
                .get("phase")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            if point.get("smaps").map(Value::is_null).unwrap_or(true) {
                missing.push(format!("{phase}: no /proc/self/smaps_rollup fields"));
            }
            if point.get("fd_count").map(Value::is_null).unwrap_or(true) {
                missing.push(format!("{phase}: no /proc/self/fd count"));
            }
            if point
                .get("thread_count")
                .map(Value::is_null)
                .unwrap_or(true)
            {
                missing.push(format!("{phase}: no /proc/self/task count"));
            }
            if point.get("handle_state").and_then(Value::as_str) == Some("missing-rules-state") {
                missing.push(format!(
                    "{phase}: handle registered but reported no rule state"
                ));
            }
            if point.get("handle_state").and_then(Value::as_str) == Some("live")
                && point
                    .get("ondisk_identity")
                    .map(Value::is_null)
                    .unwrap_or(true)
            {
                missing.push(format!(
                    "{phase}: live handle with no readable on-disk artifacts"
                ));
            }
            if point.get("vm_peak_kib").map(Value::is_null).unwrap_or(true) {
                missing.push(format!("{phase}: no /proc/self/status VmPeak"));
            }
            // An operation point must carry the window of *that* operation. A point that reports a
            // peak without one is reporting some earlier phase's high-water mark, which is exactly
            // the defect the review found in `started-a` and `stopped`.
            let is_operation =
                OPERATION_PHASES.contains(&phase.as_str()) || phase.starts_with("ab-round-");
            if is_operation && point.get("window").map(Value::is_null).unwrap_or(true) {
                missing.push(format!(
                    "{phase}: an operation point with no measurement window of its own"
                ));
            }
            if !is_operation
                && !phase.starts_with("trim-diagnostic")
                && !point.get("window").map(Value::is_null).unwrap_or(true)
            {
                missing.push(format!(
                    "{phase}: a state point that claims an operation window"
                ));
            }
        }
        for reason in missing {
            self.check("observation/completeness", false, reason);
        }
    }

    // ---- lifecycle steps ---------------------------------------------------------------------

    fn compile(&mut self, label: &str, dir: &Path, user_rules: &str) -> Result<Value, String> {
        let request = json!({
            "lists": self.lists.iter().map(|list| json!({
                "id": list["id"],
                "path": list["path"],
            })).collect::<Vec<_>>(),
            "userRules": user_rules,
            "allowlist": [],
            "outputDir": dir.display().to_string(),
            "debugRules": false,
        })
        .to_string();
        let mut window = Window::begin(self.started);
        let compiled = zshield::compile::compile_request(&request);
        window.end(self.started);
        let stats = compiled.map_err(|e| format!("compile {label}: {e}"))?;
        // Artifact hashing is deliberately after `window.end`: reading 41 MB would otherwise land
        // inside the compile's window and be reported as the compile's own high-water mark.
        let facts = self.cached_artifacts(dir)?;
        self.roles
            .insert(label.to_string(), dir.display().to_string());
        let record = json!({
            "dir": dir.display().to_string(),
            "stats": stats,
            "artifacts": facts,
            "window": window.json(&format!("compile-{label}")),
        });
        self.record(
            "compile",
            json!({"label": label, "dir": dir.display().to_string(), "record": record}),
        );
        Ok(record)
    }

    /// Artifact facts for a directory, hashed at most once.
    ///
    /// Reading `engine.bin` allocates its 41 MB payload, which is far larger than anything else this
    /// probe does. Hashing it at every observation point would put that allocation inside a phase
    /// whose peak had just been recorded and would show up as memory the *tunnel* used. Each compiled
    /// directory is written once and never again, so one hash per directory is the correct cache key.
    fn cached_artifacts(&mut self, dir: &Path) -> Result<Value, String> {
        let key = dir.display().to_string();
        if let Some(facts) = self.artifact_cache.get(&key) {
            return Ok(facts.clone());
        }
        let facts = artifact_set(dir)?;
        self.artifact_cache.insert(key, facts.clone());
        Ok(facts)
    }

    fn start(&mut self) -> Result<UnixDatagram, String> {
        let dir = self.compiled_a.clone();
        let (tun, peer) = UnixDatagram::pair().map_err(|e| format!("socketpair: {e}"))?;
        let config = json!({
            "compiledDir": dir.display().to_string(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
            "workers": 2,
            "httpsFiltering": false,
        })
        .to_string();
        let mut window = Window::begin(self.started);
        let started = zshield::jni_api::start_engine(tun.into_raw_fd(), &config);
        window.end(self.started);
        match started {
            Ok(handle) => {
                self.handle = Some(handle);
                self.current_dir = Some(dir);
                self.start_window = Some(window);
                Ok(peer)
            }
            Err(error) => {
                drop(peer);
                self.start_window = Some(window);
                Err(format!("start: {error}"))
            }
        }
    }

    /// One reload whose outcome is asserted against the rule set it loaded.
    ///
    /// Returns `(returned, generation, effect, identities_match)`. The generation is read from the
    /// handle *after* the call, and the expected generation delta is checked by the caller so a
    /// skipped and a rebuilt reload cannot be confused.
    fn reload(&mut self, dir: &Path) -> Result<Value, String> {
        let handle = self
            .handle
            .ok_or_else(|| "reload without a live handle".to_string())?;
        let before = zshield::jni_api::handle_rules_state(handle)
            .map(|state| state.generation)
            .ok_or_else(|| "no rule state before reload".to_string())?;
        // The artifacts are hashed **before** the measured window opens, so the probe's own 41 MB
        // read is not attributed to the reload. Both directories were written by this run's compiles
        // and never touched since, so the cache is not stale.
        let ondisk = self.cached_artifacts(dir)?;
        let mut window = Window::begin(self.started);
        let returned = zshield::jni_api::reload_engine(handle, &dir.display().to_string());
        // Captured immediately: everything below (the effect evaluation, the journal write)
        // allocates too, and attributing that to the reload would inflate the number the card asks
        // for by an order of magnitude.
        window.end(self.started);
        self.current_dir = Some(dir.to_path_buf());
        let after = zshield::jni_api::handle_rules_state(handle)
            .ok_or_else(|| "no rule state after reload".to_string())?;
        let effect = removeparam_effect(handle)?;
        let identities_match = identities_match(&after, &ondisk);
        Ok(json!({
            "dir": dir.display().to_string(),
            "returned": returned,
            "generation_before": before,
            "generation_after": after.generation,
            "effect_url": effect,
            "identities_match_ondisk": identities_match,
            "window": window.json("reload"),
        }))
    }

    /// Stop the tunnel, measuring the `stop_engine` call on its own.
    ///
    /// The first delivery reported `stopped` with exactly the settled/A–B peak for the same reason as
    /// `started-a`: no reset, so the previous phase's high-water mark was read back. The window here
    /// is the `stop_engine` call alone; releasing the peer descriptor and polling the resources to
    /// rest happen after it and are reported separately.
    fn stop(&mut self, peer: UnixDatagram) -> Option<Window> {
        let mut window = None;
        if let Some(handle) = self.handle.take() {
            let mut measured = Window::begin(self.started);
            zshield::jni_api::stop_engine(handle);
            measured.end(self.started);
            window = Some(measured);
        }
        drop(peer);
        self.current_dir = None;
        window
    }
}

/// Rebuild a [`Window`] from the record an operation returned, so a later observation point can
/// report *that operation's* measurement rather than whatever the counters hold now.
fn window_of(record: &Value) -> Option<Window> {
    let window = record.get("window")?;
    if window.is_null() {
        return None;
    }
    Some(Window {
        started_live: window.get("started_live_bytes")?.as_u64()?,
        started_monotonic_ns: window.get("started_monotonic_ns")?.as_u64()?,
        peak: window.get("peak_bytes")?.as_u64()?,
        ended_live: window.get("ended_live_bytes")?.as_u64()?,
        ended_monotonic_ns: window.get("ended_monotonic_ns")?.as_u64()?,
        closed: true,
    })
}

/// Does the handle's reported rule identity equal the payload identity of the artifacts on disk?
fn identities_match(state: &RulesState, ondisk: &Value) -> bool {
    let token = |name: &str| {
        ondisk
            .get(name)
            .and_then(|entry| entry.get("payload_token"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let same = |reported: &Option<PayloadIdentity>, name: &str| match (reported, token(name)) {
        (Some(reported), Some(on_disk)) => reported.token() == on_disk,
        (None, None) => true,
        _ => false,
    };
    same(&state.identities.dns, "dns.bin")
        && same(&state.identities.engine, "engine.bin")
        && same(&state.identities.extras, "extras.txt")
}

/// The identity components of one artifact set, for comparing two compiles.
fn component<'a>(set: &'a Value, name: &str, field: &str) -> Option<&'a str> {
    set.get(name)?.get(field)?.as_str()
}

fn write_selftest_lists(work: &Path) -> Result<PathBuf, String> {
    let dir = work.join("lists-selftest");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (id, body) in SELFTEST_LISTS {
        let path = dir.join(format!("{id}.txt"));
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(dir)
}

/// The canonical manifest for a group, or the self-test stand-in.
fn list_specs(group: &str, lists_dir: &Path) -> Result<Vec<Value>, String> {
    let specs: Vec<(&str, Option<u64>, Option<&str>)> = match group {
        "five" => FIVE
            .iter()
            .map(|spec| (spec.id, Some(spec.bytes), Some(spec.sha256)))
            .collect(),
        "nine" => FIVE
            .iter()
            .chain(NINE_EXTRA.iter())
            .map(|spec| (spec.id, Some(spec.bytes), Some(spec.sha256)))
            .collect(),
        "selftest" => SELFTEST_LISTS
            .iter()
            .map(|(id, _)| (*id, None, None))
            .collect(),
        other => {
            return Err(format!(
                "unknown group {other}: expected five, nine or selftest"
            ))
        }
    };

    let mut out = Vec::with_capacity(specs.len());
    let mut problems = Vec::new();
    for (id, expected_bytes, expected_sha) in specs {
        let path = lists_dir.join(format!("{id}.txt"));
        if !path.is_file() {
            problems.push(format!("missing list body {}", path.display()));
            continue;
        }
        let (sha256, bytes) = sha256_file(&path)?;
        if let (Some(expected_bytes), Some(expected_sha)) = (expected_bytes, expected_sha) {
            if bytes != expected_bytes {
                problems.push(format!(
                    "{id}: {bytes} B, the group's manifest says {expected_bytes} B"
                ));
            }
            if sha256 != expected_sha {
                problems.push(format!(
                    "{id}: sha256 {sha256}, the group's manifest says {expected_sha}"
                ));
            }
        }
        let lines = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .lines()
            .count();
        out.push(json!({
            "id": id,
            "path": path.display().to_string(),
            "bytes": bytes,
            "sha256": sha256,
            "lines": lines,
            "expected_bytes": expected_bytes,
            "expected_sha256": expected_sha,
        }));
    }

    // Extra `.txt` files in the directory would be silently ignored by the compile list above, but a
    // directory that does not hold exactly the group is not the group's input.
    if group != "selftest" {
        let expected: std::collections::BTreeSet<&str> = match group {
            "five" => FIVE.iter().map(|spec| spec.id).collect(),
            "nine" => FIVE
                .iter()
                .chain(NINE_EXTRA.iter())
                .map(|spec| spec.id)
                .collect(),
            _ => std::collections::BTreeSet::new(),
        };
        if let Ok(entries) = std::fs::read_dir(lists_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("txt") {
                    continue;
                }
                let stem = path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or("")
                    .to_string();
                if !expected.contains(stem.as_str()) {
                    problems.push(format!(
                        "unexpected list body {} in a {group}-group directory",
                        path.display()
                    ));
                }
            }
        }
    }

    if !problems.is_empty() {
        return Err(format!(
            "input verification failed for group {group}:\n  {}",
            problems.join("\n  ")
        ));
    }
    Ok(out)
}

struct Args {
    work: PathBuf,
    lists: PathBuf,
    group: String,
    run: u32,
    trim_diagnostic: bool,
    run_id: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut work = None;
    let mut lists = None;
    let mut group = None;
    let mut run = 0u32;
    let mut trim_diagnostic = false;
    let mut run_id = None;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--work" => work = args.next().map(PathBuf::from),
            "--lists" => lists = args.next().map(PathBuf::from),
            "--group" => group = args.next(),
            "--run" => {
                run = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| "--run needs a number".to_string())?
            }
            "--run-id" => run_id = args.next(),
            "--trim-diagnostic" => trim_diagnostic = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        work: work.ok_or("--work <dir> is required")?,
        lists: lists.ok_or("--lists <dir> is required")?,
        group: group.ok_or("--group five|nine|selftest is required")?,
        run,
        trim_diagnostic,
        run_id,
    })
}

fn run(args: Args) -> Result<Value, String> {
    let started_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let formal = args.group != "selftest";
    let run_id = args.run_id.clone().unwrap_or_else(|| {
        format!(
            "{}-r{}-{}-{}",
            args.group,
            args.run,
            started_unix_ns / 1_000_000_000,
            std::process::id()
        )
    });

    let run_dir = args.work.join(format!("{}-run{:02}", args.group, args.run));
    std::fs::create_dir_all(&run_dir).map_err(|e| format!("{}: {e}", run_dir.display()))?;

    // `selftest` writes its own tiny bodies; the real groups must match their manifest exactly.
    let lists_dir = if args.group == "selftest" {
        write_selftest_lists(&run_dir)?
    } else {
        args.lists.clone()
    };
    let lists = list_specs(&args.group, &lists_dir)?;

    let binary = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let (binary_sha256, binary_bytes) = sha256_file(&binary)?;

    // One JSON object per observation, written as it is taken. This file is the run's raw evidence
    // and the source of the report; nothing is accumulated in memory, so the counting allocator
    // reports the tunnel rather than the measurement of it.
    let journal_path = run_dir.join("journal.jsonl");
    let journal = std::io::BufWriter::new(
        std::fs::File::create(&journal_path)
            .map_err(|e| format!("{}: {e}", journal_path.display()))?,
    );

    let mut probe = Probe {
        run_id: run_id.clone(),
        group: args.group.clone(),
        formal,
        work: run_dir.clone(),
        compiled_a: run_dir.join("compiled-a"),
        compiled_b: run_dir.join("compiled-b"),
        lists,
        user_rule_a: RULE_A.to_string(),
        user_rule_b: RULE_B.to_string(),
        journal,
        journal_path,
        artifact_cache: BTreeMap::new(),
        roles: BTreeMap::new(),
        assertion_count: 0,
        point_count: 0,
        failures: Vec::new(),
        current_dir: None,
        handle: None,
        weaks: None,
        start_window: None,
        trim_diagnostic: args.trim_diagnostic,
        started: Instant::now(),
        baseline_fds: None,
        baseline_threads: None,
    };

    // ---- 1. process baseline ---------------------------------------------------------------
    reset_peak();
    probe.baseline_fds = count_entries("/proc/self/fd");
    probe.baseline_threads = count_entries("/proc/self/task");
    probe.point(
        "process-baseline",
        "before any compile, socket pair or engine",
        None,
    );

    // ---- 2. compile A, temporaries released -------------------------------------------------
    let set_a = probe.compile("a", &probe.compiled_a.clone(), &probe.user_rule_a.clone())?;
    let compile_a_window = window_of(&set_a);
    probe.point(
        "compiled-a",
        "compile_request returned; its list texts and serialized payloads are gone",
        compile_a_window.as_ref(),
    );

    // ---- 3. start A -------------------------------------------------------------------------
    let peer = probe.start()?;
    let handle = probe.handle.expect("start returned a handle");
    let weaks_a = capture_weaks(handle)?;
    probe.weaks = Some(capture_weaks(handle)?);
    probe.point(
        "started-a",
        "start_engine over a UnixDatagram pair standing in for the TUN descriptor",
        probe.start_window.clone().as_ref(),
    );
    let state = zshield::jni_api::handle_rules_state(handle)
        .ok_or_else(|| "no rule state after start".to_string())?;
    let set_a_artifacts = set_a
        .get("artifacts")
        .cloned()
        .ok_or_else(|| "compile a recorded no artifacts".to_string())?;
    probe.check(
        "start/generation-installed",
        state.generation > 0,
        format!("generation {}", state.generation),
    );
    probe.check(
        "start/identities-match-ondisk",
        identities_match(&state, &set_a_artifacts),
        "the handle must report the payloads that are on disk",
    );
    // The first `$removeparam` evaluation builds the lazily cached scope engines
    // (`RemoveParamRules::cached_engines`, documented in `https::extras`), so it is measured as its
    // own step. Folding it into "started" would credit the *start* with memory the first decided
    // request allocates; folding it into the reload rounds would do the same for the swap.
    let mut first_effect_window = Window::begin(probe.started);
    let effect = removeparam_effect(handle)?;
    first_effect_window.end(probe.started);
    probe.point(
        "first-removeparam-evaluation",
        "the first $removeparam evaluation, which builds the lazily cached scope engines",
        Some(&first_effect_window),
    );
    probe.check(
        "start/rule-a-in-force",
        effect == EFFECT_WITH_A,
        format!("want {EFFECT_WITH_A}, got {effect}"),
    );

    // ---- 4. twenty unchanged reloads --------------------------------------------------------
    let mut unchanged_ok = 0usize;
    let mut unchanged_generation = state.generation;
    let mut unchanged_objects = true;
    let mut unchanged_effect = 0usize;
    let mut unchanged_peak_window: Option<Window> = None;
    for round in 0..UNCHANGED_RELOADS {
        let record = probe.reload(&probe.compiled_a.clone())?;
        let returned = record["returned"].as_bool().unwrap_or(false);
        let generation = record["generation_after"].as_u64().unwrap_or(0);
        let after = capture_weaks(handle)?;
        let same_objects = after.same_as(&weaks_a);
        unchanged_objects &= same_objects;
        unchanged_generation = generation;
        let effect_ok = record["effect_url"].as_str() == Some(EFFECT_WITH_A);
        if effect_ok {
            unchanged_effect += 1;
        }
        if returned && generation == state.generation && same_objects && effect_ok {
            unchanged_ok += 1;
        }
        probe.record(
            "round",
            json!({
                "kind": "unchanged",
                "round": round + 1,
                "returned": returned,
                "generation": generation,
                "objects_reused": same_objects,
                // What the tunnel actually decided, so the checker derives the verdict from it rather
                // than from `effect_ok`.
                "effect_url": record["effect_url"],
                "effect_ok": effect_ok,
                "identities_match_ondisk": record["identities_match_ondisk"],
                // Each round's own window: the fast path must be cheap per call, not cheap on average.
                "window": record["window"],
            }),
        );
        // The point that summarises the 20 rounds reports the highest of *their* windows, so it can
        // never borrow a different phase's high-water mark.
        let round_window = window_of(&record);
        if let Some(round_window) = round_window {
            let higher = match &unchanged_peak_window {
                Some(current) => round_window.peak > current.peak,
                None => true,
            };
            if higher {
                unchanged_peak_window = Some(round_window);
            }
        }
    }
    probe.weaks = Some(capture_weaks(handle)?);
    probe.point(
        "unchanged-reloads-done",
        "20 reloads of the same artifact set: the peak of their own windows, not a later phase's",
        unchanged_peak_window.as_ref(),
    );
    probe.check(
        "unchanged/all-20-kept-the-loaded-rules",
        unchanged_ok == UNCHANGED_RELOADS,
        format!(
            "{unchanged_ok}/{UNCHANGED_RELOADS} returned true with the same generation and objects"
        ),
    );
    probe.check(
        "unchanged/generation-did-not-move",
        unchanged_generation == state.generation,
        format!("{} -> {unchanged_generation}", state.generation),
    );
    probe.check(
        "unchanged/objects-not-rebuilt",
        unchanged_objects,
        "the filter, DNS filter, engine and extras must be the same allocations each time",
    );
    probe.check(
        "unchanged/effect-stayed-a",
        unchanged_effect == UNCHANGED_RELOADS,
        format!("{unchanged_effect}/{UNCHANGED_RELOADS} evaluations still removed `old`"),
    );

    // ---- 5. compile B ----------------------------------------------------------------------
    let set_b = probe.compile("b", &probe.compiled_b.clone(), &probe.user_rule_b.clone())?;
    let compile_b_window = window_of(&set_b);
    probe.point(
        "compiled-b",
        "rule B differs from A by one typed regex $removeparam only",
        compile_b_window.as_ref(),
    );
    let set_b_artifacts = set_b
        .get("artifacts")
        .cloned()
        .ok_or_else(|| "compile b recorded no artifacts".to_string())?;
    let dns_same = component(&set_a_artifacts, "dns.bin", "file_sha256")
        == component(&set_b_artifacts, "dns.bin", "file_sha256");
    let engine_same = component(&set_a_artifacts, "engine.bin", "file_sha256")
        == component(&set_b_artifacts, "engine.bin", "file_sha256");
    let extras_diff = component(&set_a_artifacts, "extras.txt", "file_sha256")
        != component(&set_b_artifacts, "extras.txt", "file_sha256");
    probe.check(
        "ab/dns-bin-identical",
        dns_same,
        "measured, not assumed: A and B must produce the same dns.bin",
    );
    probe.check(
        "ab/engine-bin-identical",
        engine_same,
        "measured, not assumed: A and B must produce the same engine.bin",
    );
    probe.check(
        "ab/extras-changed",
        extras_diff,
        "the single rule change must reach extras.txt",
    );

    // ---- 6. reload B on the same handle ----------------------------------------------------
    let before_b = zshield::jni_api::handle_rules_state(handle)
        .map(|state| state.generation)
        .unwrap_or(0);
    let reload_b = probe.reload(&probe.compiled_b.clone())?;
    let after_b = capture_weaks(handle)?;
    probe.point(
        "reloaded-b",
        "same handle, artifact set B: DNS identity constant, extras replaced",
        window_of(&reload_b).as_ref(),
    );
    probe.check(
        "reload-b/returned",
        reload_b["returned"].as_bool().unwrap_or(false),
        "a swap that installed every component returns true",
    );
    probe.check(
        "reload-b/generation-advanced-once",
        reload_b["generation_after"].as_u64() == Some(before_b + 1),
        format!("{before_b} -> {}", reload_b["generation_after"]),
    );
    probe.check(
        "reload-b/rule-b-in-force",
        reload_b["effect_url"].as_str() == Some(EFFECT_WITH_B),
        format!(
            "want {EFFECT_WITH_B}, got {}",
            reload_b["effect_url"].as_str().unwrap_or("?")
        ),
    );
    probe.check(
        "reload-b/identities-match-ondisk",
        reload_b["identities_match_ondisk"]
            .as_bool()
            .unwrap_or(false),
        "the generation must describe the payloads on disk",
    );
    probe.check(
        "reload-b/previous-rules-released",
        weaks_a.released(),
        format!(
            "old dns={} engine={} extras={} strong refs left",
            weaks_a.dns.strong_count(),
            weaks_a.engine.strong_count(),
            weaks_a.extras.strong_count()
        ),
    );
    probe.check(
        "reload-b/filter-object-stable",
        Weak::ptr_eq(&weaks_a.filter, &after_b.filter),
        "a swap replaces the contents of the filter, not the filter the pipeline holds",
    );

    // ---- 7. A/B alternation ----------------------------------------------------------------
    let mut previous = after_b;
    let mut ab_ok = 0usize;
    let mut ab_expected_generation = reload_b["generation_after"].as_u64().unwrap_or(0);
    for round in 0..AB_ROUNDS {
        let (dir, rule, expected) = if round % 2 == 0 {
            (probe.compiled_a.clone(), "a", EFFECT_WITH_A)
        } else {
            (probe.compiled_b.clone(), "b", EFFECT_WITH_B)
        };
        let record = probe.reload(&dir)?;
        let after = capture_weaks(handle)?;
        probe.weaks = Some(capture_weaks(handle)?);
        ab_expected_generation += 1;
        let generation = record["generation_after"].as_u64().unwrap_or(0);
        let returned = record["returned"].as_bool().unwrap_or(false);
        let effect_ok = record["effect_url"].as_str() == Some(expected);
        let identities_ok = record["identities_match_ondisk"].as_bool().unwrap_or(false);
        let previous_released = previous.released();
        let filter_stable = Weak::ptr_eq(&previous.filter, &after.filter);
        if returned
            && generation == ab_expected_generation
            && effect_ok
            && identities_ok
            && previous_released
            && filter_stable
        {
            ab_ok += 1;
        }
        probe.record(
            "round",
            json!({
                "kind": "ab",
                "round": round + 1,
                "loaded": rule,
                "returned": returned,
                "generation": generation,
                "generation_expected": ab_expected_generation,
                "effect_url": record["effect_url"],
                "effect_expected": expected,
                "identities_match_ondisk": identities_ok,
                "previous_rules_released": previous_released,
                "filter_object_stable": filter_stable,
                "window": record["window"],
            }),
        );
        probe.point(
            &format!("ab-round-{:02}", round + 1),
            format!("A/B alternation, artifact set {}", rule.to_uppercase()),
            window_of(&record).as_ref(),
        );
        previous = after;
    }
    probe.weaks = Some(capture_weaks(handle)?);
    probe.check(
        "ab/all-rounds-consistent",
        ab_ok == AB_ROUNDS,
        format!("{ab_ok}/{AB_ROUNDS} rounds swapped, decided and released as expected"),
    );

    // ---- 8. settled holding state ----------------------------------------------------------
    probe.point(
        "settled",
        "the state a running tunnel sits in between compiles; rules in force, probe holding only Weak",
        None,
    );

    // ---- 9. optional trim diagnostic (explicitly not a production change) -------------------
    if probe.trim_diagnostic {
        let before = smaps_rollup();
        let live_before = live_bytes();
        let mut first_trim = Window::begin(probe.started);
        zshield::mem::trim_allocator();
        first_trim.end(probe.started);
        let after_first = smaps_rollup();
        let mut second_trim = Window::begin(probe.started);
        zshield::mem::trim_allocator();
        second_trim.end(probe.started);
        let after_second = smaps_rollup();
        let live_after = live_bytes();
        let state = probe.handle.and_then(zshield::jni_api::handle_rules_state);
        let ondisk = probe
            .current_dir
            .clone()
            .map(|dir| probe.cached_artifacts(&dir))
            .transpose()?;
        probe.record(
            "point",
            json!({
                "phase": "trim-diagnostic-rules-held",
                "note": "diagnostic only: not a production change and not part of the lifecycle above",
                "monotonic_ns": monotonic_ns(probe.started),
                "pid": std::process::id(),
                "run_id": probe.run_id,
                "group": probe.group,
                "formal": probe.formal,
                "handle": probe.handle,
                "handle_state": "live",
                "generation": state.as_ref().map(|s| s.generation),
                "identities": state.as_ref().map(|s| json!({
                    "dns": s.identities.dns.as_ref().map(PayloadIdentity::token),
                    "engine": s.identities.engine.as_ref().map(PayloadIdentity::token),
                    "extras": s.identities.extras.as_ref().map(PayloadIdentity::token),
                })),
                "ondisk_identity": ondisk,
                "counted": {"live_bytes": live_after, "live_mib": live_after as f64 / (1024.0*1024.0),
                            "live_before_bytes": live_before,
                            "scope": "bytes allocated through Rust's global allocator"},
                "windows": [first_trim.json("trim-1"), second_trim.json("trim-2")],
                "window_scope": "each trim separately; smaps reads occur outside both windows",
                "smaps_source": "/proc/self/smaps_rollup",
                "smaps_unit": "kB",
                "smaps": {"before": before, "after_first": after_first, "after_second": after_second},
                "fd_count": count_entries("/proc/self/fd"),
                "thread_count": count_entries("/proc/self/task"),
                "vm_peak_kib": proc_status_kib("VmPeak"),
            }),
        );
    }

    // ---- 10. stop and release --------------------------------------------------------------
    let stop_window = probe.stop(peer);

    // The tunnel loop leaves its select arm and the runtime's workers are joined by the time
    // `stop_engine` returns; the descriptors the loop owned close with it. Both are polled rather
    // than assumed, and what was actually observed is reported alongside the numbers.
    let settle_deadline = Instant::now() + std::time::Duration::from_secs(10);
    let mut fds = count_entries("/proc/self/fd");
    let mut threads = count_entries("/proc/self/task");
    let mut waited_ms = 0u64;
    while Instant::now() < settle_deadline {
        let fds_ok = match (fds, probe.baseline_fds) {
            (Some(now), Some(base)) => now <= base,
            _ => false,
        };
        let threads_ok = match (threads, probe.baseline_threads) {
            (Some(now), Some(base)) => now <= base,
            _ => false,
        };
        if fds_ok && threads_ok {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
        waited_ms += 25;
        fds = count_entries("/proc/self/fd");
        threads = count_entries("/proc/self/task");
    }
    // Observed after the settle wait, so the point describes the state the run actually reached.
    probe.point_after_stop(fds, threads, waited_ms, stop_window.as_ref());

    probe.check(
        "stop/handle-gone",
        zshield::jni_api::handle_rules_state(handle).is_none()
            && zshield::jni_api::handle_http_filter(handle).is_none()
            && zshield::jni_api::handle_dns_filter(handle).is_none(),
        "every accessor must report the handle is gone",
    );
    probe.check(
        "stop/rules-released",
        probe
            .weaks
            .as_ref()
            .map(Weaks::all_released)
            .unwrap_or(false),
        match &probe.weaks {
            Some(weaks) => format!("weak liveness after stop: {}", weaks.liveness()),
            None => "no weaks were captured".to_string(),
        },
    );
    probe.check(
        "stop/fds-returned",
        matches!((fds, probe.baseline_fds), (Some(now), Some(base)) if now <= base),
        format!(
            "fd {fds:?} vs baseline {:?} after {waited_ms} ms",
            probe.baseline_fds
        ),
    );
    probe.check(
        "stop/threads-returned",
        matches!((threads, probe.baseline_threads), (Some(now), Some(base)) if now <= base),
        format!(
            "threads {threads:?} vs baseline {:?} after {waited_ms} ms",
            probe.baseline_threads
        ),
    );

    if probe.trim_diagnostic {
        let before = smaps_rollup();
        let live_before = live_bytes();
        let mut first_trim = Window::begin(probe.started);
        zshield::mem::trim_allocator();
        first_trim.end(probe.started);
        let after_first = smaps_rollup();
        let mut second_trim = Window::begin(probe.started);
        zshield::mem::trim_allocator();
        second_trim.end(probe.started);
        let after_second = smaps_rollup();
        let live_after = live_bytes();
        probe.record(
            "point",
            json!({
                "phase": "trim-diagnostic-after-stop",
                "note": "diagnostic only: the rules are already released here, so this is a teardown control",
                "monotonic_ns": monotonic_ns(probe.started),
                "pid": std::process::id(),
                "run_id": probe.run_id,
                "group": probe.group,
                "formal": probe.formal,
                "handle": Value::Null,
                "handle_state": "released",
                "counted": {"live_bytes": live_after, "live_mib": live_after as f64 / (1024.0*1024.0),
                            "live_before_bytes": live_before,
                            "scope": "bytes allocated through Rust's global allocator"},
                "windows": [first_trim.json("trim-1"), second_trim.json("trim-2")],
                "window_scope": "each trim separately; smaps reads occur outside both windows",
                "smaps_source": "/proc/self/smaps_rollup",
                "smaps_unit": "kB",
                "smaps": {"before": before, "after_first": after_first, "after_second": after_second},
                "fd_count": count_entries("/proc/self/fd"),
                "thread_count": count_entries("/proc/self/task"),
                "vm_peak_kib": proc_status_kib("VmPeak"),
            }),
        );
    }

    // ---- document --------------------------------------------------------------------------
    // Everything the run observed now lives only in the journal; read it back in one pass so the
    // report is assembled from exactly the bytes a reviewer can inspect, and verify there that no
    // observation is missing. The journal must be flushed first: the writer buffers, and an unflushed
    // read would silently drop the last observations — exactly the "a missing observation looks like
    // a result" failure this card is about.
    probe.flush_journal();
    let Journal {
        points,
        rounds,
        assertions,
    } = read_journal(&probe.journal_path)?;
    probe.require_observations(&points);

    // Optional diagnostics must not replace the recorded holding/stop observations in the summary.
    let observed = |phase: &str, pointer: &str| {
        points
            .iter()
            .find(|point| point["phase"] == phase)
            .and_then(|point| point.pointer(pointer))
            .and_then(Value::as_u64)
    };
    let holding_live =
        observed("settled", "/counted/live_bytes").ok_or("missing settled live heap")?;
    let holding_rss = observed("settled", "/smaps/Rss").ok_or("missing settled RSS")?;
    let stop_live =
        observed("stopped", "/counted/live_bytes").ok_or("missing stopped live heap")?;

    let baseline_live = points
        .iter()
        .find(|point| point["phase"] == "process-baseline")
        .and_then(|point| point.pointer("/counted/live_bytes"))
        .and_then(Value::as_u64);
    // Every peak in the summary comes from the measurement window of the operation that produced
    // it, never from a bare counter reading: the first delivery's summary mixed the two and the
    // review found a "reload peak" that was really an older phase's high-water mark.
    let window_peak = |point: &Value| point.pointer("/window/peak_bytes").and_then(Value::as_u64);
    // These differences compare the unchanged batch with its post-batch state and the A/B peak
    // with the subsequent settled state. They are not measurements of simultaneous allocations.
    let unchanged_peak = points
        .iter()
        .find(|point| point["phase"] == "unchanged-reloads-done")
        .and_then(window_peak);
    let reload_peak = points
        .iter()
        .filter(|point| {
            point["phase"]
                .as_str()
                .map(|phase| phase.starts_with("ab-round"))
                .unwrap_or(false)
        })
        .filter_map(window_peak)
        .max();
    let settled_point = points.iter().find(|point| point["phase"] == "settled");
    let summary = json!({
        "baseline_live_bytes": baseline_live,
        "holding_live_bytes": holding_live,
        "holding_rss_kib": holding_rss,
        "post_stop_live_bytes": stop_live,
        "released_by_stop_bytes": holding_live.saturating_sub(stop_live),
        "unchanged_reload_peak_bytes": unchanged_peak,
        "reload_peak_bytes": reload_peak,
        // These are peak-minus-later-observation differences, not simultaneous live allocations.
        "unchanged_reload_excess_bytes": unchanged_peak.map(|peak| {
            peak.saturating_sub(
                points
                    .iter()
                    .find(|point| point["phase"] == "unchanged-reloads-done")
                    .and_then(|point| point.pointer("/counted/live_bytes"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
        }),
        "reload_excess_max_bytes": reload_peak.map(|peak| {
            peak.saturating_sub(
                settled_point
                    .and_then(|point| point.pointer("/counted/live_bytes"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
        }),
        "scope": "host glibc process; not Android PSS and not a prediction of one",
    });

    let passed = probe.failures.is_empty();
    let document = json!({
        "schema": "zshield.i2.jni-memory-profile/1",
        "run_id": run_id,
        "group": probe.group,
        "formal": probe.formal,
        "run_index": args.run,
        "pid": std::process::id(),
        "started_unix_ns": started_unix_ns,
        "duration_seconds": monotonic_ns(probe.started) as f64 / 1_000_000_000.0,
        "note": "host heap via a counting allocator plus raw /proc/self/smaps_rollup; not Android PSS",
        "binary": {
            "path": binary.display().to_string(),
            "bytes": binary_bytes,
            "sha256": binary_sha256,
        },
        "work_dir": probe.work.display().to_string(),
        "journal": probe.journal_path.display().to_string(),
        "inputs": {
            "lists_dir": lists_dir.display().to_string(),
            "lists": probe.lists,
            "user_rule_a": probe.user_rule_a,
            "user_rule_a_sha256": sha256_text(&probe.user_rule_a),
            "user_rule_b": probe.user_rule_b,
            "user_rule_b_sha256": sha256_text(&probe.user_rule_b),
            "effect_url": EFFECT_URL,
            "expected_with_a": EFFECT_WITH_A,
            "expected_with_b": EFFECT_WITH_B,
        },
        "artifacts": {
            "roles": probe.roles,
            "by_dir": probe.artifact_cache,
        },
        "points": points,
        "rounds": rounds,
        "assertions": assertions,
        "assertion_count": probe.assertion_count,
        "failures": probe.failures,
        "summary": summary,
        "result": if passed { "pass" } else { "fail" },
    });
    Ok(document)
}

/// Read the journal back as three ordered lists.
///
/// The journal is one JSON object per line, written as each observation is taken. Reading it back
/// rather than keeping the records in memory is what lets the counting allocator describe the tunnel
/// instead of the bookkeeping — see [`Probe::journal`](Probe).
/// The journal's three record lists, in the order they were taken.
struct Journal {
    points: Vec<Value>,
    rounds: Vec<Value>,
    assertions: Vec<Value>,
}

fn read_journal(path: &Path) -> Result<Journal, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut points = Vec::new();
    let mut rounds = Vec::new();
    let mut assertions = Vec::new();
    for (index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: {e}", path.display(), index + 1))?;
        let kind = entry
            .get("record")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = entry.get("value").cloned().unwrap_or(Value::Null);
        match kind {
            "point" => points.push(value),
            "round" => rounds.push(value),
            "assertion" => assertions.push(value),
            "compile" | "resource_settle" => {}
            other => {
                return Err(format!(
                    "{}:{}: unknown record {other}",
                    path.display(),
                    index + 1
                ))
            }
        }
    }
    Ok(Journal {
        points,
        rounds,
        assertions,
    })
}

fn sha256_text(text: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest.as_ref() {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    hex
}

fn main() {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("usage: i2_jni_memory_profile --work <dir> --lists <dir> --group five|nine|selftest --run <n> [--trim-diagnostic]");
            eprintln!("{error}");
            // A usage error is still one legal JSON document on stdout, so a driver never has to guess
            // whether a non-zero exit produced evidence.
            println!(
                "{}",
                json!({
                    "schema": "zshield.i2.jni-memory-profile/1",
                    "result": "error",
                    "error": error,
                })
            );
            std::process::exit(2);
        }
    };
    match run(args) {
        Ok(document) => {
            let passed = document["result"] == "pass";
            match serde_json::to_string_pretty(&document) {
                Ok(text) => println!("{text}"),
                Err(error) => {
                    eprintln!("cannot serialize the document: {error}");
                    std::process::exit(1);
                }
            }
            if !passed {
                let failures = document["failures"]
                    .as_array()
                    .map(|list| list.len())
                    .unwrap_or(0);
                eprintln!("FAIL: {failures} control(s) failed");
                std::process::exit(1);
            }
            eprintln!("PASS: every control held");
        }
        Err(error) => {
            eprintln!("error: {error}");
            println!(
                "{}",
                json!({
                    "schema": "zshield.i2.jni-memory-profile/1",
                    "result": "error",
                    "error": error,
                })
            );
            std::process::exit(1);
        }
    }
}
