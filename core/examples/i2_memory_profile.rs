//! Host-side attribution of the idle rule-set footprint, structure by structure (MYS-2840).
//!
//! Usage:
//!
//! ```text
//! cargo run --release --example i2_memory_profile -- <compiled-dir> [--lists <dir>] [--json]
//! ```
//!
//! `docs/PERF.md` §14 attributed the *build* cost of the rule set on the host with a counting
//! allocator (`mem_probe.rs`). This example answers the question the memory card asks and that
//! `dumpsys meminfo` cannot: of the state a started tunnel keeps resident, **which structure holds
//! how much**, and how much of what `dumpsys` reports is the compile's allocator arena rather than
//! live rules.
//!
//! # Scope
//!
//! This is a component probe: it loads DNS, HTTP and extras, optionally compiles lists, and reloads
//! only the HTTP component from the newly compiled artifacts. It does **not** call `start_engine`
//! or `reload_engine`: DNS/extras replacement, unchanged-artifact short-circuiting, the final JNI
//! trim, live requests and the Android runtime are not reproduced. Results cannot establish the
//! cost of that complete lifecycle or a production allocator fix.
//!
//! # What is measured, and what is not
//!
//! Live heap is a counting global allocator; RSS is `/proc/self/statm`. Each step reports the live
//! delta it retained, its own high-water mark, and the RSS delta. `trim_allocator()` is the
//! same allocator primitive (`M_PURGE` on Android, `malloc_trim` on glibc), in this probe's lifecycle.
//!
//! # Trim observations (`--ab-trim`, retained for CLI compatibility)
//!
//! First measure two trims while all three rule structures remain owned; then drop them and repeat
//! as a separate teardown control. Each snapshot includes counted live bytes and unmodified kernel
//! smaps field names/units. Earlier revisions measured only after dropping the rules, so their
//! reported saving included the freed rules themselves. This is not a production timing A/B.
//!
//! **This is host memory, not Android PSS.** The two differ by the allocator (glibc here, bionic
//! scudo on the device), page sharing, the JVM's own heap, and the kernel's accounting of the mapped
//! shared library. A host number therefore supports a *mechanism* ("loading `engine.bin` retains
//! one 39.5 MiB flatbuffer, not two") and never a device figure. `docs/I2_MEMORY_PROFILE.md` states
//! this boundary; no device PSS is inferred from these numbers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

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

fn mib(bytes: f64) -> f64 {
    bytes / (1024.0 * 1024.0)
}

fn live() -> f64 {
    LIVE.load(Ordering::Relaxed) as f64
}

fn peak() -> f64 {
    PEAK.load(Ordering::Relaxed) as f64
}

fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Resident set size. `/proc/self/statm` field 2 is resident pages; the page size comes from the
/// kernel's own answer rather than an assumed 4 KiB, so a 16 KiB-page host is not scaled by 4×.
fn rss() -> f64 {
    let raw = match std::fs::read_to_string("/proc/self/statm") {
        Ok(raw) => raw,
        Err(_) => return 0.0,
    };
    let pages: u64 = match raw
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
    {
        Some(pages) => pages,
        None => return 0.0,
    };
    let page = {
        extern "C" {
            fn getpagesize() -> core::ffi::c_int;
        }
        // SAFETY: no arguments, no preconditions, always positive.
        let size = unsafe { getpagesize() };
        if size > 0 {
            size as f64
        } else {
            4096.0
        }
    };
    pages as f64 * page
}

/// One measured step: what it retained, what it peaked at, and what the process RSS did.
struct Step {
    label: &'static str,
    live_before: f64,
    live_after: f64,
    peak: f64,
    rss_before: f64,
    rss_after: f64,
    /// Whether this step's retained bytes are part of what a started tunnel keeps.
    retained_state: bool,
    note: String,
}

impl Step {
    fn retained(&self) -> f64 {
        self.live_after - self.live_before
    }

    /// How far above its own end state this step went. Reported so a compile's 200 MiB high-water
    /// mark is visibly a transient rather than retained rules.
    fn transient(&self) -> f64 {
        (self.peak - self.live_after.max(self.live_before)).max(0.0)
    }

    fn rss_delta(&self) -> f64 {
        self.rss_after - self.rss_before
    }
}

#[derive(Default)]
struct Report {
    steps: Vec<Step>,
    facts: Vec<(String, String)>,
    /// Points in the sequence where live heap and RSS were both taken, so their gap is visible.
    settled: Vec<(String, f64)>,
}

impl Report {
    fn step<T>(
        &mut self,
        label: &'static str,
        retained_state: bool,
        note: impl Into<String>,
        body: impl FnOnce() -> T,
    ) -> T {
        let live_before = live();
        let rss_before = rss();
        reset_peak();
        let value = body();
        self.steps.push(Step {
            label,
            live_before,
            live_after: live(),
            peak: peak(),
            rss_before,
            rss_after: rss(),
            retained_state,
            note: note.into(),
        });
        value
    }

    fn fact(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.facts.push((name.into(), value.into()));
    }

    /// Record RSS minus the counting allocator's live bytes at `label`.
    ///
    /// The difference is **not** "memory no live object holds". RSS also carries the code and shared
    /// mappings of this executable and its libraries, every thread stack, the allocator's own
    /// metadata, and — decisively for a probe — anything allocated outside Rust's global allocator
    /// (a C library buffer, an mmap made directly). The counter sees only what went through
    /// `GlobalAlloc`. So this number is an upper bound on "resident but not in counted live heap",
    /// and this example does not attribute it to any one cause.
    fn gap(&mut self, label: &str, live: f64, rss: f64) {
        self.settled.push((
            format!(
                "{label}: live (GlobalAlloc) {:.3} MiB, rss {:.3} MiB, rss-minus-live",
                mib(live),
                mib(rss)
            ),
            rss - live,
        ));
    }

    fn print(&self, json: bool) {
        if json {
            self.print_json();
            return;
        }
        println!(
            "# host attribution of the rule-set footprint (counting allocator + /proc/self/statm)"
        );
        println!("# NOTE: host heap, not Android PSS. Supports a mechanism, not a device figure.");
        for (name, value) in &self.facts {
            println!("# {name}: {value}");
        }
        println!();
        let header = format!(
            "{:<40} {:>11} {:>11} {:>11} {:>11}  {:<9} {}",
            "step", "retained MiB", "peak MiB", "transient MiB", "rss delta", "state?", "note"
        );
        println!("{header}");
        for step in &self.steps {
            println!(
                "{:<40} {:>11.3} {:>11.3} {:>11.3} {:>11.3}  {:<9} {}",
                step.label,
                mib(step.retained()),
                mib(step.peak),
                mib(step.transient()),
                mib(step.rss_delta()),
                if step.retained_state {
                    "retained"
                } else {
                    "transient"
                },
                step.note
            );
        }
        let retained: f64 = self
            .steps
            .iter()
            .filter(|step| step.retained_state)
            .map(Step::retained)
            .sum();
        println!();
        println!(
            "# retained live heap for a started tunnel: {:.3} MiB (sum of the 'retained' rows)",
            mib(retained)
        );
        // The gap between what live objects need and what the process keeps is the part no rule
        // holds: allocator arenas, the mapping of the shared library, and the stack. It is reported
        // as its own line because it is the quantity a device PSS includes and a live-heap sum does
        // not, so a reader cannot mistake the retained sum for the footprint.
        for (label, value) in &self.settled {
            println!("# {label}: {:.3} MiB", mib(*value));
        }
        println!("# process RSS at the end: {:.3} MiB", mib(rss()));
    }

    fn print_json(&self) {
        let mut out = String::from("{\n");
        out.push_str("  \"note\": \"host heap via a counting allocator; not Android PSS\",\n");
        out.push_str("  \"facts\": {");
        for (index, (name, value)) in self.facts.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "\n    {}: {}",
                json_string(name),
                json_string(value)
            ));
        }
        out.push_str("\n  },\n  \"steps\": [");
        for (index, step) in self.steps.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&format!(
                "\n    {{\"label\": {}, \"retained_mib\": {:.6}, \"peak_mib\": {:.6}, \
                 \"transient_mib\": {:.6}, \"rss_delta_mib\": {:.6}, \"retained_state\": {}, \
                 \"note\": {}}}",
                json_string(step.label),
                mib(step.retained()),
                mib(step.peak),
                mib(step.transient()),
                mib(step.rss_delta()),
                step.retained_state,
                json_string(&step.note)
            ));
        }
        out.push_str("\n  ],\n  \"retained_total_mib\": ");
        let retained: f64 = self
            .steps
            .iter()
            .filter(|step| step.retained_state)
            .map(Step::retained)
            .sum();
        out.push_str(&format!("{:.6},\n", mib(retained)));
        out.push_str(&format!("  \"rss_end_mib\": {:.6}\n}}\n", mib(rss())));
        print!("{out}");
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32))
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut compiled: Option<PathBuf> = None;
    let mut lists_dir: Option<PathBuf> = None;
    let mut json = false;
    let mut ab_trim = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--json" => json = true,
            "--ab-trim" => ab_trim = true,
            "--lists" => lists_dir = args.next().map(PathBuf::from),
            other if compiled.is_none() => compiled = Some(PathBuf::from(other)),
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let Some(compiled) = compiled else {
        eprintln!("usage: i2_memory_profile <compiled-dir> [--lists <dir>] [--json]");
        std::process::exit(2);
    };

    let mut report = Report::default();
    report.fact("compiled dir", compiled.display().to_string());
    let mut artifact_bytes = Vec::new();
    for artifact in ["dns.bin", "engine.bin", "extras.txt"] {
        let path = compiled.join(artifact);
        let size = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        report.fact(format!("{artifact} bytes"), size.to_string());
        artifact_bytes.push((artifact, size));
    }
    report.fact("rss at start", format!("{:.3} MiB", mib(rss())));

    // ---- 1. Native.start: dns.bin ---------------------------------------------------------------
    let payload = report.step(
        "read dns.bin payload",
        false,
        "the bytes the loader hands on",
        || match zshield::compiled::Envelope::read_payload(
            &compiled.join("dns.bin"),
            zshield::compiled::Artifact::Dns,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                eprintln!("dns.bin: {error}");
                std::process::exit(1);
            }
        },
    );
    report.fact("dns payload bytes", payload.len().to_string());
    drop(payload);
    report.step(
        "dns payload released",
        false,
        "the loader drops it before decoding",
        || {},
    );

    let filter = report.step("dns.bin loaded", true, "the decoded DomainSets", || {
        zshield::compile::load_dns_filter(&compiled)
            .expect("load")
            .expect("dns.bin")
    });
    let stats = filter.stats();
    report.fact(
        "dns rules",
        format!(
            "{} block / {} exception / {} unsupported / {} network-only",
            stats.block_rules, stats.exception_rules, stats.unsupported, stats.network_only
        ),
    );

    // ---- 2. Native.start: engine.bin ------------------------------------------------------------
    // `load` is the production start path: it reads the payload, hashes it, deserializes, drops the
    // payload and trims. The retained delta compared to `engine.bin`'s size answers the card's
    // "does the load buffer survive into steady state" question — one copy, or two.
    let main_engine = report.step(
        "engine.bin loaded",
        true,
        "the flatbuffer the tunnel keeps",
        || {
            zshield::http::engine::load(&compiled)
                .expect("load")
                .expect("engine.bin")
        },
    );

    // ---- 3. Native.start: extras.txt ------------------------------------------------------------
    let extras = report.step(
        "extras.txt parsed",
        true,
        "popup/denyallow/removeparam/unhide/entity",
        || zshield::compile::load_extra_modifiers(&compiled),
    );
    // The 3.6 MiB above is one number for five families. Each family compiles its own
    // `adblock::Engine`s (one per `$popup` group, per `$removeparam` scope form, per entity rule), so
    // "the extras cost X" is only useful with the split: a fix can then aim at the family that holds
    // the bytes rather than at the text, which is 270 KiB.
    report.fact("extras rules", extras.len().to_string());
    report.fact("extras popup rules", extras.popup.len().to_string());
    report.fact("extras denyallow rules", extras.denyallow.len().to_string());
    report.fact(
        "extras global-unhide rules",
        extras.global_unhide.len().to_string(),
    );
    report.fact(
        "extras entity-domain rules",
        extras.entity_domain.len().to_string(),
    );
    report.fact("removeparam rules", extras.removeparam.len().to_string());
    report.fact(
        "removeparam scope forms",
        extras.removeparam.scope_form_count().to_string(),
    );
    report.fact(
        "removeparam cached scope engines at load",
        extras.removeparam.cached_engines().to_string(),
    );

    let after_load_live = live();
    let after_load_rss = rss();
    report.fact(
        "live heap after the start path",
        format!("{:.3} MiB", mib(after_load_live)),
    );
    report.fact(
        "rss after the start path",
        format!("{:.3} MiB", mib(after_load_rss)),
    );
    report.gap("after the start path", after_load_live, after_load_rss);

    // ---- 4. the compile the app runs on every launch -------------------------------------------
    // `FilterRepository.initialize` schedules this unconditionally. It is a transient — a whole
    // second engine plus a 40 MB serialization — but its freed pages are what the allocator may keep,
    // so both its peak and what survives the trim afterwards are recorded.
    let request = lists_dir
        .as_deref()
        .and_then(|dir| build_request(dir, &compiled));
    if let Some(request) = &request {
        let stats = report.step(
            "compile (every launch)",
            false,
            "a transient: a second whole engine",
            || zshield::compile::compile_request(request),
        );
        match stats {
            Ok(stats) => {
                report.fact("compiled dns rules", stats.dns_rules.to_string());
                report.fact("compiled network rules", stats.network_rules.to_string());
                report.fact("compiled engine bytes", stats.engine_bytes.to_string());
            }
            Err(error) => {
                eprintln!("compile failed: {error}");
                std::process::exit(1);
            }
        }
        // The production reload path: `http::engine::reload` builds the second engine while the
        // first is still installed, swaps it in, drops the payload and trims. The previous revision
        // of this example never called it, so its "after compile" figure was the state after
        // `compile_request` returned — not the state a running tunnel reaches.
        let recompiled = compiled.join("recompile-probe");
        report.fact("HTTP reload source", recompiled.display().to_string());
        let reload = report.step(
            "HTTP component reload",
            false,
            "a second engine built beside the live one",
            || {
                // SAFETY OF THE PROBE: the compiled artifacts on disk are the ones just produced above,
                // so this reload installs the same rules the compile wrote; the live engine's rules are
                // replaced with bytes that came from the same input.
                zshield::http::engine::reload(&main_engine, &recompiled)
            },
        );
        match reload {
            Ok(bytes) => report.fact("reload installed engine bytes", bytes.to_string()),
            Err(error) => {
                eprintln!("HTTP component reload failed: {error}");
                std::process::exit(1);
            }
        }
        report.fact("live heap after reload", format!("{:.3} MiB", mib(live())));
        report.fact("rss after reload", format!("{:.3} MiB", mib(rss())));
        report.gap("after reload", live(), rss());
    } else {
        report.fact("compile+reload", "skipped (no --lists directory)");
    }

    // ---- 5. what a started tunnel keeps, after everything is settled ----------------------------
    // The retained structures are still the ones loaded in step 1-3 (the reload above replaced the
    // engine's rules in place, it did not add a second copy). What is reported here is RSS minus the
    // counted live heap — see `gap`'s note for what that difference does and does not contain.
    let settled_live = live();
    report.fact("live heap settled", format!("{:.3} MiB", mib(settled_live)));
    report.fact("rss settled", format!("{:.3} MiB", mib(rss())));
    report.gap("settled", settled_live, rss());
    // Keep the loaded structures alive to this point: they are what "settled" means.
    report.fact(
        "engine flatbuffer vs artifact",
        format!(
            "artifact {} B; see the 'engine.bin loaded' retained row",
            artifact_bytes
                .iter()
                .find(|(name, _)| *name == "engine.bin")
                .map(|(_, size)| size.to_string())
                .unwrap_or_else(|| "?".to_string())
        ),
    );
    if ab_trim {
        observe_trims("rules-retained", &mut report);
        // Retain all three owners across the measurements, including in an optimized build.
        std::hint::black_box((&main_engine, &extras, &filter));
    }
    drop(main_engine);
    drop(extras);
    drop(filter);

    if ab_trim {
        observe_trims("rules-dropped-control", &mut report);
    }
    report.print(json);
    let _ = Path::new(".");
}

/// A `compile` request over every list body in `lists_dir`, written under `compiled`.
///
/// The contract is `docs/JNI.md`'s, and `compile_probe.rs` uses the same shape. The output directory
/// is a subdirectory so the probe never overwrites the artifacts it started from.
fn build_request(lists_dir: &Path, compiled: &Path) -> Option<String> {
    let mut entries = String::new();
    let mut any = false;
    let mut paths: Vec<_> = std::fs::read_dir(lists_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    paths.sort();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("txt") {
            continue;
        }
        let id = path.file_stem()?.to_string_lossy().to_string();
        if any {
            entries.push(',');
        }
        any = true;
        entries.push_str(&format!(
            "{{\"id\": {}, \"path\": {}}}",
            json_string(&id),
            json_string(&path.display().to_string())
        ));
    }
    if !any {
        return None;
    }
    let output = compiled.join("recompile-probe");
    Some(format!(
        "{{\"lists\": [{entries}], \"userRules\": \"\", \"allowlist\": [], \
         \"outputDir\": {}, \"debugRules\": false}}",
        json_string(&output.display().to_string())
    ))
}

/// Record kernel field names directly: Private_Dirty is not a synonym for anonymous memory.
/// The snapshot is host-only; missing procfs fields remain absent rather than becoming zero.
fn memory_snapshot() -> serde_json::Value {
    let counted_live_bytes = live();
    let fields = [
        "Rss",
        "Anonymous",
        "Pss_Anon",
        "Pss_File",
        "Pss_Shmem",
        "Private_Dirty",
        "Private_Clean",
        "Shared_Dirty",
        "Shared_Clean",
    ];
    let mut smaps_kib = serde_json::Map::new();
    if let Ok(raw) = std::fs::read_to_string("/proc/self/smaps_rollup") {
        for line in raw.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            if !fields.contains(&key) {
                continue;
            }
            let mut words = value.split_whitespace();
            if let (Some(number), Some("kB")) = (words.next(), words.next()) {
                if let Ok(kib) = number.parse::<u64>() {
                    smaps_kib.insert(key.into(), serde_json::json!(kib));
                }
            }
        }
    }
    serde_json::json!({"counted_live_bytes": counted_live_bytes, "smaps_kib": smaps_kib})
}

/// Observational checkpoints, not a model of JNI reload or evidence for a production fix.
fn observe_trims(phase: &str, report: &mut Report) {
    let before = memory_snapshot();
    zshield::mem::trim_allocator();
    let after_first = memory_snapshot();
    zshield::mem::trim_allocator();
    let after_second = memory_snapshot();
    // Store valid JSON inside the normal report instead of appending Rust Option debug syntax to
    // --json output. Allocate report strings only after all three observations have been collected.
    report.fact(
        format!("trim observation {phase}"),
        serde_json::json!({
            "phase": phase,
            "scope": "host component probe; not full JNI reload or Android PSS",
            "before": before,
            "after_first": after_first,
            "after_second": after_second,
        })
        .to_string(),
    );
}
