//! Host-side heap accounting for the whole core lifecycle (M4b).
//!
//! Usage: `cargo run --release --example mem_probe -- <request.json> <compile-dir>`
//!
//! Every number is measured, not estimated: a counting global allocator reports live/peak bytes and
//! `/proc/self/statm` reports what the process actually keeps. `docs/PERF.md` §14 quotes these.

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::Path;
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

fn mib(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn live() -> f64 {
    mib(LIVE.load(Ordering::Relaxed))
}

fn peak() -> f64 {
    mib(PEAK.load(Ordering::Relaxed))
}

fn reset_peak() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
}

fn rss() -> f64 {
    let raw = std::fs::read_to_string("/proc/self/statm").expect("statm");
    let pages: u64 = raw
        .split_whitespace()
        .nth(1)
        .expect("rss field")
        .parse()
        .expect("pages");
    pages as f64 * 4096.0 / (1024.0 * 1024.0)
}

fn report(label: &str, live_before: f64, rss_before: f64) {
    println!(
        "{label:<44} live {:>7.1} (heap {:>+6.1})  rss {:>7.1} ({:>+6.1})  peak {:.1}",
        live(),
        live() - live_before,
        rss(),
        rss() - rss_before,
        peak()
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let request_path = args.next().unwrap_or_else(|| {
        eprintln!("usage: mem_probe <request.json> <compile-dir>");
        std::process::exit(2);
    });
    let dir = std::path::PathBuf::from(args.next().unwrap_or_default());
    let dir = dir.as_path();

    println!("start                        live {:.1}  rss {:.1}", live(), rss());

    // ---- 1. the tunnel's start path: dns.bin + engine.bin -------------------------------------
    let (l, r) = (live(), rss());
    let filter = zshield::compile::load_dns_filter(dir).unwrap().expect("dns.bin");
    report("dns.bin loaded", l, r);
    println!(
        "    {} block / {} exception",
        filter.stats().block_rules,
        filter.stats().exception_rules
    );

    reset_peak();
    let (l, r) = (live(), rss());
    let http = zshield::http::engine::load(dir).unwrap().expect("engine.bin");
    report("engine.bin loaded", l, r);
    println!("    engine load peak heap: {:.1} MiB", peak());

    reset_peak();
    let (l, r) = (live(), rss());
    println!("\n-- steady state after start --");
    report("steady state", l, r);

    // ---- 2. the compile the app runs on every start ------------------------------------------
    let raw = std::fs::read_to_string(&request_path).expect("request");
    reset_peak();
    let (l, r) = (live(), rss());
    let stats = zshield::compile::compile_request(&raw).expect("compile");
    report("compile_request", l, r);
    println!(
        "    compile peak heap: {:.1} MiB ({} dns rules, {} network)",
        peak(),
        stats.dns_rules,
        stats.network_rules
    );

    reset_peak();
    let (l, r) = (live(), rss());
    println!("\n-- after compile --");
    report("steady state", l, r);

    drop(http);
    drop(filter);
    println!("\nafter dropping both RuleSets: live {:.1}  rss {:.1}", live(), rss());
    let _ = Path::new(".");
}
