//! Where does the idle native heap go? (M4b measurement helper.)
//!
//! Usage: `cargo run --release --example heap_probe -- <compile-dir>`
//!
//! Everything on the tunnel's steady-state path is built here and measured with a counting
//! allocator, one structure at a time, so `docs/PERF.md` §14 can attribute the device's native heap
//! without a profiler.

use std::alloc::{GlobalAlloc, Layout, System};
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

fn step(label: &str, before: f64) {
    println!(
        "{label:<46} live {:>7.2} MiB ({:>+7.2})  step peak {:.2}",
        live(),
        live() - before,
        peak()
    );
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: heap_probe <compile-dir>");
        std::process::exit(2);
    });
    let dir = std::path::Path::new(&dir);

    println!("=== cold start (what a VPN start allocates) ===");
    let mut base = live();
    reset_peak();
    let filter = zshield::compile::load_dns_filter(dir).unwrap().expect("dns.bin");
    step("dns filter (compiled DomainSets)", base);
    base = live();
    reset_peak();
    let http = zshield::http::engine::load(dir).unwrap().expect("engine.bin");
    step("adblock engine (flatbuffer)", base);
    println!("    engine step peak: {:.2} MiB (payload + flatbuffer copy)", peak());
    println!("idle total: {:.2} MiB\n", live());

    println!("=== per-connection cost (MAX_CONNECTIONS = {}) ===", 512);
    base = live();
    reset_peak();
    // One forwarded connection: two ring buffers (client→stack, stack→forwarder) plus one smoltcp
    // socket pair with the same capacity, plus a copy buffer per direction.
    let buffers = zshield::tun::probe_one_connection();
    step("one connection (4 x 64 KiB + 2 x 32 KiB)", base);
    println!(
        "    x512 worst case: {:.1} MiB — but only live connections are allocated\n",
        live() - base
    );
    drop(buffers);

    println!("=== the DNS cache (4096 entries, empty at idle) ===");
    base = live();
    reset_peak();
    let cache = zshield::dns::cache::Cache::new(4096, 3600);
    step("empty cache", base);
    drop(cache);

    drop(http);
    drop(filter);
    println!("\nfinal live: {:.2} MiB", live());
}
