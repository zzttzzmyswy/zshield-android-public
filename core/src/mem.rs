//! Resident-memory accounting and the one allocator lever (M4b).
//!
//! `docs/PERF.md` needs to say *which* structure costs *how much* on the device, not only what
//! `dumpsys meminfo` totals. `dumpsys meminfo` cannot break the native heap down per structure, so
//! the core reports its own resident set size (RSS) at the points in its lifecycle where a
//! structure is built, replaced or released, and `docs/PERF.md` §14 subtracts consecutive lines.
//!
//! Reading `/proc/self/statm` costs a few microseconds and needs no permission — the process reads
//! its own entry. It stays in the shipped build because it is the only way a user filing a memory
//! report can show where the memory went.

/// Resident set size of this process, in KiB.
///
/// `None` where `/proc` is unavailable (a sandbox without procfs). Callers treat "no measurement"
/// as "log nothing" rather than as an error.
pub fn rss_kib() -> Option<u64> {
    let raw = std::fs::read_to_string("/proc/self/statm").ok()?;
    // statm: size resident shared text lib data dt (all in pages)
    let pages: u64 = raw.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(page_size_kib()))
}

/// The kernel's page size in KiB.
///
/// Android runs 4 KiB and 16 KiB page kernels; assuming 4 would scale every number by 4× on the
/// latter. `libc`'s `getpagesize` is the authority, and it is not reachable through `std`.
fn page_size_kib() -> u64 {
    extern "C" {
        fn getpagesize() -> core::ffi::c_int;
    }
    // SAFETY: `getpagesize` takes no arguments, has no preconditions, and returns a positive value.
    let size = unsafe { getpagesize() };
    if size > 0 {
        (size as u64) / 1024
    } else {
        4
    }
}

/// Ask the allocator to hand freed pages back to the kernel.
///
/// The allocator keeps freed memory in its arena so the next allocation does not fault it back in —
/// right for a steady-state workload, wrong for this process, whose peak is a ~200 MiB rule compile
/// and a 40 MB engine deserialization followed by a ~50 MiB idle state. Without this the idle native
/// heap carries those freed pages indefinitely; `docs/PERF.md` §14 measures both sides.
///
/// **Which call.** bionic does not implement `malloc_trim`; it implements `mallopt(M_PURGE)`
/// (`malloc.h`, API 28+, this app's `minSdk`). The NDK header is the authority here — an extern
/// declaration of `malloc_trim` would fail to link, and on glibc (the host build) `M_PURGE` does not
/// exist, so the two platforms need different calls. Both are declared directly rather than looked
/// up with `dlsym`: a missing symbol would fail the whole `.so` at load time, and both symbols exist
/// on every platform this crate is built for.
///
/// The return value is ignored here: it reports whether the option was accepted, not how many
/// pages were released. The stronger lifecycle purge below checks it to select a fallback.
pub fn trim_allocator() {
    #[cfg(target_os = "android")]
    {
        // `M_PURGE` from bionic's `malloc.h`. Written out rather than included so the crate needs no
        // build script; the value is ABI, not preference.
        const M_PURGE: core::ffi::c_int = -101;
        extern "C" {
            fn mallopt(option: core::ffi::c_int, value: core::ffi::c_int) -> core::ffi::c_int;
        }
        // SAFETY: `mallopt` takes two ints and has no preconditions; it is safe from any thread.
        unsafe {
            let _ = mallopt(M_PURGE, 0);
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        extern "C" {
            fn malloc_trim(pad: usize) -> core::ffi::c_int;
        }
        // SAFETY: `malloc_trim` is a glibc entry point with no preconditions; pad 0 means "release
        // everything you can". Safe from any thread at any time.
        unsafe {
            let _ = malloc_trim(0);
        }
    }
}

/// Return unused pages, including the small size classes a normal Android purge may skip.
/// Used at lifecycle boundaries (rule build/load or UI hidden),
/// never per request or on a timer. M_PURGE_ALL is supported since Android 14 (API 34); older
/// allocators reject the option with 0 and use the existing API-28 purge instead.
pub fn trim_unused_memory() {
    #[cfg(target_os = "android")]
    {
        const M_PURGE_ALL: core::ffi::c_int = -104;
        extern "C" {
            fn mallopt(option: core::ffi::c_int, value: core::ffi::c_int) -> core::ffi::c_int;
        }
        // SAFETY: mallopt takes two integers and has no preconditions, including on unsupported
        // options. bionic malloc.h documents 1 for success and 0 for an unsupported option.
        if unsafe { mallopt(M_PURGE_ALL, 0) } == 1 {
            return;
        }
    }
    trim_allocator();
}

/// Log one line with the current RSS, so `adb logcat` shows the cost of each lifecycle step.
///
/// Every line carries the same `rss:` prefix, so `adb logcat | grep "ZShieldCore.*rss:"` prints the
/// whole sequence and `docs/PERF.md` §14 quotes exactly those lines.
pub fn log_rss(stage: &str) {
    match rss_kib() {
        Some(kib) => crate::log_msg("info", &format!("rss: {stage} = {kib} KiB")),
        None => crate::log_msg("debug", &format!("rss: {stage} = unmeasurable")),
    }
}

/// The same line, phrased as the cost of one step (`docs/PERF.md` §14's delta column).
pub fn log_rss_delta(stage: &str, before: Option<u64>, after: Option<u64>) {
    if let (Some(before), Some(after)) = (before, after) {
        let delta = after as i64 - before as i64;
        crate::log_msg(
            "info",
            &format!("rss: {stage} = {delta:+} KiB ({before} -> {after} KiB)"),
        );
    }
}

/// Format a KiB count the way the doc tables print it.
pub fn kib_to_mib(kib: u64) -> f64 {
    kib as f64 / 1024.0
}

#[cfg(test)]
mod tests {
    #[test]
    fn rss_is_readable_and_plausible() {
        // On any Linux host this must land between a few hundred KiB and 64 GiB. A unit slip
        // (bytes vs KiB vs pages) would land far outside that window.
        let rss = super::rss_kib().expect("procfs is available in the test environment");
        assert!(rss > 256, "rss {rss} KiB is implausibly small");
        assert!(rss < 64 * 1024 * 1024, "rss {rss} KiB is implausibly large");
    }

    #[test]
    fn the_page_size_is_a_power_of_two_and_at_least_4_kib() {
        let size = super::page_size_kib();
        assert!(size >= 4, "page size {size} KiB is too small");
        assert!(size.is_power_of_two(), "page size {size} KiB is not a power of two");
    }

    #[test]
    fn trimming_the_allocator_does_not_panic() {
        // Allocate enough to reach the mmap threshold, free it, then trim: the point is that the
        // call is safe at any time, including with live allocations on the heap.
        let keep: Vec<u8> = vec![7u8; 4 << 20];
        let big: Vec<u8> = vec![1u8; 32 << 20];
        drop(big);
        super::trim_allocator();
        super::trim_unused_memory();
        assert!(keep.iter().all(|byte| *byte == 7));
    }

    #[test]
    fn logging_a_stage_does_not_panic() {
        super::log_rss("test");
        super::log_rss_delta("test delta", Some(100), Some(200));
        super::log_rss_delta("test delta", None, None);
    }
}
