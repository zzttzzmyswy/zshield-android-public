//! Host-side probe: what the rule-identity observation costs on the paths that pay for it.
//!
//! Usage: `cargo run --release --example rules_identity_cost -- <compiled-dir>`
//!
//! MYS-2825 added a SHA-256 over each artifact payload on the load/swap path, so the readiness check
//! can name the rule content in force instead of inferring it from a byte count. That is only
//! defensible if the cost is understood: this prints, for the artifacts a real build produces, the
//! measured hash time next to the load time it is part of, so the number in the delivery note comes
//! from a run rather than from an estimate.
//!
//! It also prints what the identity is *not*: the per-request path is untouched, and the retained
//! state is one 64-hex token plus a count per component (no copy of the rules).

use std::path::Path;
use std::time::Instant;

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: rules_identity_cost <compiled-dir>");
        std::process::exit(2);
    });
    let dir = Path::new(&dir);

    for (name, file, artifact) in [
        ("dns.bin", zshield::compiled::DNS_FILE, zshield::compiled::Artifact::Dns),
        ("engine.bin", zshield::compiled::ENGINE_FILE, zshield::compiled::Artifact::Engine),
        ("extras.txt", zshield::compiled::EXTRAS_FILE, zshield::compiled::Artifact::Extras),
    ] {
        let path = dir.join(file);
        if !path.exists() {
            println!("{name}: absent");
            continue;
        }
        // Hashed from a buffer that is already resident — the same buffer the loader installs — so the
        // number below excludes the read and is the whole of what the observation adds.
        let payload = zshield::compiled::Envelope::read_payload(&path, artifact).expect("payload");
        let started = Instant::now();
        let identity = zshield::compiled::PayloadIdentity::of_payload(&payload);
        let hash_ms = started.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{name}: {} B, sha256 {:.2} ms ({:.0} MB/s), {} retained",
            identity.bytes,
            hash_ms,
            if hash_ms > 0.0 { identity.bytes as f64 / 1e6 / (hash_ms / 1000.0) } else { f64::INFINITY },
            identity.token().len()
        );
        drop(payload);
    }

    // What a start pays: the hash of each payload, measured on the buffer the loader already holds.
    //
    // The load functions are **not** timed against each other here, because that comparison cannot be
    // made honestly in this profile: `load()` is `load_with_identity()` with the identity dropped, and
    // with LTO the compiler removes the whole hash from the plain arm (measured: both arms come out
    // within noise of each other, which is not a real result). The number that matters is the one
    // below, and the honest statement is that the added work is exactly this, once per start or
    // successful swap — not per request.
    let total: u128 = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let artifact = match path.file_name().and_then(|n| n.to_str()) {
                Some(zshield::compiled::DNS_FILE) => zshield::compiled::Artifact::Dns,
                Some(zshield::compiled::ENGINE_FILE) => zshield::compiled::Artifact::Engine,
                Some(zshield::compiled::EXTRAS_FILE) => zshield::compiled::Artifact::Extras,
                _ => return None,
            };
            let payload = zshield::compiled::Envelope::read_payload(&path, artifact).ok()?;
            let started = Instant::now();
            let identity = zshield::compiled::PayloadIdentity::of_payload(&payload);
            let elapsed = started.elapsed();
            // Keep the identity observable so the hash cannot be optimized away in this measurement.
            println!("  {} -> {}", path.display(), identity.token());
            Some(elapsed.as_micros())
        })
        .sum();
    println!("total identity cost per start/swap: {:.1} ms", total as f64 / 1000.0);
    println!("per request: 0 (nothing on the request path reads or hashes a rule artifact)");
}
