//! Host-side probe: compile a request JSON exactly as the app would, then measure the cold-start
//! load of the resulting artifacts. Used for the `docs/PERF.md` numbers without a device.
//!
//! Usage: `cargo run --release --example compile_probe -- <request.json>`

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: compile_probe <request.json>");
        std::process::exit(2);
    });
    let raw = std::fs::read_to_string(&path).expect("read request");
    let started = std::time::Instant::now();
    let stats = match zshield::compile::compile_request(&raw) {
        Ok(stats) => stats,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };
    println!("{}", serde_json::to_string_pretty(&stats).unwrap());
    println!("compile wall: {} ms", started.elapsed().as_millis());

    let dir = std::path::PathBuf::from(&stats.output_dir);
    let t = std::time::Instant::now();
    let filter = zshield::compile::load_dns_filter(&dir)
        .expect("load")
        .expect("artifact");
    println!(
        "dns.bin load: {} ms, {} block / {} exception",
        t.elapsed().as_millis(),
        filter.stats().block_rules,
        filter.stats().exception_rules
    );

    let raw_engine = std::fs::read(dir.join("engine.bin")).expect("engine.bin");
    let t = std::time::Instant::now();
    let envelope =
        zshield::compiled::Envelope::decode(zshield::compiled::Artifact::Engine, &raw_engine)
            .expect("envelope");
    let mut engine = adblock::Engine::default();
    engine.deserialize(&envelope.payload).expect("engine");
    println!(
        "engine.bin load: {} ms ({} B)",
        t.elapsed().as_millis(),
        raw_engine.len()
    );
}
