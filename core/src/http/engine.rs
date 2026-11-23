//! Runtime loading of the precompiled adblock engine (`engine.bin`).
//!
//! M1 compiled `engine.bin` and never loaded it. M2b loads it at start and on every rule reload, so
//! plaintext HTTP requests are matched against the full subscription set (task card §1).
//!
//! # Why a separate handle from the DNS filter
//!
//! `dns.bin` and `engine.bin` are produced by the same compile and are useless alone: a build with one
//! but not the other filters DNS *or* URLs, which from the user's side looks like filtering partly
//! stopped working. [`load`] therefore reports each artifact independently and lets the caller decide,
//! rather than failing both.
//!
//! # Why the engine is swapped behind an `RwLock`
//!
//! Same reason as [`crate::dns::engine::Engine::filter`]: a hot reload has to replace the rules while
//! requests are in flight. Each request takes one `Arc` snapshot before it decides, so it is judged by
//! exactly one rule set. See [`crate::http::decision::HttpFilter`].
//!
//! # Memory
//!
//! The engine lives in a flatbuffer that is loaded as one allocation; `docs/PERF.md` §11 records the
//! measured cost. [`crate::http::decision::HttpFilter`] keeps exactly one engine alive at a time, so a
//! reload transiently holds two (old + new) and then drops the old.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::compiled::{self, Artifact, Envelope};
use crate::http::decision::HttpFilter;

/// Wall-clock duration of the most recent successful [`load`], in microseconds.
///
/// Read by `start`/`reload` to log the cost (`docs/PERF.md` records it). Process-global for the same
/// reason as [`crate::compile::LAST_LOAD_MICROS`]: the only consumer is a log line, and the loader's
/// signature should not carry it.
pub static LAST_ENGINE_LOAD_MICROS: AtomicU64 = AtomicU64::new(0);

/// Size of the engine artifact last loaded, in bytes.
pub static LAST_ENGINE_BYTES: AtomicU64 = AtomicU64::new(0);

/// Load `engine.bin` from `dir`, with the built-in `$redirect` resources registered.
///
/// Returns `Ok(None)` when the directory holds no artifact (a first run, or a DNS-only rule set) and
/// `Err` only when a file exists but cannot be used — the caller then keeps whatever rules it has and
/// reports the reason, exactly as the DNS artifact loader does.
pub fn load(dir: &Path) -> Result<Option<HttpFilter>, String> {
    Ok(load_with_identity(dir)?.map(|(filter, _)| filter))
}

/// [`load`], plus the content identity of the `engine.bin` payload that was deserialized.
///
/// `None` means "no artifact in this directory"; an `Err` means a file exists and cannot be used, in
/// which case nothing was installed and there is no identity to report — a failed load must never be
/// able to produce a successful generation. The hash is taken from the payload buffer the loader
/// already holds, immediately before `deserialize` consumes it, so it describes the bytes that became
/// the engine and costs no second read of a 41 MB file.
pub fn load_with_identity(
    dir: &Path,
) -> Result<Option<(HttpFilter, crate::compiled::PayloadIdentity)>, String> {
    let path = dir.join(compiled::ENGINE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let started = Instant::now();
    // `read_payload` strips the envelope header in place, so the 41 MB artifact is resident once
    // instead of twice (`Envelope::read` = file buffer + payload copy). `docs/PERF.md` §14 has the
    // measured cold-start peak.
    let payload = Envelope::read_payload(&path, Artifact::Engine)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let bytes = payload.len() as u64;
    let identity = crate::compiled::PayloadIdentity::of_payload(&payload);
    let mut engine = adblock::Engine::default();
    engine
        .deserialize(&payload)
        .map_err(|err| format!("{}: cannot deserialize the engine: {err}", path.display()))?;
    let filter = HttpFilter::new(engine);
    // `deserialize` copies the payload into the flatbuffer the engine reads from; the payload itself
    // is dead here, and it is the largest transient allocation the start path makes (41 MB). Return
    // its pages before the tunnel starts serving.
    let rss_before_trim = crate::mem::rss_kib();
    drop(payload);
    crate::mem::trim_allocator();
    crate::mem::log_rss_delta("engine payload released", rss_before_trim, crate::mem::rss_kib());
    LAST_ENGINE_BYTES.store(bytes, Ordering::Relaxed);
    LAST_ENGINE_LOAD_MICROS.store(
        started.elapsed().as_micros() as u64,
        Ordering::Relaxed,
    );
    Ok(Some((filter, identity)))
}

/// Replace the rules of a live engine handle.
///
/// On any failure the old rules stay in force: a reload that half-applies would leave the tunnel
/// filtering with a rule set nobody asked for.
pub fn reload(filter: &HttpFilter, dir: &Path) -> Result<u64, String> {
    Ok(reload_with_identity(filter, dir)?.bytes)
}

/// [`reload`], plus the identity of the payload that replaced the live engine's rules.
///
/// The identity is only produced after `filter.replace` has installed the new engine: a reload that
/// could not deserialize the artifact returns `Err` and leaves the previous rules — and the previous
/// identity — in force, so no failed swap can look like a successful generation.
pub fn reload_with_identity(
    filter: &HttpFilter,
    dir: &Path,
) -> Result<crate::compiled::PayloadIdentity, String> {
    let path = dir.join(compiled::ENGINE_FILE);
    if !path.exists() {
        return Err(format!("no {} in {}", compiled::ENGINE_FILE, dir.display()));
    }
    let started = Instant::now();
    let payload = Envelope::read_payload(&path, Artifact::Engine)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let identity = crate::compiled::PayloadIdentity::of_payload(&payload);
    let bytes = payload.len() as u64;
    let mut engine = adblock::Engine::default();
    engine
        .deserialize(&payload)
        .map_err(|err| format!("{}: cannot deserialize the engine: {err}", path.display()))?;
    filter.replace(engine);
    drop(payload);
    crate::mem::trim_allocator();
    LAST_ENGINE_BYTES.store(bytes, Ordering::Relaxed);
    LAST_ENGINE_LOAD_MICROS.store(
        started.elapsed().as_micros() as u64,
        Ordering::Relaxed,
    );
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::head::{HttpRequest, Version};
    use crate::http::resource::RequestKind;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "zshield-engine-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    /// Compile `rules` into `dir/engine.bin` the same way a real compile would.
    fn write_engine(dir: &TempDir, rules: &str) {
        let list = dir.0.join("list.txt");
        std::fs::write(&list, rules).expect("write list");
        let request = serde_json::json!({
            "lists": [{"id": "test", "path": list.to_string_lossy()}],
            "userRules": "",
            "allowlist": [],
            "outputDir": dir.0.to_string_lossy(),
        });
        let stats = crate::compile::compile_request(&request.to_string()).expect("compile");
        assert!(stats.engine_bytes > 0);
    }

    fn request(url: &str) -> HttpRequest {
        let parsed = adblock::url_parser::parse_url(url).expect("url");
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: Version::Http11,
            url: parsed.url.clone(),
            host: parsed.hostname().to_string(),
            hostname: parsed.hostname().to_string(),
            referer: Some("http://site.example/".to_string()),
            fetch_dest: Some("script".to_string()),
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

    #[test]
    fn a_compiled_engine_is_loaded_and_blocks() {
        let dir = TempDir::new("load");
        write_engine(&dir, "||ads.example.com^$script\n");
        let filter = load(&dir.0).expect("load").expect("artifact present");
        assert!(
            filter.decide(&request("http://ads.example.com/x.js")).block,
            "the engine must block what the list blocks"
        );
        assert!(!filter.decide(&request("http://clean.example.com/x.js")).block);
        assert!(LAST_ENGINE_BYTES.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn a_directory_without_an_artifact_is_not_an_error() {
        let dir = TempDir::new("empty");
        assert!(load(&dir.0).expect("no error").is_none());
    }

    #[test]
    fn a_corrupt_artifact_is_an_error_not_a_panic() {
        let dir = TempDir::new("corrupt");
        std::fs::write(
            dir.0.join(compiled::ENGINE_FILE),
            b"definitely not an artifact",
        )
        .expect("write");
        let err = load(&dir.0).expect_err("must fail");
        assert!(!err.is_empty());
    }

    #[test]
    fn a_payload_that_is_not_an_engine_is_rejected() {
        // A valid envelope around a payload the engine cannot deserialize: caught by the loader, so
        // a half-written or foreign artifact degrades to "recompile" instead of a broken tunnel.
        let dir = TempDir::new("bad-payload");
        let envelope = Envelope::new(Artifact::Engine, b"garbage payload".to_vec());
        envelope
            .write_atomic(&dir.0.join(compiled::ENGINE_FILE))
            .expect("write");
        let err = load(&dir.0).expect_err("must fail");
        assert!(err.contains("deserialize"), "{err}");
    }

    #[test]
    fn reload_replaces_the_rules_of_a_live_handle() {
        let dir = TempDir::new("reload");
        write_engine(&dir, "||old.example.com^$script\n");
        let filter = load(&dir.0).expect("load").expect("artifact");
        assert!(filter.decide(&request("http://old.example.com/x.js")).block);

        write_engine(&dir, "||new.example.com^$script\n");
        let bytes = reload(&filter, &dir.0).expect("reload");
        assert!(bytes > 0);
        assert!(filter.decide(&request("http://new.example.com/x.js")).block);
        assert!(
            !filter.decide(&request("http://old.example.com/x.js")).block,
            "the previous rules must be gone"
        );
    }

    #[test]
    fn a_failed_reload_keeps_the_old_rules() {
        let dir = TempDir::new("reload-fail");
        write_engine(&dir, "||keep.example.com^$script\n");
        let filter = load(&dir.0).expect("load").expect("artifact");
        assert!(filter.decide(&request("http://keep.example.com/x.js")).block);

        // Corrupt artifact, then a reload.
        std::fs::write(dir.0.join(compiled::ENGINE_FILE), b"broken").expect("write");
        assert!(reload(&filter, &dir.0).is_err());
        assert!(
            filter.decide(&request("http://keep.example.com/x.js")).block,
            "a failed reload must leave the old rules in force"
        );

        // Missing artifact.
        std::fs::remove_file(dir.0.join(compiled::ENGINE_FILE)).expect("remove");
        let err = reload(&filter, &dir.0).expect_err("must fail");
        assert!(err.contains("no engine.bin"), "{err}");
        assert!(filter.decide(&request("http://keep.example.com/x.js")).block);
    }

    #[test]
    fn the_loaded_engine_carries_the_redirect_resources() {
        // The resources are registered by the loader, not by the list, so a `$redirect` rule works
        // on a freshly started tunnel.
        let dir = TempDir::new("redirect");
        write_engine(&dir, "||ads.example.com/x.js$script,redirect=noopjs\n");
        let filter = load(&dir.0).expect("load").expect("artifact");
        let decision = filter.decide(&request("http://ads.example.com/x.js"));
        assert!(decision.block);
        assert!(
            decision.serves_redirect(),
            "the built-in noopjs resource must be available after a load"
        );
        let _ = RequestKind::Script;
    }
}
