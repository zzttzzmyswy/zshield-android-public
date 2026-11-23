//! Rule compilation: turn enabled filter lists plus the user's own rules into the two serialized
//! artifacts the tunnel loads (`dns.bin`, `engine.bin`).
//!
//! Pipeline (see `docs/JNI.md` §"compile"):
//!
//! 1. read every list file, in the order the request gives them;
//! 2. classify each line ([`classify_line`]) and feed the DNS-eligible ones into a [`Filter`];
//! 3. feed the *whole* text of every list plus the user rules into adblock-rust's `FilterSet`
//!    (it has its own, far more complete parser, and it needs the full text to resolve `$badfilter`
//!    and to optimise);
//! 4. serialize both products with the versioned envelope from [`crate::compiled`];
//! 5. report per-list and total statistics.
//!
//! **DNS-layer rule selection** is the part that must not be sloppy. A subscription rule like
//! `||ads.example^$third-party` or `||cdn.example/ads.js` only forbids *part* of a domain's
//! traffic. Turning it into a whole-domain DNS block would break sites in a way the rule author
//! never intended, so those lines go to the adblock engine only and are counted as `networkRules`
//! (task card §4). AdGuard's own DNS filter behaves the same way.

use std::path::Path;
use std::time::Instant;

use adblock::lists::{FilterSet, ParseOptions};
use serde::{Deserialize, Serialize};

use crate::compiled::{self, Artifact, Envelope};
use crate::dns::filter::{Filter, FilterBuilder, ListCounts};

/// One filter list to compile, as named by the Kotlin repository.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileList {
    /// Stable list id (`catalog.json` id, or a generated id for user-added lists).
    pub id: String,
    /// Absolute path of the downloaded list text.
    pub path: String,
}

/// The `compile(requestJson)` request (see `docs/JNI.md`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompileRequest {
    /// Lists to compile, in load order.
    pub lists: Vec<CompileList>,
    /// The user's custom rules, as one text blob.
    pub user_rules: String,
    /// Domains the user always wants resolved, regardless of any list.
    pub allowlist: Vec<String>,
    /// Directory that receives `dns.bin` and `engine.bin`. Created if missing.
    pub output_dir: String,
    /// Record the original text of every network rule in `engine.bin` (M2b).
    ///
    /// Off by default because it is expensive: on the default list set it roughly doubles both the
    /// artifact (39.5 MB → 74.6 MB) and the engine's resident memory (39.5 MB → 75 MB), which is most
    /// of the `docs/PERF.md` §1 PSS budget. Without it `FilterDecision::matched_rule` is `None` and
    /// the request log cannot say which rule fired — a diagnostic feature, so the caller decides.
    pub debug_rules: bool,
}

/// Per-list counters reported to the UI ("规则统计", `docs/DESIGN.md` §1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListStats {
    pub id: String,
    /// Total lines in the file, comments included.
    pub lines: u64,
    /// Domains that ended up in the DNS filter (blocks and exceptions).
    pub dns_rules: u64,
    /// Network rules handed to the adblock engine (path patterns, modifiers, ...).
    pub network_rules: u64,
    /// Element hiding / scriptlet rules (a subset of `networkRules`).
    pub cosmetic_rules: u64,
    /// Lines that could not be parsed at all (the UI's "不支持").
    pub unsupported: u64,
    /// Bytes read from disk.
    pub bytes: u64,
}

/// Totals for the whole compile, returned as the `compile` result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompileStats {
    pub lists: Vec<ListStats>,
    pub total_lines: u64,
    pub dns_rules: u64,
    pub network_rules: u64,
    pub cosmetic_rules: u64,
    pub unsupported: u64,
    /// Valid rules that belong to the adblock engine only (a subset of `networkRules`).
    pub network_only: u64,
    /// Rules actually kept in the DNS filter (blocks + exceptions, after `$badfilter`).
    pub dns_block_rules: u64,
    pub dns_exception_rules: u64,
    /// User allowlist entries.
    pub allowlist: u64,
    /// Wall-clock duration of the whole compile.
    pub elapsed_ms: u64,
    /// Size of `dns.bin` on disk.
    pub dns_bytes: u64,
    /// Size of `engine.bin` on disk.
    pub engine_bytes: u64,
    /// Size of `extras.txt` on disk (`$popup`, `$denyallow`, `$removeparam=/regex/` rules).
    pub extras_bytes: u64,
    /// Output directory the artifacts were written to.
    pub output_dir: String,
}

/// Compile and write the artifacts. Returns the statistics as the JSON document `compile` returns.
pub fn compile_request(request_json: &str) -> Result<CompileStats, String> {
    let request: CompileRequest = serde_json::from_str(request_json)
        .map_err(|e| format!("invalid compile request JSON: {e}"))?;
    compile(&request)
}

/// Compile according to an already-parsed request.
pub fn compile(request: &CompileRequest) -> Result<CompileStats, String> {
    if request.output_dir.trim().is_empty() {
        return Err("compile: outputDir is required".to_string());
    }
    let started = Instant::now();
    let output_dir = Path::new(&request.output_dir);
    std::fs::create_dir_all(output_dir)
        .map_err(|e| format!("compile: cannot create {}: {e}", output_dir.display()))?;

    let mut stats = CompileStats {
        output_dir: request.output_dir.clone(),
        ..CompileStats::default()
    };
    // Stage timings are logged so a slow compile on a device can be attributed without a profiler
    // (`docs/PERF.md` records the device numbers). Cheap: a couple of `Instant::elapsed` calls.
    let mut stage = Instant::now();
    let mark = |label: &str, stage: &mut Instant| {
        crate::log_msg(
            "info",
            &format!("compile stage {label}: {} ms", stage.elapsed().as_millis()),
        );
        *stage = Instant::now();
    };

    let allowlist: Vec<String> = request.allowlist.clone();
    // Record content identities, never rule text or paths. This binds device measurements to
    // the inputs actually compiled without exporting the app's private filter files.
    crate::log_msg(
        "info",
        &format!(
            "compile inputs: lists={} user_rules={} allowlist={} debug_rules={}",
            request.lists.len(),
            compiled::PayloadIdentity::of_payload(request.user_rules.as_bytes()).token(),
            compiled::PayloadIdentity::of_payload(
                &serde_json::to_vec(&request.allowlist).expect("string list serializes")
            )
            .token(),
            request.debug_rules,
        ),
    );
    let dns_path = output_dir.join(compiled::DNS_FILE);
    let engine_path = output_dir.join(compiled::ENGINE_FILE);

    // The two products are independent: the DNS side needs each line classified, the engine needs
    // the raw text. Both need the same files read, so each pipeline owns its own read (the second
    // read is served from the page cache by then) and the whole compile costs the slower pipeline
    // instead of the sum. On the Pixel 5 that turned ~4.3 s into ~3.3 s, which is what makes a rule
    // change land inside the 5 s the acceptance criterion allows.
    //
    // `FilterSet` is `Send` but not `Sync`, which is why it is *moved* into its thread rather than
    // shared, and `FilterBuilder` likewise.
    crate::mem::log_rss("compile start");
    let (dns_result, engine_result) = std::thread::scope(|scope| {
        let lists = &request.lists;
        let user_rules = &request.user_rules;
        let dns_handle = scope.spawn(move || -> Result<(Filter, u64, Vec<ListCounts>), String> {
            let mut builder = FilterBuilder::new();
            let mut counts = Vec::with_capacity(lists.len() + 1);
            for list in lists {
                let text = read_list(&list.id, &list.path)?;
                counts.push(builder.add_text(&text));
            }
            if !user_rules.trim().is_empty() {
                counts.push(builder.add_text(user_rules));
            }
            builder.resolve_badfilters();
            let mut filter = Filter::new();
            builder.apply_to(&mut filter);
            filter.add_allowlist(allowlist.iter().map(String::as_str));
            // `apply_to` consumed the builder, and the per-list text is dead by now: release the
            // freed pages before the artifact is written so the DNS side does not hold them while
            // the engine side is still running.
            crate::mem::trim_allocator();
            let bytes = Envelope::new(Artifact::Dns, filter.encode_payload())
                .write_atomic(&dns_path)
                .map(|bytes| bytes as u64)
                .map_err(|e| format!("compile: cannot write {}: {e}", dns_path.display()))?;
            Ok((filter, bytes, counts))
        });
        let engine_handle = scope.spawn(move || -> Result<u64, String> {
            let mut filter_set = FilterSet::new(request.debug_rules);
            for list in lists {
                let text = read_list(&list.id, &list.path)?;
                filter_set.add_filter_list(text, ParseOptions::default());
            }
            if !user_rules.trim().is_empty() {
                filter_set.add_filter_list(user_rules.clone(), ParseOptions::default());
            }
            let engine = adblock::Engine::new_with_filter_set(filter_set);
            // `Engine::serialize` returns the whole 41 MB artifact while the engine that produced it
            // is still alive, so the peak necessarily holds both. Freeing the engine first lets the
            // allocator return its pages before the write; the payload is already owned.
            let payload = engine.serialize();
            drop(engine);
            crate::mem::trim_allocator();
            let bytes = Envelope::new(Artifact::Engine, payload)
                .write_atomic(&engine_path)
                .map(|bytes| bytes as u64)
                .map_err(|e| format!("compile: cannot write {}: {e}", engine_path.display()))?;
            Ok(bytes)
        });
        // Both are joined before either result is unwrapped, so a failure on one side waits for the
        // other and cannot leave half an artifact pair behind.
        let dns = dns_handle
            .join()
            .unwrap_or_else(|_| Err("compile: dns thread panicked".to_string()));
        let engine = engine_handle
            .join()
            .unwrap_or_else(|_| Err("compile: engine thread panicked".to_string()));
        (dns, engine)
    });

    let (filter, dns_bytes, mut counts) = dns_result?;
    stats.engine_bytes = engine_result?;

    // Per-list statistics line up with `request.lists` order, then the optional user-rules entry.
    if counts.len() > request.lists.len() {
        let user_counts = counts.pop().expect("checked length");
        accumulate(
            &mut stats,
            "user-rules".to_string(),
            user_counts,
            request.user_rules.len() as u64,
        );
    }
    for (list, list_counts) in request.lists.iter().zip(counts) {
        let bytes = std::fs::metadata(&list.path).map(|m| m.len()).unwrap_or(0);
        // Per-list numbers are logged so the rule counts a build produces can be read off a device
        // (`adb logcat | grep "list stats"`) without a debug build or a JSON dump.
        crate::log_msg(
            "info",
            &format!(
                "list stats {}: {} lines, {} dns, {} network ({} cosmetic), {} unsupported, {} B",
                list.id,
                list_counts.lines,
                list_counts.dns_rules,
                list_counts.network_rules,
                list_counts.cosmetic_rules,
                list_counts.unsupported,
                bytes
            ),
        );
        accumulate(&mut stats, list.id.clone(), list_counts, bytes);
    }
    // Keep the reported order stable: sources in request order, user rules last.
    stats.lists.sort_by_key(|entry| {
        if entry.id == "user-rules" {
            usize::MAX
        } else {
            request
                .lists
                .iter()
                .position(|list| list.id == entry.id)
                .unwrap_or(usize::MAX - 1)
        }
    });

    let dns_stats = filter.stats();
    stats.dns_block_rules = dns_stats.block_rules as u64;
    stats.dns_exception_rules = dns_stats.exception_rules as u64;
    stats.network_only = dns_stats.network_only as u64;
    stats.allowlist = filter.allowlist_len() as u64;
    stats.dns_bytes = dns_bytes;

    mark("engine+serialize", &mut stage);

    // The modifiers the engine refuses are compiled from the same text, in the same run: they are not
    // part of `engine.bin` (they are this core's own matcher), so a compile that produced them only in
    // memory would lose them at the next process start. The count is logged here so a list that
    // suddenly stops producing them is visible.
    let extras = collect_extra_modifiers(request);
    // Written next to `dns.bin`/`engine.bin` because these rules are this core's own matcher and are
    // not part of `engine.bin`. Only the rule lines that need them are stored, so the file is a few
    // hundred KiB against the 41 MB engine — and the *original* lines, so a rule the current build
    // cannot use yet becomes usable after an upgrade without a recompile of the engine.
    let extras_payload = extras.serialize_lines().into_bytes();
    let extras_bytes = Envelope::new(Artifact::Extras, extras_payload)
        .write_atomic(&output_dir.join(compiled::EXTRAS_FILE))
        .map(|bytes| bytes as u64)
        .map_err(|e| {
            format!(
                "compile: cannot write {}: {e}",
                output_dir.join(compiled::EXTRAS_FILE).display()
            )
        })?;
    stats.extras_bytes = extras_bytes;
    crate::log_msg(
        "info",
        &format!(
            "extra modifiers: {} popup, {} denyallow, {} removeparam, extras.txt {} B",
            extras.popup.len(),
            extras.denyallow.len(),
            extras.removeparam.len(),
            extras_bytes
        ),
    );
    mark("extra modifiers", &mut stage);

    stats.elapsed_ms = started.elapsed().as_millis() as u64;
    crate::log_msg(
        "info",
        &format!(
            "compiled {} lists: {} dns rules ({} block / {} exception), {} network, {} unsupported, \
             dns.bin {} B, engine.bin {} B, {} ms",
            stats.lists.len(),
            stats.dns_rules,
            stats.dns_block_rules,
            stats.dns_exception_rules,
            stats.network_rules,
            stats.unsupported,
            stats.dns_bytes,
            stats.engine_bytes,
            stats.elapsed_ms
        ),
    );
    Ok(stats)
}

/// Read one list file as UTF-8 text.
///
/// `from_utf8_lossy` always allocates a fresh copy even when the input is already valid UTF-8, and
/// filter lists essentially always are, so the `String` is taken directly when possible.
fn read_list(id: &str, path: &str) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("compile: cannot read list {id} ({path}): {e}"))?;
    crate::log_msg(
        "info",
        &format!(
            "compile list: id={} content={}",
            serde_json::to_string(id).expect("string serializes"),
            compiled::PayloadIdentity::of_payload(&bytes).token(),
        ),
    );
    Ok(match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    })
}

/// Fold one source's counts into the running totals.
fn accumulate(stats: &mut CompileStats, id: String, counts: ListCounts, bytes: u64) {
    stats.lists.push(ListStats {
        id,
        lines: counts.lines,
        dns_rules: counts.dns_rules,
        network_rules: counts.network_rules,
        cosmetic_rules: counts.cosmetic_rules,
        unsupported: counts.unsupported,
        bytes,
    });
    stats.total_lines += counts.lines;
    stats.dns_rules += counts.dns_rules;
    stats.network_rules += counts.network_rules;
    stats.cosmetic_rules += counts.cosmetic_rules;
    stats.unsupported += counts.unsupported;
}

/// Wall-clock duration of the most recent [`load_dns_filter`] call, in microseconds.
///
/// Read by `start` to log the cold-start cost of the precompiled artifact (the number
/// `docs/PERF.md` records). A process-global rather than a return value because the only consumer is
/// a log line inside the JNI start path, which must not change the loader's signature.
pub static LAST_LOAD_MICROS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Load `extras.txt` from `dir` and rebuild the self-evaluated modifier rule sets.
///
/// Returns an empty set when the file is absent, which is the normal state for a first run and for a
/// compile that found no such rules: the option sets are optional everywhere, so an empty result is
/// indistinguishable from "nothing to do" and must not be an error.
pub fn load_extra_modifiers(dir: &Path) -> crate::https::extras::ExtraModifiers {
    load_extra_modifiers_with_identity(dir).0
}

/// Everything a load of `extras.txt` can conclude, as a value the caller must handle.
///
/// The three states are deliberately distinct, because collapsing them is what let a corrupt file
/// look like "no rules" (MYS-2859):
///
/// - [`ExtrasLoad::Missing`] — there is no `extras.txt`. A legitimate state: a compile that produced
///   no `$popup`/`$denyallow`/`$removeparam` rule writes an empty file rather than none, so an absent
///   file means an older artifact set or a directory that never had one. Nothing to install.
/// - [`ExtrasLoad::Loaded`] — the file decoded and its text was parsed into rule sets. The identity
///   is over the bytes that were parsed, so it describes the rules in force, not the file on disk.
/// - [`ExtrasLoad::Unusable`] — the file exists but cannot be used (bad magic, wrong version, a
///   truncated payload, a checksum mismatch, or text that is not UTF-8). Nothing was installed, and
///   the caller must not record the file as loaded: the next call has to retry.
///
/// The `Loaded` payload is boxed because the rule sets are ~1 KiB of `Vec`s and this value is moved
/// through a few `match` arms; clippy's `large_enum_variant` is right that the `Unusable` arm should
/// not have to carry that size.
#[derive(Debug)]
pub enum ExtrasLoad {
    Missing,
    Loaded {
        modifiers: Box<crate::https::extras::ExtraModifiers>,
        identity: crate::compiled::PayloadIdentity,
    },
    Unusable(String),
}

/// Load `extras.txt` and report which of the three states above applies.
///
/// This is the loader the **reload** path uses. It distinguishes "absent" from "broken" precisely
/// because a reload that could not read the modifiers must not pretend it installed them: a reload
/// that clears the rule set in force and records `extras` as current would pin an empty modifier set
/// until some later compile happened to change `dns.bin` or `engine.bin` too.
///
/// The **start** path keeps the lenient [`load_extra_modifiers_with_identity`]: a tunnel that refuses
/// to come up filters nothing at all, so there a broken `extras.txt` degrades to "no extra modifiers"
/// with the reason in the log, and the fingerprint recorded at start is deliberately absent so the
/// first reload retries.
pub fn load_extra_modifiers_checked(dir: &Path) -> ExtrasLoad {
    let path = dir.join(compiled::EXTRAS_FILE);
    if !path.exists() {
        return ExtrasLoad::Missing;
    }
    match Envelope::read(&path, Artifact::Extras) {
        Ok(envelope) => {
            let identity = crate::compiled::PayloadIdentity::of_payload(&envelope.payload);
            match String::from_utf8(envelope.payload) {
                Ok(text) => {
                    let started = Instant::now();
                    let modifiers = crate::https::extras::collect([text.as_str()]);
                    crate::log_msg(
                        "info",
                        &format!(
                            "extra modifiers loaded: {} popup, {} denyallow, {} removeparam, {} ms",
                            modifiers.popup.len(),
                            modifiers.denyallow.len(),
                            modifiers.removeparam.len(),
                            started.elapsed().as_millis()
                        ),
                    );
                    ExtrasLoad::Loaded {
                        modifiers: Box::new(modifiers),
                        identity,
                    }
                }
                Err(_) => ExtrasLoad::Unusable("extras.txt is not UTF-8".to_string()),
            }
        }
        Err(err) => ExtrasLoad::Unusable(format!("extras.txt unusable, recompile required: {err}")),
    }
}

/// [`load_extra_modifiers_checked`], degraded to the start path's contract.
///
/// Returns the rule sets that could be built plus the identity of the text they came from. `None` for
/// the identity means "no artifact, or one this build cannot use", which the start path reports as an
/// absent component rather than guessing.
pub fn load_extra_modifiers_with_identity(
    dir: &Path,
) -> (
    crate::https::extras::ExtraModifiers,
    Option<crate::compiled::PayloadIdentity>,
) {
    match load_extra_modifiers_checked(dir) {
        ExtrasLoad::Loaded {
            modifiers,
            identity,
        } => (*modifiers, Some(identity)),
        ExtrasLoad::Missing => (crate::https::extras::ExtraModifiers::default(), None),
        ExtrasLoad::Unusable(reason) => {
            // Not fatal: the engine's own rules still apply, and the reason is visible in the log. A
            // stale extras.txt is exactly the case a version bump is supposed to produce, and failing
            // the whole start over it would be worse than filtering a little less.
            crate::log_msg("warn", &reason);
            (crate::https::extras::ExtraModifiers::default(), None)
        }
    }
}

/// Load `dns.bin` from `dir` into a [`Filter`].
///
/// Returns `None` when the directory holds no artifact (first run) and an error only when a file
/// exists but is unusable — the `start` path treats both as "fall back", while the Kotlin side
/// distinguishes them to decide whether to trigger a recompile.
///
/// The payload is taken out of the file buffer in place (`Envelope::read_payload`) and the sections
/// are copied straight into their [`DomainSet`](crate::dns::filter)s, so the transient cost of the
/// load is one 4.3 MB buffer rather than the 13.3 MiB the `HashSet<String>` decoder needed
/// (`docs/PERF.md` §14).
/// Parse the modifiers the engine refuses out of the same list text the engine was compiled from.
///
/// Called by the compile path (which has the text in hand) and by nothing else: the runtime loads the
/// serialized artifacts, so these rules have to be built when the lists are. A read failure on one list
/// is not fatal — that list's extra modifiers are simply absent, and the normal compile already reports
/// the unreadable file.
pub fn collect_extra_modifiers(request: &CompileRequest) -> crate::https::extras::ExtraModifiers {
    let mut modifiers = crate::https::extras::ExtraModifiers::default();
    for list in &request.lists {
        match std::fs::read(&list.path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                modifiers.add_list(&text);
            }
            Err(err) => crate::log_msg(
                "warn",
                &format!("extra modifiers: cannot read list {}: {err}", list.id),
            ),
        }
    }
    if !request.user_rules.trim().is_empty() {
        modifiers.add_list(&request.user_rules);
    }
    modifiers.build();
    modifiers
}

pub fn load_dns_filter(dir: &Path) -> Result<Option<Filter>, String> {
    Ok(load_dns_filter_with_identity(dir)?.map(|(filter, _identity)| filter))
}

/// [`load_dns_filter`], plus the content identity of the `dns.bin` payload that was decoded.
///
/// The identity is taken from the payload buffer this call read and decoded, so it describes the rule
/// set that is actually in force; it is `None` exactly when there is no artifact to load. `docs/
/// TESTING.md` §14.8e explains why a byte count is not a substitute.
pub fn load_dns_filter_with_identity(
    dir: &Path,
) -> Result<Option<(Filter, crate::compiled::PayloadIdentity)>, String> {
    let path = dir.join(compiled::DNS_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let started = Instant::now();
    let payload = compiled::Envelope::read_payload(&path, compiled::Artifact::Dns)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let identity = compiled::PayloadIdentity::of_payload(&payload);
    let result = Filter::decode_payload(&payload)
        .map(|filter| Some((filter, identity)))
        .map_err(|e| format!("{}: {e}", path.display()));
    LAST_LOAD_MICROS.store(
        started.elapsed().as_micros() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiled::{DNS_FILE, ENGINE_FILE};
    use crate::dns::filter::Verdict;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "zshield-compile-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn write(&self, name: &str, content: &str) -> String {
            let path = self.0.join(name);
            std::fs::write(&path, content).expect("write");
            path.to_string_lossy().into_owned()
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn request(dir: &TempDir, lists: Vec<(&str, &str)>) -> CompileRequest {
        CompileRequest {
            lists: lists
                .into_iter()
                .map(|(id, path)| CompileList {
                    id: id.to_string(),
                    path: path.to_string(),
                })
                .collect(),
            user_rules: String::new(),
            allowlist: Vec::new(),
            output_dir: dir.join("compiled").to_string_lossy().into_owned(),
            debug_rules: true,
        }
    }

    const SAMPLE_LIST: &str = "\
[Adblock Plus 2.0]
! Title: Sample
! Expires: 1 day
||dns-block.example^
||dns-block.example^$important
||third-party.example^$third-party
||path.example/ads.js
||domain-option.example^$domain=foo.example
@@||exception.example^
0.0.0.0 hosts-entry.example
127.0.0.1 127.0.0.2
banner.example##.ad-banner
example.com#@#.allowed
example.com##+js(set-constant, ads, false)
@@||exception.example^$badfilter
! another comment

||after-blank.example^
";

    #[test]
    fn dns_layer_selection_matches_the_task_card() {
        let dir = TempDir::new("selection");
        let path = dir.write("list.txt", SAMPLE_LIST);
        let stats = compile(&request(&dir, vec![("sample", &path)])).expect("compile");

        let filter = load_dns_filter(&dir.join("compiled"))
            .expect("load")
            .expect("artifact exists");

        // Hosts entries and unmodified domain rules block at the DNS layer.
        assert_eq!(filter.match_domain("dns-block.example"), Verdict::Block);
        assert_eq!(filter.match_domain("hosts-entry.example"), Verdict::Block);
        assert_eq!(filter.match_domain("127.0.0.2"), Verdict::Block);
        // `$important` is still a whole-domain block.
        assert_eq!(filter.match_domain("sub.dns-block.example"), Verdict::Block);
        // `@@` removed by `$badfilter` in the same list, so the name stays blocked by nothing and
        // resolves normally.
        assert_eq!(filter.match_domain("exception.example"), Verdict::Allow);

        // A rule with a scope modifier must NOT become a whole-domain DNS block.
        assert_eq!(
            filter.match_domain("third-party.example"),
            Verdict::Allow,
            "`$third-party` must not block the whole domain at the DNS layer"
        );
        assert_eq!(
            filter.match_domain("path.example"),
            Verdict::Allow,
            "a path rule must not block the whole domain at the DNS layer"
        );
        assert_eq!(
            filter.match_domain("domain-option.example"),
            Verdict::Allow,
            "`$domain=` must not block the whole domain at the DNS layer"
        );

        // Cosmetic rules never reach the DNS layer.
        assert_eq!(filter.match_domain("banner.example"), Verdict::Allow);

        assert_eq!(filter.match_domain("after-blank.example"), Verdict::Block);
        assert!(stats.dns_rules >= 5);
    }

    #[test]
    fn compile_stats_counts_every_class() {
        let dir = TempDir::new("stats");
        let path = dir.write("list.txt", SAMPLE_LIST);
        let stats = compile(&request(&dir, vec![("sample", &path)])).expect("compile");

        assert_eq!(stats.lists.len(), 1);
        let list = &stats.lists[0];
        assert_eq!(list.id, "sample");
        assert_eq!(list.lines, SAMPLE_LIST.lines().count() as u64);
        // 1 comment header + 1 `[Adblock Plus 2.0]` + 3 metadata comments + 1 trailing comment.
        // `classify_line` treats `[...]` and `!` lines alike, so both count as comments.
        let classifiable = SAMPLE_LIST
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('!') && !trimmed.starts_with('[')
            })
            .count() as u64;
        assert_eq!(list.dns_rules + list.network_rules + list.unsupported, classifiable);
        assert_eq!(list.cosmetic_rules, 3, "two ## rules and one ##+js rule");
        assert_eq!(list.bytes, SAMPLE_LIST.len() as u64);
        assert_eq!(
            stats.total_lines,
            list.lines,
            "totals must equal the sum of the lists"
        );
        assert_eq!(stats.network_rules, list.network_rules);
        assert!(stats.dns_block_rules > 0);
        assert!(stats.dns_bytes > 0);
        assert!(stats.engine_bytes > 0);
    }

    #[test]
    fn compile_writes_both_artifacts_with_headers() {
        let dir = TempDir::new("artifacts");
        let path = dir.write("list.txt", SAMPLE_LIST);
        compile(&request(&dir, vec![("sample", &path)])).expect("compile");

        let dns = std::fs::read(dir.join("compiled").join(DNS_FILE)).expect("dns.bin");
        let engine = std::fs::read(dir.join("compiled").join(ENGINE_FILE)).expect("engine.bin");
        assert_eq!(Envelope::decode(Artifact::Dns, &dns).expect("dns envelope").format_version, compiled::FORMAT_VERSION);
        assert_eq!(
            Envelope::decode(Artifact::Engine, &engine)
                .expect("engine envelope")
                .format_version,
            compiled::FORMAT_VERSION
        );
    }

    #[test]
    fn engine_artifact_deserializes_and_matches_the_dns_filter() {
        let dir = TempDir::new("engine");
        let path = dir.write("list.txt", SAMPLE_LIST);
        compile(&request(&dir, vec![("sample", &path)])).expect("compile");

        let raw = std::fs::read(dir.join("compiled").join(ENGINE_FILE)).expect("engine.bin");
        let envelope = Envelope::decode(Artifact::Engine, &raw).expect("envelope");
        let mut engine = adblock::Engine::default();
        engine.deserialize(&envelope.payload).expect("deserialize");

        let blocked = adblock::request::Request::new(
            "https://dns-block.example/x.js",
            "https://page.example/",
            "script",
            "get",
        )
        .expect("request");
        assert!(
            engine.check_network_request(&blocked).should_block(),
            "the engine must still block after a serialize/deserialize round trip"
        );

        let path_rule = adblock::request::Request::new(
            "https://path.example/ads.js",
            "https://page.example/",
            "script",
            "get",
        )
        .expect("request");
        assert!(
            engine.check_network_request(&path_rule).should_block(),
            "path rules are the engine's job even though the DNS layer ignores them"
        );

        let clean = adblock::request::Request::new(
            "https://clean.example/app.js",
            "https://page.example/",
            "script",
            "get",
        )
        .expect("request");
        assert!(!engine.check_network_request(&clean).should_block());
    }

    #[test]
    fn allowlist_beats_list_rules_in_the_compiled_artifact() {
        let dir = TempDir::new("allowlist");
        let path = dir.write("list.txt", "||blocked.example^\n||blocked.example^$important\n");
        let mut req = request(&dir, vec![("sample", &path)]);
        req.allowlist = vec!["sub.blocked.example".to_string(), "@@||other.example^".to_string()];
        let stats = compile(&req).expect("compile");

        let filter = load_dns_filter(&dir.join("compiled"))
            .expect("load")
            .expect("artifact");
        assert_eq!(filter.match_domain("blocked.example"), Verdict::Block);
        assert_eq!(
            filter.match_domain("sub.blocked.example"),
            Verdict::Allow,
            "the user allowlist must beat even `$important`"
        );
        assert_eq!(filter.match_domain("other.example"), Verdict::Allow);
        assert_eq!(stats.allowlist, 2);
    }

    #[test]
    fn user_rules_participate_in_dns_and_engine_layers() {
        let dir = TempDir::new("user-rules");
        let path = dir.write("list.txt", "! empty list\n");
        let mut req = request(&dir, vec![("sample", &path)]);
        req.user_rules = "||user-blocked.example^\n||user-blocked.example/path\n".to_string();
        let stats = compile(&req).expect("compile");

        let filter = load_dns_filter(&dir.join("compiled"))
            .expect("load")
            .expect("artifact");
        assert_eq!(filter.match_domain("user-blocked.example"), Verdict::Block);
        // The custom rules show up as a pseudo-list in the statistics.
        assert!(stats.lists.iter().any(|l| l.id == "user-rules"));
    }

    #[test]
    fn badfilter_crosses_list_boundaries() {
        let dir = TempDir::new("badfilter");
        let first = dir.write("a.txt", "||cross.example^\n");
        let second = dir.write("b.txt", "||cross.example^$badfilter\n");
        compile(&request(&dir, vec![("a", &first), ("b", &second)])).expect("compile");

        let filter = load_dns_filter(&dir.join("compiled"))
            .expect("load")
            .expect("artifact");
        assert_eq!(
            filter.match_domain("cross.example"),
            Verdict::Allow,
            "a `$badfilter` in one list must disable the rule in another"
        );
    }

    #[test]
    fn missing_list_is_a_clean_error() {
        let dir = TempDir::new("missing");
        let err = compile(&request(&dir, vec![("gone", "/nonexistent/list.txt")]))
            .expect_err("must fail");
        assert!(err.contains("gone"), "{err}");
    }

    #[test]
    fn empty_output_dir_is_rejected() {
        let err = compile(&CompileRequest::default()).expect_err("must fail");
        assert!(err.contains("outputDir"), "{err}");
    }

    #[test]
    fn compile_request_json_round_trips() {
        let json = r#"{
            "lists":[{"id":"a","path":"/tmp/a.txt"}],
            "userRules":"||x.example^",
            "allowlist":["y.example"],
            "outputDir":"/tmp/out"
        }"#;
        let req: CompileRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.lists[0].id, "a");
        assert_eq!(req.user_rules, "||x.example^");
        assert_eq!(req.allowlist, vec!["y.example".to_string()]);
        assert_eq!(req.output_dir, "/tmp/out");
    }

    #[test]
    fn rule_attribution_is_opt_in_and_costs_artifact_size() {
        // `debugRules` doubles `engine.bin` (docs/PERF.md §11.2), so it is a request field rather
        // than always-on. Both sides of the trade are pinned here: off by default, and the artifact
        // really does carry less without it.
        let dir = TempDir::new("debug-rules");
        let path = dir.write("list.txt", SAMPLE_LIST);

        let mut plain = request(&dir, vec![("sample", &path)]);
        plain.output_dir = dir.join("plain").to_string_lossy().into_owned();
        plain.debug_rules = false;
        let plain_stats = compile(&plain).expect("compile");

        let mut attributed = request(&dir, vec![("sample", &path)]);
        attributed.output_dir = dir.join("attributed").to_string_lossy().into_owned();
        attributed.debug_rules = true;
        let attributed_stats = compile(&attributed).expect("compile");

        assert!(
            attributed_stats.engine_bytes > plain_stats.engine_bytes,
            "recording rule text must cost artifact size: {} vs {}",
            attributed_stats.engine_bytes,
            plain_stats.engine_bytes
        );

        // The default must be "off": `CompileRequest::default()` is what a caller who omits the
        // field gets through serde, and it must not silently pay for attribution.
        assert!(!CompileRequest::default().debug_rules);
        let omitted: CompileRequest =
            serde_json::from_str(r#"{"outputDir":"/tmp/x"}"#).expect("parse");
        assert!(!omitted.debug_rules);
    }

    #[test]
    fn load_returns_none_without_artifact() {
        let dir = TempDir::new("no-artifact");
        let loaded = load_dns_filter(&dir.0).expect("no error");
        assert!(loaded.is_none());
    }

    #[test]
    fn load_rejects_a_version_mismatched_artifact() {
        let dir = TempDir::new("stale");
        let path = dir.write("list.txt", SAMPLE_LIST);
        compile(&request(&dir, vec![("sample", &path)])).expect("compile");
        let file = dir.join("compiled").join(DNS_FILE);
        let mut raw = std::fs::read(&file).expect("read");
        raw[8..10].copy_from_slice(&(compiled::FORMAT_VERSION + 7).to_le_bytes());
        std::fs::write(&file, &raw).expect("write");

        let err = load_dns_filter(&dir.join("compiled")).expect_err("must fail");
        assert!(err.contains("recompile"), "{err}");
    }
}
