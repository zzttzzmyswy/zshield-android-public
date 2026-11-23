//! The single JNI entry point, `top.zztweb.zshield.core.Native`.
//!
//! The Kotlin signatures (see `docs/JNI.md`) are:
//!
//! ```kotlin
//! object Native {
//!     external fun version(): String
//!     external fun init(context: Context)
//!     external fun start(tunFd: Int, configJson: String): Long
//!     external fun stop(handle: Long)
//!     external fun statsJson(handle: Long): String
//!     external fun recentRequestsJson(handle: Long, sinceId: Long): String
//!     external fun lastError(): String
//! }
//! ```
//!
//! Every native call returns a plain value; failures never throw across the boundary, they set the
//! thread-safe `lastError` slot and return `0` / empty instead. That keeps the Kotlin control plane
//! simple and prevents a Rust panic from taking down the app process.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jobject, jstring, JNI_FALSE, JNI_TRUE};
use jni::{jni_mangle, Env, EnvUnowned, Outcome};

use crate::config::Config;
use crate::dns::engine::Engine;
use crate::dns::filter::Filter;
use crate::http::decision::HttpFilter;
use crate::http::log::RequestLog;
use crate::http::relay::{HttpContext, HttpSnapshot, HttpStats};
use crate::tun::forward::{ForwardSnapshot, ForwardStats, HttpsPipeline};
use crate::tun::policy::Policy;
use crate::tunnel::{self, StopFlag, TunStats};

/// Core version reported to Kotlin. The app's build sets `ZSHIELD_VERSION` from
/// `version.properties`; the fallback keeps a plain `cargo build` meaningful.
pub const VERSION: &str = match option_env!("ZSHIELD_VERSION") {
    Some(version) => version,
    None => "0.0.1",
};

static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLES: OnceLock<Mutex<Vec<Arc<EngineHandle>>>> = OnceLock::new();

fn handles() -> &'static Mutex<Vec<Arc<EngineHandle>>> {
    HANDLES.get_or_init(|| Mutex::new(Vec::new()))
}

fn set_last_error(message: impl Into<String>) {
    let message = message.into();
    crate::log_msg("warn", &message);
    let mut slot = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    *slot = message;
}

fn take_last_error() -> String {
    let slot = LAST_ERROR.lock().unwrap_or_else(|e| e.into_inner());
    slot.clone()
}

/// One running engine, owned by a handle the Kotlin side holds.
pub struct EngineHandle {
    pub id: u64,
    pub engine: Arc<Engine>,
    pub stop: Arc<StopFlag>,
    pub tun_stats: Arc<TunStats>,
    pub forward_stats: Arc<ForwardStats>,
    pub runtime: tokio::runtime::Runtime,
    /// The plaintext-HTTP and HTTPS pipelines, behind one lock each (MYS-2716).
    ///
    /// They are slots rather than plain fields because of the first-launch race: the tunnel can be
    /// started before the first compile has written `engine.bin`, and the compile then finishes
    /// while the tunnel is up. `reload` installs the artifacts into these slots, so the running
    /// tunnel picks them up without being rebuilt — a plain field captured at `start` had nowhere
    /// to put them, which is exactly the "引擎 未加载" report this fixes.
    pub pipelines: Arc<crate::tunnel::PipelineSlots>,
    /// The recent-request ring buffer served by `recentRequestsJson`.
    pub http_log: Arc<RequestLog>,
    pub http_stats: Arc<HttpStats>,
    /// Cosmetic-injection counters (M3b), shared by both pipelines.
    pub cosmetic_stats: Arc<crate::cosmetic::CosmeticStats>,
    /// The `$removeheader` rules in force, for the delivery note and `statsJson`.
    pub removeheader: Arc<crate::https::modifiers::RemoveHeaderRules>,
    /// The validated configuration, kept so a late compile can build the HTTPS pipeline that the
    /// first `start` could not (no `engine.bin` yet).
    pub config: crate::config::ValidatedConfig,
    /// Rule and config summary for `statsJson`.
    pub upstream_kinds: Vec<String>,
    pub rule_files: Vec<String>,
    /// Identity of the artifacts currently loaded: `dns.bin`, `engine.bin` and `extras.txt`.
    ///
    /// A reload is not free: it rebuilds both the DNS filter and the 41 MB adblock engine while the
    /// old ones are still installed, so the transient peak is ~2× the steady state and the idle
    /// native heap has to be trimmed afterwards (`docs/PERF.md` §14). The app compiles on every
    /// start (the repository schedules a compile once its lists are in place), so without this the
    /// tunnel paid that cost for an artifact that had not changed — measured at +8 MB of residual
    /// native heap on the Pixel 5 even after the trim. The fingerprint is each artifact's payload
    /// length and CRC32, read out of a 20-byte header: the writer is `write_atomic` (a rename of a
    /// freshly created file), so a rewrite always changes it, and this is a hot path that cannot
    /// afford to hash 41 MB.
    ///
    /// `None` means "no artifact set to compare against", which is also what a load that only
    /// partly landed records, so the next `reload` retries instead of skipping
    /// ([`ArtifactFingerprint`]).
    pub loaded_artifacts: std::sync::Mutex<Option<ArtifactFingerprint>>,
    /// What this handle has **in force**, for the readiness observation ([`crate::rules_identity`]).
    ///
    /// Separate from [`loaded_artifacts`](Self::loaded_artifacts) on purpose: that one answers "did the
    /// files on disk change since I last rebuilt?" with a 20-byte header read, and is deliberately
    /// cheap enough for the reload path. This one answers "which rule content is the engine actually
    /// running?", which only a hash of the loaded bytes can answer, and which is therefore filled in
    /// only where a load or a swap really happened.
    pub rules: std::sync::Mutex<crate::rules_identity::RulesState>,
    pub mode: &'static str,
    pub mtu: usize,
}

/// Identity of the three compiled artifacts currently loaded.
///
/// For `dns.bin` and `engine.bin` this is `(payload length, CRC32)` read out of the 20-byte envelope
/// header — see [`crate::compiled::Envelope::identity`]. For `extras.txt` it is the same pair taken
/// from the *validated* payload, because that file is small enough to read and because its header
/// alone cannot tell "the compile wrote the same rules" from "something truncated the text".
///
/// The modification time is deliberately *not* part of any of them: the app recompiles on every
/// start, so an mtime-based check would never match and the reload would always rebuild both rule
/// sets for identical bytes.
///
/// # Why all three, and why `extras` is optional
///
/// The first version of this type covered `dns` and `engine` only, on the assumption that a rule
/// change always changes one of them. It does not: `$removeparam`, `$popup` and `$denyallow` live in
/// `extras.txt` alone ([`crate::https::extras`]), so editing such a rule rewrote `extras.txt` and
/// nothing else — and the reload skipped, leaving the previous modifiers in force for the life of
/// the tunnel (MYS-2859). Every artifact the rule set is made of has to be part of the decision.
///
/// `None` for `extras` means "no `extras.txt` in this directory", which is a legitimate state (a
/// directory written by a build that produced no such rules, or one where the user deleted it). It
/// is *not* how an unusable file is reported: such a file makes [`read`](Self::read) return `None`,
/// so no fingerprint is recorded and the next reload tries again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactFingerprint {
    dns: (u32, u32),
    engine: (u32, u32),
    extras: Option<(u32, u32)>,
}

impl ArtifactFingerprint {
    /// Read every artifact's identity, `None` when the set cannot describe an installed rule set:
    /// `dns.bin` or `engine.bin` missing/unreadable, or an `extras.txt` that exists but is not a
    /// usable artifact.
    ///
    /// A `None` here is not an error to report: it means "there is no loaded rule set to compare
    /// against, so reload", which is exactly what the caller does with it.
    pub fn read(dir: &std::path::Path) -> Option<Self> {
        Some(Self {
            dns: crate::compiled::Envelope::identity(
                &dir.join(crate::compiled::DNS_FILE),
                crate::compiled::Artifact::Dns,
            )
            .ok()?,
            engine: crate::compiled::Envelope::identity(
                &dir.join(crate::compiled::ENGINE_FILE),
                crate::compiled::Artifact::Engine,
            )
            .ok()?,
            extras: read_extras_identity(dir)?,
        })
    }
}

/// The identity of `extras.txt` as a *loadable* artifact.
///
/// `Some(None)` when there is no such file (legitimate: nothing to install), `Some(Some(..))` when
/// it decodes, and `None` when a file exists but cannot be used — a truncated text, a foreign
/// magic, a checksum mismatch, or bytes that are not UTF-8. Reporting that last case as an identity
/// would let a failed load be recorded as installed, and the next `reload` would then skip the retry
/// the failure needs.
///
/// "Loadable" here means exactly what [`crate::compile::load_extra_modifiers_checked`] means by it,
/// including the UTF-8 requirement: a fingerprint the loader would reject must not be one the
/// skip-fast path can match.
///
/// This reads and checksums the payload instead of trusting the header because `extras.txt` is the
/// text of a few hundred rules, not 41 MB: the cost is well under a millisecond, and the header
/// alone cannot distinguish a complete file from one whose tail was lost.
fn read_extras_identity(dir: &std::path::Path) -> Option<Option<(u32, u32)>> {
    let path = dir.join(crate::compiled::EXTRAS_FILE);
    if !path.exists() {
        return Some(None);
    }
    match crate::compiled::Envelope::read(&path, crate::compiled::Artifact::Extras) {
        Ok(envelope) => {
            if std::str::from_utf8(&envelope.payload).is_err() {
                return None;
            }
            Some(Some((
                envelope.payload.len() as u32,
                crate::compiled::crc32(&envelope.payload),
            )))
        }
        Err(_) => None,
    }
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle")
            .field("id", &self.id)
            .field("upstream_kinds", &self.upstream_kinds)
            .field("rule_files", &self.rule_files)
            .finish()
    }
}

impl EngineHandle {
    /// The plaintext-HTTP rule engine in force, `None` while no `engine.bin` has been loaded.
    pub fn http_filter(&self) -> Option<Arc<HttpFilter>> {
        self.pipelines.http().map(|context| context.filter)
    }

    /// The HTTPS decryption pipeline in force, if one was built.
    pub fn https(&self) -> Option<Arc<HttpsPipeline>> {
        self.pipelines.https()
    }
}

impl EngineHandle {
    fn stats_json(&self) -> String {
        let stats = self.engine.stats();
        let (packets_in, packets_out, dropped) = self.tun_stats.snapshot();
        let ForwardSnapshot {
            tcp_active,
            tcp_total,
            udp_active,
            bytes_up,
            bytes_down,
            blocked_connections,
            quic_dropped,
            dns_hijacked,
            encrypted_dns_dropped,
        } = self.forward_stats.snapshot();
        let HttpSnapshot {
            requests: http_requests,
            blocked: http_blocked,
            redirected: http_redirected,
            degraded: http_degraded,
            rewritten: http_rewritten,
        } = self.http_stats.snapshot();
        let cosmetic = self.cosmetic_stats.snapshot();
        // One snapshot per call: a reload landing mid-serialization must not produce a document in
        // which `httpsFiltering` says one thing and the counters come from another pipeline.
        let https_pipeline = self.pipelines.https();
        let https = https_pipeline
            .as_ref()
            .map(|pipeline| pipeline.context.stats.snapshot())
            .unwrap_or_default();
        // The self-evaluated modifier rule sets, snapshotted once so the counters in the document all
        // describe the same rule set.
        let extras = self
            .http_filter()
            .map(|filter| filter.extras())
            .unwrap_or_default();
        // Built in two objects and merged: one `json!` literal with every counter in the crate
        // exceeds serde_json's macro recursion limit, and a nested `json!` would not help.
        let tunnel = serde_json::json!({
            "version": VERSION,
            "mode": self.mode,
            "mtu": self.mtu,
            "dnsQueries": stats.dns_queries,
            "dnsBlocked": stats.dns_blocked,
            "dnsErrors": stats.dns_errors,
            "dnsCached": stats.dns_cached,
            "dnsUpstreamQueries": stats.dns_upstream_queries,
            "upstreamLatencyMsP50": stats.upstream_latency_ms_p50,
            "cacheEntries": stats.cache_entries,
            "rulesBlock": stats.rules_block,
            "rulesException": stats.rules_exception,
            "rulesUnsupported": stats.rules_unsupported,
            "rulesNetworkOnly": stats.rules_network_only,
            "echStripped": stats.ech_stripped,
            "upstreams": self.upstream_kinds,
            "tunPacketsIn": packets_in,
            "tunPacketsOut": packets_out,
            "tunDropped": dropped,
            "tcpActive": tcp_active,
            "tcpTotal": tcp_total,
            "udpActive": udp_active,
            "bytesUp": bytes_up,
            "bytesDown": bytes_down,
            "blockedConnections": blocked_connections,
            "quicDropped": quic_dropped,
            "dnsHijacked": dns_hijacked,
            "encryptedDnsDropped": encrypted_dns_dropped,
            "httpRequests": http_requests,
            "httpBlocked": http_blocked,
            "httpRedirected": http_redirected,
            "httpRewritten": http_rewritten,
            "httpDegraded": http_degraded,
            "httpEngineLoaded": self.pipelines.has_http(),
            "requestLogSize": self.http_log.len() as u64,
        });
        // M3a: the HTTPS counters (task card §5). Present even when HTTPS filtering is off, so the UI
        // reading them never has to special-case the disabled state.
        let https_counters = serde_json::json!({
            "httpsFiltering": https_pipeline.is_some(),
            "httpsIntercepted": https.intercepted,
            "httpsPassthrough": https.passthrough,
            "httpsAutoBypassed": https.auto_bypassed,
            "httpsUpstreamInvalid": https.upstream_invalid,
            "httpsHandshakeFailures": https.handshake_failures,
            // MYS-2727: disconnects that were counted but deliberately not treated as evidence of a
            // rejected certificate (a racing browser connection, or one that left before our leaf).
            "httpsDisconnectsIgnored": https.disconnects_ignored,
            "h2Streams": https.h2_streams,
            "h2Blocked": https.h2_blocked,
            "httpsBypassEntries": https_pipeline
                .as_ref()
                .map(|pipeline| pipeline.bypass.len() as u64)
                .unwrap_or(0),
            "httpsRemoveHeaderRules": self.removeheader.len() as u64,
            // M5b: the modifiers the pinned engine refuses and this core evaluates itself
            // (docs/JNI.md §"$popup"). Present even when zero, so the UI can tell "no such rules in the
            // enabled lists" from "this build does not report them".
            "httpsPopupRules": extras.popup.len() as u64,
            "httpsDenyAllowRules": extras.denyallow.len() as u64,
            "httpsRemoveParamRules": extras.removeparam.len() as u64,
            // M3b: cosmetic injection (task card §5). Always present, zero when nothing was injected.
            "cosmeticInjected": cosmetic.injected,
            "cosmeticSkipped": cosmetic.skipped,
            "scriptletsInjected": cosmetic.scriptlets,
            "cosmeticCspMeta": cosmetic.csp_meta,
            "cosmeticScriptlets": crate::cosmetic::scriptlets::count() as u64,
            // How many selectors a subscription asked for that could not be injected safely (docs/JNI.md
            // §8.6). Non-zero means a list is carrying hostile or broken rules.
            "cosmeticRejectedSelectors": cosmetic.rejected_selectors,
            // Procedural rules (M5b): how many documents got the runtime, how many rules it was given,
            // and how many the selector screen refused. Separate from `cosmeticRejectedSelectors`
            // because the two are different failures: a hostile selector versus a rule whose CSS half a
            // browser cannot parse.
            "cosmeticProcedural": cosmetic.procedural,
            "cosmeticProceduralRules": cosmetic.procedural_rules,
            "cosmeticProceduralDropped": cosmetic.procedural_dropped,
        });
        let mut value = tunnel;
        if let (Some(target), Some(extra)) = (value.as_object_mut(), https_counters.as_object()) {
            target.extend(extra.clone());
        }
        value.to_string()
    }
}

fn find_handle(handle: u64) -> Option<Arc<EngineHandle>> {
    let handles = handles().lock().unwrap_or_else(|e| e.into_inner());
    handles
        .iter()
        .find(|entry| entry.id == handle)
        .map(Arc::clone)
}

// ---- read-only accessors for host controls outside this module ----
//
// A host control (`core/examples/*.rs`) has to observe the rules a live handle really has in force,
// not a fresh deserialization of the same files — that would answer "what do the artifacts say" and
// not "what is the tunnel deciding with", which is exactly the distinction the extras-reload bug
// turned on. These expose the same `Arc`s the request path reads, and change no state.

/// The plaintext-HTTP rule engine in force on `handle`, `None` when none is loaded.
pub fn handle_http_filter(handle: u64) -> Option<Arc<HttpFilter>> {
    find_handle(handle)?.http_filter()
}

/// The DNS rule set in force on `handle`.
pub fn handle_dns_filter(handle: u64) -> Option<Arc<Filter>> {
    Some(find_handle(handle)?.engine.filter())
}

/// What `handle` has in force: the three component identities and the generation.
pub fn handle_rules_state(handle: u64) -> Option<crate::rules_identity::RulesState> {
    let entry = find_handle(handle)?;
    let state = entry
        .rules
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    Some(state)
}

fn load_filter(rule_files: &[String]) -> Result<Filter, String> {
    let mut filter = Filter::new();
    for path in rule_files {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                filter.load_text(&text);
            }
            Err(err) => {
                // A missing rule file must not take the tunnel down; it is reported through
                // `lastError` and counted, and the remaining files still apply.
                set_last_error(format!("cannot read rule file {path}: {err}"));
            }
        }
    }
    Ok(filter)
}

/// Resolve the filter the engine should start with.
///
/// Order (task card §4): the precompiled `dns.bin` when `compiledDir` is set and the file is
/// usable; otherwise the plain `ruleFiles` text. A corrupt or stale artifact is *not* fatal — it is
/// reported through `lastError` so the Kotlin side can trigger a recompile, and the tunnel still
/// starts with whatever rules it can get, because a VPN that refuses to come up filters nothing at
/// all.
fn resolve_filter(
    config: &crate::config::ValidatedConfig,
) -> (Filter, Option<crate::compiled::PayloadIdentity>) {
    if !config.compiled_dir.trim().is_empty() {
        let dir = std::path::Path::new(&config.compiled_dir);
        match crate::compile::load_dns_filter_with_identity(dir) {
            Ok(Some((filter, identity))) => {
                let stats = filter.stats();
                // The decode buffers (the 4.3 MB payload plus the per-section record strings) are
                // dead once the sets are built; return their pages before the 41 MB engine load
                // makes its own peak, so the two do not add up.
                crate::mem::trim_allocator();
                crate::log_msg(
                    "info",
                    &format!(
                        "compiled rules loaded in {} ms",
                        crate::compile::LAST_LOAD_MICROS.load(std::sync::atomic::Ordering::Relaxed)
                            / 1000
                    ),
                );
                crate::log_msg(
                    "info",
                    &format!(
                        "loaded compiled rules: {} block, {} exception, {} unsupported, {} network-only ({})",
                        stats.block_rules,
                        stats.exception_rules,
                        stats.unsupported,
                        stats.network_only,
                        dir.display()
                    ),
                );
                return (filter, Some(identity));
            }
            Ok(None) => {
                set_last_error(format!(
                    "no compiled rules in {} (compile required)",
                    dir.display()
                ));
            }
            Err(err) => {
                // Version mismatch, corruption, unreadable file: all mean "recompile".
                set_last_error(format!("compiled rules unusable: {err}"));
            }
        }
    }
    // The plain-text fallback is not an artifact, so there is no payload identity to report: the
    // rule set came from `ruleFiles` on disk, which the compile has not turned into a target build.
    // Reporting a made-up identity here would let a run claim it measured a rule set it did not.
    match load_filter(&config.rule_files) {
        Ok(filter) => (filter, None),
        Err(err) => {
            set_last_error(err);
            (Filter::new(), None)
        }
    }
}

/// Resolve the plaintext-HTTP rule engine.
///
/// The precompiled `engine.bin` is the only source: M2b has no "parse the lists at start" path,
/// because that is what `compile` exists for (fixed decision 6). A missing artifact leaves HTTP
/// unfiltered and is reported, exactly as a missing `dns.bin` falls back to `ruleFiles` on the DNS
/// side — the tunnel still comes up, with hostname-level filtering.
fn resolve_http_filter(
    config: &crate::config::ValidatedConfig,
) -> Option<(Arc<HttpFilter>, crate::compiled::IdentitySet)> {
    if config.compiled_dir.trim().is_empty() {
        crate::log_msg(
            "info",
            "no compiledDir configured: plaintext HTTP is not filtered (hostname filtering only)",
        );
        return None;
    }
    let dir = std::path::Path::new(&config.compiled_dir);
    match crate::http::engine::load_with_identity(dir) {
        Ok(Some((filter, engine_identity))) => {
            crate::log_msg(
                "info",
                &format!(
                    "engine loaded in {} ms, {} B ({} redirect resources)",
                    crate::http::LAST_ENGINE_LOAD_MICROS.load(Ordering::Relaxed) / 1000,
                    crate::http::LAST_ENGINE_BYTES.load(Ordering::Relaxed),
                    crate::http::resources::builtin_names().count(),
                ),
            );
            let (extras, extras_identity) = crate::compile::load_extra_modifiers_with_identity(dir);
            // The identities describe what was just installed: the engine payload that was
            // deserialized, and the extras text that was parsed into the modifier sets.
            let identities =
                crate::rules_identity::identities(None, Some(engine_identity), extras_identity);
            Some((Arc::new(filter.with_extras(Arc::new(extras))), identities))
        }
        Ok(None) => {
            set_last_error(format!(
                "no {} in {} (compile required; HTTP requests are not filtered)",
                crate::compiled::ENGINE_FILE,
                dir.display()
            ));
            None
        }
        Err(err) => {
            // Version mismatch, corruption, a foreign payload: all mean "recompile". No identity is
            // produced: nothing was installed, so there is no generation to report.
            set_last_error(format!("compiled engine unusable: {err}"));
            None
        }
    }
}

/// The owner lookup the HTTPS decision uses.
///
/// On Android it is a JNI callback into `top.zztweb.zshield.https.OwnerResolver.ownerUid`, which
/// calls `ConnectivityManager.getConnectionOwnerUid`. Doing it from the Rust thread (rather than
/// having Kotlin pre-compute a table) is what keeps the decision in one place. The call is blocking
/// and unbounded, so the forwarding layer runs it on the blocking pool with a 200 ms budget and only
/// when the decision actually needs it ([`crate::https::policy::lookup_owner`]); the answer is not
/// reused for later connections, because a source port is not an application identity.
///
/// Without the JVM — a host build, the unit tests — every answer is "unknown", and an unknown owner
/// is never decrypted, so the tunnel behaves exactly as it did before M3a.
#[cfg(target_os = "android")]
fn platform_owner_lookup() -> PlatformOwnerLookup {
    PlatformOwnerLookup
}

/// Off Android there is no `ConnectivityManager`, and an unknown owner is never decrypted.
#[cfg(not(target_os = "android"))]
fn platform_owner_lookup() -> crate::https::policy::NoOwnerLookup {
    crate::https::policy::NoOwnerLookup
}

/// The JVM, stashed by `Native.init` so a tokio worker thread can attach to it later.
///
/// `JavaVM` is `Send + Sync` and lives for the process, which is exactly the lifetime a `OnceLock`
/// gives it. A tunnel that starts before `init` ran finds it empty and reports "unknown owner" for
/// every connection — which is never decrypted, i.e. the pre-M3a behaviour.
#[cfg(target_os = "android")]
static JAVA_VM: OnceLock<jni::JavaVM> = OnceLock::new();

/// A global reference to the `OwnerResolver` class, resolved in `init`.
///
/// `FindClass` from a natively-attached thread searches the *system* class loader, which does not
/// know this app's classes — so a lookup from a tokio worker thread fails with "class not found"
/// even though the class exists. Resolving it once from `init`, where the caller's (application)
/// class loader is in force, is the standard fix; the global reference keeps it valid for the
/// process.
#[cfg(target_os = "android")]
static OWNER_RESOLVER: OnceLock<jni::objects::Global<jni::objects::JClass<'static>>> =
    OnceLock::new();

/// The signature of `OwnerResolver.ownerUid`, resolved once alongside the class.
#[cfg(target_os = "android")]
static OWNER_UID_METHOD: OnceLock<jni::objects::JStaticMethodID> = OnceLock::new();

/// `ConnectivityManager.getConnectionOwnerUid` through a static Kotlin helper.
///
/// The class and method are part of the JNI contract and are documented in `docs/JNI.md`:
///
/// ```kotlin
/// object OwnerResolver {
///     @JvmStatic fun ownerUid(protocol: Int, localIp: String, localPort: Int,
///                             remoteIp: String, remotePort: Int): Int
/// }
/// ```
///
/// A negative return means "unknown" and becomes `None`. So does every failure mode — no stashed VM,
/// a pending exception, a class that is not on the classpath — because guessing a uid would decrypt
/// an application the user never selected.
#[cfg(target_os = "android")]
pub struct PlatformOwnerLookup;

#[cfg(target_os = "android")]
impl crate::https::policy::OwnerLookup for PlatformOwnerLookup {
    fn owner_uid(
        &self,
        local: std::net::SocketAddr,
        remote: std::net::SocketAddr,
    ) -> Option<u32> {
        use jni::objects::JValue;

        // `IPPROTO_TCP` is 6 on Android's Linux kernel.
        const IPPROTO_TCP: i32 = 6;

        let vm = match JAVA_VM.get() {
            Some(vm) => vm,
            None => {
                crate::log_msg("warn", "owner lookup: no JVM stashed");
                return None;
            }
        };
        let (Some(class), Some(method)) = (OWNER_RESOLVER.get(), OWNER_UID_METHOD.get()) else {
            crate::log_msg("warn", "owner lookup: OwnerResolver was not resolved by init");
            return None;
        };
        // The lookup runs on a tokio worker thread, which is not attached by default. Attaching costs
        // a few microseconds, against a TLS handshake that follows it.
        let result = vm.attach_current_thread(|env: &mut Env<'_>| -> jni::errors::Result<i32> {
            let local_ip = env.new_string(local.ip().to_string())?;
            let remote_ip = env.new_string(remote.ip().to_string())?;
            let args = [
                JValue::Int(IPPROTO_TCP).as_jni(),
                JValue::Object(&local_ip).as_jni(),
                JValue::Int(i32::from(local.port())).as_jni(),
                JValue::Object(&remote_ip).as_jni(),
                JValue::Int(i32::from(remote.port())).as_jni(),
            ];
            // SAFETY: `class` and `method` were resolved together in `init` and are process-global;
            // the argument list matches the signature that lookup used.
            let value = unsafe {
                env.call_static_method_unchecked(
                    class,
                    method,
                    jni::signature::ReturnType::Primitive(jni::signature::Primitive::Int),
                    &args,
                )
            }?;
            value.i()
        });
        match result {
            Ok(uid) if uid >= 0 => Some(uid as u32),
            Ok(uid) => {
                crate::log_msg(
                    "debug",
                    &format!("owner lookup {local} -> {remote}: uid {uid} (unknown)"),
                );
                None
            }
            Err(err) => {
                crate::log_msg("warn", &format!("owner lookup {local} -> {remote} failed: {err}"));
                None
            }
        }
    }
}

/// Build the HTTPS pipeline, or explain why it cannot run.
///
/// Four things have to be true, and each has its own reason (task card §1/§2):
///
/// 1. the control plane asked for HTTPS filtering — which it only does when the CA is installed, so
///    "on but not installed" never reaches here;
/// 2. a rule engine is loaded — MITM with no rules would only add latency and a trust anchor;
/// 3. a root CA is installed through `loadCa`;
/// 4. the upstream TLS configuration builds (the platform verifier is available).
///
/// Every failure is a *soft* one: the tunnel still comes up with plaintext and hostname filtering,
/// and the reason goes to `lastError`, which is the same contract every other optional artifact
/// follows in this core.
fn build_https_pipeline(
    config: &crate::config::ValidatedConfig,
    http_filter: Option<&Arc<HttpFilter>>,
    http_context: Option<&HttpContext>,
    removeheader: &Arc<crate::https::modifiers::RemoveHeaderRules>,
) -> Result<Option<Arc<HttpsPipeline>>, String> {
    match build_https_pipeline_inner(config, http_filter, http_context, removeheader) {
        PipelineOutcome::Built(pipeline) => Ok(Some(pipeline)),
        PipelineOutcome::Off => {
            crate::log_msg("info", "https filtering off: 443 connections are relayed verbatim");
            Ok(None)
        }
        PipelineOutcome::Unavailable(reason) => {
            // A soft failure: the tunnel still comes up, with plaintext and hostname filtering.
            set_last_error(reason);
            Ok(None)
        }
    }
}

/// Why the HTTPS pipeline was or was not built.
///
/// Returned rather than folded into `lastError` alone so the tests can assert the *reason* without
/// racing every other test's writes to the process-global error slot.
enum PipelineOutcome {
    Built(Arc<HttpsPipeline>),
    /// The control plane did not ask for it: not a failure, and no error is recorded.
    Off,
    /// It was asked for but cannot run; the string goes to `lastError`.
    Unavailable(String),
}

/// Build the HTTPS pipeline for a running tunnel if it does not have one yet.
///
/// Called from `reload_engine` on the first compile: a tunnel started before `engine.bin` existed
/// could not build the pipeline (there was no rule engine to decide a decrypted request with), and
/// without this it would keep relaying 443 verbatim for the rest of its life — the exact "HTTPS
/// filtering does nothing until you restart the VPN" report (`docs/JNI.md` §"首编译热替换").
///
/// A pipeline that already exists is never replaced: the swap would drop the live auto-bypass table
/// and the per-connection statistics for no benefit. Rebuilding it on a *CA* change is a different
/// path (`loadCa` runs before every `start`).
fn install_https_pipeline_if_missing(entry: &EngineHandle) {
    if entry.pipelines.has_https() {
        return;
    }
    let Some(http_filter) = entry.http_filter() else {
        // Nothing to decide with; `reload_engine` only calls this after installing an engine.
        return;
    };
    let Some(http_context) = entry.pipelines.http() else {
        return;
    };
    match build_https_pipeline(
        &entry.config,
        Some(&http_filter),
        Some(&http_context),
        &entry.removeheader,
    ) {
        Ok(Some(pipeline)) => {
            entry.pipelines.install_https(pipeline);
            crate::log_msg(
                "info",
                "https filtering pipeline installed on the first compile",
            );
        }
        Ok(None) => {}
        Err(err) => set_last_error(format!("reload: https pipeline not installed: {err}")),
    }
}

fn build_https_pipeline_inner(
    config: &crate::config::ValidatedConfig,
    http_filter: Option<&Arc<HttpFilter>>,
    http_context: Option<&HttpContext>,
    removeheader: &Arc<crate::https::modifiers::RemoveHeaderRules>,
) -> PipelineOutcome {
    if !config.https_filtering {
        return PipelineOutcome::Off;
    }
    let (Some(http_filter), Some(base_context)) = (http_filter, http_context) else {
        return PipelineOutcome::Unavailable(
            "httpsFiltering is on but no rule engine is loaded; HTTPS connections are not decrypted"
                .to_string(),
        );
    };
    let Some(ca) = current_ca() else {
        return PipelineOutcome::Unavailable(
            "httpsFiltering is on but loadCa has not installed a root CA; \
             HTTPS connections are not decrypted"
                .to_string(),
        );
    };
    let upstream = match crate::https::tls::client_config() {
        Ok(upstream) => upstream,
        Err(err) => {
            return PipelineOutcome::Unavailable(format!("https filtering unavailable: {err}"));
        }
    };

    let modifier_source = Arc::new(crate::https::modifiers::HttpsModifiers::new(
        http_filter.clone(),
        removeheader.clone(),
        http_filter.extras_arc(),
    ));
    let decrypted_context = HttpContext {
        filter: http_filter.clone(),
        log: base_context.log.clone(),
        stats: base_context.stats.clone(),
        cosmetic: base_context.cosmetic.clone(),
        // The scheme decides the URL a rule sees and the framing of a rewritten body: the HTTP/2 leg
        // has its own framing, so only the HTTP/1.1 stream uses this.
        framing: crate::cosmetic::OutFraming::Chunked,
        head_limit: base_context.head_limit,
        scheme: crate::http::head::Scheme::Https,
        modifiers: Some(modifier_source),
    };

    let stats = Arc::new(crate::https::HttpsStats::default());
    let context = crate::https::HttpsContext {
        http: decrypted_context,
        removeheader: removeheader.clone(),
        ca: ca.clone(),
        upstream,
        bypass: Arc::new(crate::https::policy::AutoBypass::default()),
        stats,
    };

    let policy = crate::https::policy::HttpsPolicy {
        enabled: true,
        uids: config.https_uids.clone(),
        excluded_hosts: config.https_excluded_hosts.clone(),
    };
    crate::log_msg(
        "info",
        &format!(
            "https filtering on: ca {}, {} selected uids, {} excluded hosts",
            ca.info().fingerprint_sha256,
            policy.uids.len(),
            policy.excluded_hosts.len()
        ),
    );
    PipelineOutcome::Built(Arc::new(HttpsPipeline {
        policy: std::sync::RwLock::new(policy),
        bypass: context.bypass.clone(),
        context,
    }))
}

/// Load the encrypted-DNS host list, reporting problems without failing the start.
fn load_encrypted_dns_hosts(path: &str) -> std::collections::HashSet<String> {
    if path.trim().is_empty() {
        return std::collections::HashSet::new();
    }
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let hosts = Policy::parse_encrypted_dns_hosts(&text);
            crate::log_msg(
                "info",
                &format!("encrypted-dns host list: {} hosts from {path}", hosts.len()),
            );
            hosts
        }
        Err(err) => {
            // Not fatal: the fixed list only adds to the user's rules, and a VPN that refuses to
            // start filters nothing. Reported so the control plane can see it.
            set_last_error(format!("cannot read encrypted-dns host list {path}: {err}"));
            std::collections::HashSet::new()
        }
    }
}

/// `version(): String?`
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn version<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        Ok(to_jstring(env, VERSION))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        _ => std::ptr::null_mut(),
    }
}

/// `init(context: Context)`: hands the JVM/Context to rustls-platform-verifier so certificate
/// validation can use the Android system trust store. Must be called once before the first DoH
/// query.
///
/// The verifier crate only exposes that initialiser when building for Android; on a host build
/// (unit tests) this is a no-op, which is why the DoH tests do not go through the platform
/// verifier.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn init<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    context: JObject<'local>,
) {
    #[cfg(target_os = "android")]
    {
        let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<()> {
            // Stash the VM first: the HTTPS owner lookup runs on a tokio worker thread and needs to
            // attach to it. A failure here is not fatal — `get_java_vm` only fails with a pending
            // exception, which the verifier initialisation below would hit anyway.
            if let Ok(vm) = env.get_java_vm() {
                let _ = JAVA_VM.set(vm);
            }
            // Resolve the owner resolver while the application class loader is in force. Doing it
            // here (rather than in the lookup) is what makes a later `FindClass`-free call possible.
            if let Ok(class) = env.find_class(jni::jni_str!(
                "top/zztweb/zshield/https/OwnerResolver"
            )) {
                if let Ok(method) = env.get_static_method_id(
                    &class,
                    jni::jni_str!("ownerUid"),
                    jni::jni_sig!("(ILjava/lang/String;ILjava/lang/String;I)I"),
                ) {
                    let _ = OWNER_UID_METHOD.set(method);
                }
                if let Ok(global) = env.new_global_ref(&class) {
                    let _ = OWNER_RESOLVER.set(global);
                }
            } else {
                crate::log_msg("warn", "init: cannot resolve OwnerResolver; HTTPS owner lookups will report unknown");
            }
            match rustls_platform_verifier::android::init_with_env(env, context) {
                Ok(()) => Ok(()),
                // Initialisation only fails if the JVM accessors are unusable; the platform
                // verifier then fails at query time, which surfaces through `lastError`.
                Err(err) => {
                    crate::log_msg("warn", &format!("platform verifier init failed: {err}"));
                    Ok(())
                }
            }
        });
        if matches!(outcome.into_outcome(), Outcome::Panic(_)) {
            set_last_error("rustls platform verifier initialisation panicked");
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (&mut env, context);
    }
}

/// `start(tunFd: Int, configJson: String): Long`
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn start<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
) -> jlong {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jlong> {
        let raw = config_json.try_to_string(env)?;
        let handle = match start_engine(tun_fd, &raw) {
            Ok(handle) => handle as jlong,
            Err(err) => {
                set_last_error(err);
                0
            }
        };
        Ok(handle)
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("start: {err}"));
            0
        }
        Outcome::Panic(_) => {
            set_last_error("start: native panic");
            0
        }
    }
}

/// Testable core of `Native.start`.
pub fn start_engine(tun_fd: jint, config_json: &str) -> Result<u64, String> {
    // Take ownership of the fd first, so every early return below closes it instead of leaking it:
    // the Kotlin side has already called `detachFd()` and will never close it.
    let owned_fd = tunnel::own_fd(tun_fd).map_err(|e| format!("tun fd: {e}"))?;
    let config = Config::from_json(config_json).map_err(|e| format!("config: {e}"))?;
    let rss_before_rules = crate::mem::rss_kib();
    let (dns_filter, dns_identity) = resolve_filter(&config);
    let filter = Arc::new(dns_filter);
    crate::mem::log_rss_delta(
        "dns rules loaded",
        rss_before_rules,
        crate::mem::rss_kib(),
    );
    let rule_stats = filter.stats();
    crate::log_msg(
        "info",
        &format!(
            "rules: {} files, {} block, {} exception, {} unsupported, {} network-only",
            rule_stats.files_loaded,
            rule_stats.block_rules,
            rule_stats.exception_rules,
            rule_stats.unsupported,
            rule_stats.network_only
        ),
    );

    // M2b: the adblock engine, loaded once and shared by every forwarding task. A missing or
    // unusable `engine.bin` is not fatal — the tunnel then filters by hostname only, and the reason
    // is in `lastError`, which is the same policy the DNS artifact follows (a VPN that refuses to
    // come up filters nothing at all).
    let rss_before_engine = crate::mem::rss_kib();
    let http_loaded = resolve_http_filter(&config);
    crate::mem::log_rss_delta(
        "http engine loaded",
        rss_before_engine,
        crate::mem::rss_kib(),
    );
    // Split the engine from its identity: the pipeline takes the engine, the readiness observation
    // takes the identity (MYS-2825).
    let (http_filter, mut start_identities) = match http_loaded {
        Some((filter, identities)) => (Some(filter), identities),
        None => (None, crate::compiled::IdentitySet::default()),
    };
    start_identities.dns = dns_identity;
    let http_log = Arc::new(RequestLog::new());
    let http_stats = Arc::new(HttpStats::default());
    // M3b: cosmetic injection counters, shared by the plaintext and decrypted pipelines so `statsJson`
    // reports one number per event rather than one per connection type.
    let cosmetic_stats = Arc::new(crate::cosmetic::CosmeticStats::default());
    // The plaintext pipeline keeps its M2b behaviour: no modifier source, so an allowed request is
    // forwarded byte for byte. The decrypted pipeline (below) gets one, because `$removeparam`,
    // `$removeheader` and `$csp` only mean anything on a connection whose bytes are ours to change.
    let http_context = http_filter.as_ref().map(|filter| HttpContext {
        filter: filter.clone(),
        log: http_log.clone(),
        stats: http_stats.clone(),
        cosmetic: cosmetic_stats.clone(),
        // Plain HTTP is HTTP/1.x: a rewritten body has no length, so it is chunked.
        framing: crate::cosmetic::OutFraming::Chunked,
        head_limit: config.http_head_bytes,
        scheme: crate::http::head::Scheme::Http,
        modifiers: None,
    });

    let engine = Engine::new(&config, filter).map_err(|e| format!("upstream: {e}"))?;
    // MYS-2742: the same ring buffer serves all three layers, so the log and the blocked counters
    // answer one question. Attached before the tunnel starts, so no query is answered unlogged.
    let engine = Arc::new(engine.with_log(http_log.clone()));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.workers.max(1))
        .enable_all()
        .thread_name("zshield-core")
        .build()
        .map_err(|e| format!("runtime: {e}"))?;

    let stop = Arc::new(StopFlag::new());
    let tun_stats = Arc::new(TunStats::default());
    let forward_stats = Arc::new(ForwardStats::default());
    let id = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);

    // The encrypted-DNS host list is an asset extracted by the app; a missing file means "no fixed
    // list", not a failure to start — the user's own rules still apply.
    let encrypted_dns_hosts = load_encrypted_dns_hosts(&config.encrypted_dns_hosts_file);
    let policy = Arc::new(config.policy(encrypted_dns_hosts));
    crate::log_msg(
        "info",
        &format!(
            "tunnel policy: mode {}, mtu {}, quic {}, encrypted-dns {} ({} hosts), \
             timeouts tcp {}s/udp {}s, sniff {}B/{}ms, http head {}B",
            policy.mode.as_str(),
            policy.mtu,
            policy.block_quic,
            policy.block_encrypted_dns,
            policy.encrypted_dns_hosts.len(),
            policy.tcp_idle_timeout.as_secs(),
            policy.udp_idle_timeout.as_secs(),
            policy.sniff_bytes,
            policy.sniff_timeout.as_millis(),
            config.http_head_bytes,
        ),
    );

    let upstream_kinds = config
        .upstreams
        .iter()
        .map(|upstream| match upstream {
            crate::config::UpstreamConfig::Doh { url, .. } => format!("doh:{url}"),
            crate::config::UpstreamConfig::Udp { address } => format!("udp:{address}"),
        })
        .collect::<Vec<_>>();

    // M3a: the HTTPS pipeline. Built only when the control plane asked for it *and* the rule engine
    // loaded — without an engine there is nothing to decide a decrypted request with, and MITM with
    // no rules would only add latency and a trust anchor for no filtering.
    let removeheader = Arc::new(crate::https::modifiers::collect_removeheader(
        std::iter::empty(),
    ));
    let https = build_https_pipeline(&config, http_filter.as_ref(), http_context.as_ref(), &removeheader)?;

    // The slots the running tunnel reads its pipelines from. `reload` fills them in when the first
    // compile lands, so a tunnel started before `engine.bin` existed starts filtering HTTP (and
    // decrypting HTTPS) without being rebuilt (`docs/JNI.md` §"首编译热替换").
    let pipelines = Arc::new(tunnel::PipelineSlots::new(http_context, https));

    let handle = Arc::new(EngineHandle {
        id,
        engine: engine.clone(),
        stop: stop.clone(),
        tun_stats: tun_stats.clone(),
        forward_stats: forward_stats.clone(),
        runtime,
        pipelines: pipelines.clone(),
        http_log: http_log.clone(),
        http_stats,
        cosmetic_stats,
        removeheader: removeheader.clone(),
        config: config.clone(),
        upstream_kinds,
        rule_files: config.rule_files.clone(),
        // What this `start` actually loaded, so the first `reload` can tell "same artifact" from
        // "the compile produced something new" without re-reading 41 MB.
        loaded_artifacts: std::sync::Mutex::new(
            (!config.compiled_dir.trim().is_empty())
                .then(|| ArtifactFingerprint::read(std::path::Path::new(&config.compiled_dir)))
                .flatten(),
        ),
        // The start's own install is recorded below, once the tunnel is really up: a generation
        // reported before the stack can carry a request would describe a rule set that is not yet
        // the one deciding anything.
        rules: std::sync::Mutex::new(crate::rules_identity::RulesState::default()),
        mode: policy.mode.as_str(),
        mtu: policy.mtu,
    });

    // The tunnel loop owns the runtime; when `stop` is set the loop returns and the runtime is
    // dropped with the handle.
    let tunnel_config = tunnel::TunnelConfig {
        engine,
        policy,
        stop: stop.clone(),
        tun_stats,
        forward_stats,
        pipelines,
        owner_lookup: Arc::new(platform_owner_lookup()),
        log: http_log.clone(),
    };
    handle.runtime.spawn(async move {
        tunnel::run(owned_fd, tunnel_config).await;
    });

    handles()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(handle.clone());
    crate::log_msg("info", &format!("engine started, handle {id}"));
    // The readiness observation (MYS-2825). Emitted here, not at the top of `start`: only now are the
    // engine, the pipelines and the tunnel loop in place, so this line describes a rule set that is
    // actually deciding. The generation it carries is the one every sample in this run must match.
    let generation = handle
        .rules
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .installed(start_identities.clone());
    crate::rules_identity::IdentityEvent {
        event: "start",
        ok: true,
        handle: id,
        generation,
        identities: start_identities,
        reason: None,
    }
    .log();
    // The engine payload is purged before extras are parsed. Release the later loader's
    // scratch too; cached startups no longer get an incidental purge from compilation.
    let before = crate::mem::rss_kib();
    crate::mem::trim_unused_memory();
    crate::mem::log_rss_delta("startup temporaries released", before, crate::mem::rss_kib());
    Ok(id)
}

/// `stop(handle: Long)`
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn stop<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>, handle: jlong) {
    let outcome = env.with_env(|_env: &mut Env<'local>| -> jni::errors::Result<()> {
        stop_engine(handle as u64);
        Ok(())
    });
    let _ = outcome.into_outcome();
}

/// Testable core of `Native.stop`.
pub fn stop_engine(handle: u64) {
    let entry = {
        let mut handles = handles().lock().unwrap_or_else(|e| e.into_inner());
        let position = handles.iter().position(|entry| entry.id == handle);
        position.map(|index| handles.remove(index))
    };
    let Some(entry) = entry else {
        set_last_error(format!("stop: unknown handle {handle}"));
        return;
    };
    entry.stop.request();
    // Give the loop a moment to leave its select arm, then drop the runtime, which aborts any
    // task still running (there must be nothing left that touches the fd by then).
    entry
        .runtime
        .block_on(async { tokio::time::sleep(std::time::Duration::from_millis(50)).await });
    // The request log names every host the device talked to, so it is memory-only and never outlives
    // the tunnel (`docs/JNI.md` §6.4, `docs/DESIGN.md` §11). Dropping the handle would free it anyway;
    // clearing here also empties it for a caller still holding an `Arc`, and resets the QUIC dedupe
    // table so the next run does not believe it already reported a destination.
    entry.http_log.clear();
    crate::log_msg("info", &format!("engine stopped, handle {handle}"));
}

/// Turn a JSON document into a Java string, or `null` when the JVM itself refuses to allocate one.
///
/// Every `String`-returning entry point goes through here. Two things follow from that:
///
/// - the *value* is always valid JSON even on an error path (`{}`, `[]`, `{"error":"..."}`), so a
///   Kotlin caller that parses it never sees a half-built document;
/// - `null` remains possible, but only when `NewStringUTF` could not run at all (a pending exception
///   or an exhausted JVM). The Kotlin declarations are therefore `String?` and every caller handles
///   `null` — that is `docs/JNI.md` §"返回值" and the MYS-2716 fix: the old signature claimed
///   non-null, so the one case the Rust side cannot prevent crashed the app process.
fn to_jstring(env: &mut Env<'_>, json: &str) -> jstring {
    match JString::from_str(env, json) {
        Ok(text) => text.into_raw(),
        Err(err) => {
            set_last_error(format!("cannot allocate the result string: {err}"));
            std::ptr::null_mut()
        }
    }
}

/// `statsJson(handle: Long): String?`
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn stats_json<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        let json = match find_handle(handle as u64) {
            Some(entry) => entry.stats_json(),
            None => {
                set_last_error(format!("stats: unknown handle {handle}"));
                // Valid, empty JSON rather than `""`: `{}` parses into every field's default, which
                // is what the Kotlin side shows as "no counters yet". An empty string would be an
                // unparseable document.
                "{}".to_string()
            }
        };
        Ok(to_jstring(env, &json))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("statsJson: {err}"));
            std::ptr::null_mut()
        }
        Outcome::Panic(_) => {
            set_last_error("statsJson: native panic");
            std::ptr::null_mut()
        }
    }
}

/// `compile(requestJson: String): String?`
///
/// Synchronous, and deliberately so: the caller (Kotlin) runs it on a background thread and needs
/// the statistics as a return value. A compile of the default list set takes a few seconds, which
/// is far too long to hold the JNI caller on the UI thread — see `docs/JNI.md`.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn compile<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    request_json: JString<'local>,
) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        let raw = request_json.try_to_string(env)?;
        let json = compile_json(&raw);
        Ok(to_jstring(env, &json))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        // The JVM environment itself failed, so no string can be built. `null` is the documented
        // "check lastError()" signal on the Kotlin side (docs/JNI.md).
        Outcome::Err(err) => {
            set_last_error(format!("compile: {err}"));
            std::ptr::null_mut()
        }
        Outcome::Panic(_) => {
            set_last_error("compile: native panic");
            std::ptr::null_mut()
        }
    }
}

/// Testable core of `Native.compile`: never fails, reports errors as `{"error": "..."}`.
pub fn compile_json(request_json: &str) -> String {
    let result = crate::compile::compile_request(request_json);
    // The compiler's DNS builder and extras matchers are now dropped. Its earlier trims run
    // while some of those temporaries are still alive; an unchanged reload returns before its
    // own trim, so that path otherwise retains the compilation's freed pages indefinitely.
    let before = crate::mem::rss_kib();
    let cleanup_started = std::time::Instant::now();
    crate::mem::trim_unused_memory();
    crate::mem::log_rss_delta("compile temporaries released", before, crate::mem::rss_kib());
    crate::log_msg(
        "info",
        &format!(
            "compile allocator cleanup: {} ms",
            cleanup_started.elapsed().as_millis()
        ),
    );
    match result {
        Ok(stats) => serde_json::to_string(&stats).unwrap_or_else(|e| {
            error_json(&format!("compile: cannot serialize statistics: {e}"))
        }),
        Err(err) => {
            set_last_error(&err);
            error_json(&err)
        }
    }
}

fn error_json(message: &str) -> String {
    serde_json::json!({ "error": message }).to_string()
}

/// `reload(handle: Long, compiledDir: String): Boolean`
///
/// Replaces the running engine's rule set with the artifacts in `compiledDir`. In-flight queries
/// keep the filter they started with; the DNS cache is cleared because every entry in it was a
/// decision made by the previous rules. On any failure the old filter stays in force and the reason
/// is written to `lastError`.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn reload<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    compiled_dir: JString<'local>,
) -> jboolean {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jboolean> {
        let dir = compiled_dir.try_to_string(env)?;
        Ok(if reload_engine(handle as u64, &dir) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("reload: {err}"));
            JNI_FALSE
        }
        Outcome::Panic(_) => {
            set_last_error("reload: native panic");
            JNI_FALSE
        }
    }
}

/// What a reload does with the modifier rule sets, decided from [`crate::compile::ExtrasLoad`].
///
/// One value rather than two independent `Option`s, because the failure this type exists to prevent
/// (MYS-2859) was exactly an install decision and a bookkeeping decision that could disagree: the
/// reload installed an empty modifier set and then wrote the new fingerprint, so the corrupt
/// `extras.txt` was never retried.
///
/// `modifiers` is boxed for the same reason [`crate::compile::ExtrasLoad`] boxes it: the `Keep` arm
/// carries a short reason and should not pay for the rule sets' size.
enum ExtrasPlan {
    /// Install these rule sets and report this identity (`None` = the artifact is absent).
    Install {
        modifiers: Box<crate::https::extras::ExtraModifiers>,
        identity: Option<crate::compiled::PayloadIdentity>,
    },
    /// Install nothing; the modifiers already in force stay in force, and the swap is a failure.
    Keep { reason: String },
}

impl ExtrasPlan {
    /// Why this plan makes the swap a failure, if it does.
    fn failure(&self) -> Option<String> {
        match self {
            Self::Install { .. } => None,
            Self::Keep { reason } => Some(format!("extras: {reason}")),
        }
    }
}

/// Testable core of `Native.reload`.
///
/// Replaces both the DNS filter and the adblock engine. The two artifacts are produced together by
/// one compile, so replacing one and not the other would leave the tunnel filtering URLs with one
/// rule set and hostnames with another. The third artifact, `extras.txt`, carries the modifiers this
/// core evaluates itself and is part of the same swap for the same reason.
pub fn reload_engine(handle: u64, compiled_dir: &str) -> bool {
    let Some(entry) = find_handle(handle) else {
        set_last_error(format!("reload: unknown handle {handle}"));
        return false;
    };
    if compiled_dir.trim().is_empty() {
        set_last_error("reload: compiledDir is empty");
        return false;
    }
    let dir = std::path::Path::new(compiled_dir);

    // Nothing to do when the artifacts are byte-identical to what this tunnel already loaded. That
    // is the common case, not an edge case: the app schedules a compile on every start, so a
    // `reload` used to rebuild both the DNS filter and the 41 MB engine on top of the copies the
    // running tunnel already held, purely to end up with the same rules. `docs/PERF.md` §14 has the
    // measured cost of doing it versus skipping it.
    let fingerprint = ArtifactFingerprint::read(dir);
    if let Some(fingerprint) = fingerprint {
        let current = entry
            .loaded_artifacts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .to_owned();
        if current == Some(fingerprint) {
            crate::log_msg(
                "info",
                "rules reload: artifacts unchanged, keeping the loaded rule sets",
            );
            return true;
        }
    }

    // The extras are loaded **before** anything is swapped. They are the one artifact whose failure
    // is not fatal to a reload (the engine's own rules still apply), but it is fatal to *recording*
    // the swap as complete: a reload that installed an empty modifier set and then wrote the new
    // fingerprint would skip the retry that a corrupt `extras.txt` needs, and the user's
    // `$removeparam` rules would stay off until some later compile also changed `dns.bin` or
    // `engine.bin` (MYS-2859).
    let extras_load = crate::compile::load_extra_modifiers_checked(dir);
    if let crate::compile::ExtrasLoad::Unusable(reason) = &extras_load {
        crate::log_msg("warn", reason);
        // The Kotlin side turns a `false` return into `CompileState.Failed(lastError)`, so the reason
        // has to be in the slot the JNI contract documents. The engine path below may overwrite it
        // with its own reason; either one names a real failure, and the log line above carries both.
        set_last_error(format!("reload: extras not replaced: {reason}"));
    }

    let filter = match crate::compile::load_dns_filter_with_identity(dir) {
        Ok(Some((filter, identity))) => (filter, identity),
        Ok(None) => {
            set_last_error(format!(
                "reload: no compiled rules in {}",
                dir.display()
            ));
            // Nothing was installed, so nothing changed in force. The event is emitted anyway: a
            // failed swap that leaves no trace in the log is indistinguishable from one that never
            // ran, and the readiness check refuses on a reported failure (`MYS-2825`).
            report_failed_reload(&entry, format!("dns: no compiled rules in {}", dir.display()));
            return false;
        }
        Err(err) => {
            set_last_error(format!("reload: {err}"));
            report_failed_reload(&entry, format!("dns: {err}"));
            return false;
        }
    };
    let (filter, dns_identity) = filter;
    // What to do with the modifiers, decided once so the install and the recorded identity cannot
    // disagree.
    //
    // An **absent** `extras.txt` is a legitimate empty rule set, not a failure: a compile that found
    // no `$popup`/`$denyallow`/`$removeparam` rule writes an empty file, so an absent one means the
    // rules were removed or the directory predates this artifact. Installing the empty set is what
    // makes a deletion take effect, and the identity is `None`, which is how the observation spells
    // "absent".
    //
    // An **unusable** file is the case this used to get wrong: it installed the empty set (silently
    // dropping every modifier the user had) and then recorded the new fingerprint, so the failure was
    // never retried (MYS-2859). Now nothing is installed, the modifiers already in force stay in
    // force, and the swap is reported with `ok=false` and no fingerprint so the next call retries.
    let extras_plan = match extras_load {
        crate::compile::ExtrasLoad::Missing => ExtrasPlan::Install {
            modifiers: Box::new(crate::https::extras::ExtraModifiers::default()),
            identity: None,
        },
        crate::compile::ExtrasLoad::Loaded {
            modifiers,
            identity,
        } => ExtrasPlan::Install {
            modifiers,
            identity: Some(identity),
        },
        crate::compile::ExtrasLoad::Unusable(reason) => ExtrasPlan::Keep { reason },
    };
    let stats = filter.stats();
    let invalidated = entry.engine.replace_filter(std::sync::Arc::new(filter));
    // The DNS side is in force from here on, so the readiness observation starts from that fact: if
    // the engine swap below fails, the truth is "new hostname rules, old URL rules", and that is what
    // the event reports (`MYS-2825`: an inconsistent swap must be visible, not smoothed over).
    let mut next_identities = entry
        .rules
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .identities
        .clone();
    next_identities.dns = Some(dns_identity);
    // The engine artifact is optional: a rule set compiled with no network rules produces one anyway,
    // but a directory from an older version may not have it. A failure here leaves the previous
    // engine in force and is reported, which is the same contract as the DNS side.
    //
    // A tunnel that started before the first compile has no engine in its slot at all. That is the
    // case the `None` arm handles: the newly compiled `engine.bin` is *installed* into the running
    // tunnel instead of being reported as "no engine loaded" (`docs/JNI.md` §"首编译热替换"). The
    // loaded artifact is reused for that instead of being deserialized twice.
    let mut failure: Option<String> = extras_plan.failure();
    let engine_note = match entry.http_filter() {
        Some(existing) => match crate::http::engine::reload_with_identity(&existing, dir) {
            Ok(identity) => {
                // The engine's rules were just replaced, so the rules this core evaluates itself have
                // to be replaced with them: a `$popup` rule that survived a list edit while the engine
                // moved on would be the one part of the rule set that never updates.
                match extras_plan {
                    ExtrasPlan::Install {
                        modifiers,
                        identity: extras_identity,
                    } => {
                        existing.replace_extras(Arc::new(*modifiers));
                        next_identities.extras = extras_identity;
                    }
                    // Nothing installed and nothing recorded: the modifiers in force did not change,
                    // so their identity does not either. (`extras_plan` is not used again below, so
                    // this arm consuming it is fine.)
                    ExtrasPlan::Keep { .. } => {}
                }
                next_identities.engine = Some(identity.clone());
                format!("engine {} B", identity.bytes)
            }
            Err(err) => {
                set_last_error(format!("reload: engine not replaced: {err}"));
                // The old engine and the old extras are still in force, so `next_identities` keeps
                // them: the line describes the mixture that really decides requests.
                if failure.is_none() {
                    failure = Some(format!("engine: {err}"));
                }
                format!("engine unchanged ({err})")
            }
        },
        None => match crate::http::engine::load_with_identity(dir) {
            Ok(Some((loaded, identity))) => {
                // A tunnel that started before the first compile had no engine, so it had no
                // modifiers in force either: whatever this load installs is the first set.
                let (modifiers, extras_identity) = match extras_plan {
                    ExtrasPlan::Install {
                        modifiers,
                        identity,
                    } => (*modifiers, identity),
                    ExtrasPlan::Keep { .. } => (
                        crate::https::extras::ExtraModifiers::default(),
                        None,
                    ),
                };
                entry.pipelines.install_http(HttpContext {
                    filter: Arc::new(loaded.with_extras(Arc::new(modifiers))),
                    log: entry.http_log.clone(),
                    stats: entry.http_stats.clone(),
                    cosmetic: entry.cosmetic_stats.clone(),
                    framing: crate::cosmetic::OutFraming::Chunked,
                    head_limit: entry.config.http_head_bytes,
                    scheme: crate::http::head::Scheme::Http,
                    modifiers: None,
                });
                // HTTPS decryption had the same prerequisite (an engine to decide with), so the
                // pipeline that could not be built at `start` is built here.
                install_https_pipeline_if_missing(&entry);
                next_identities.extras = extras_identity;
                next_identities.engine = Some(identity.clone());
                format!("engine {} B (loaded on first compile)", identity.bytes)
            }
            Ok(None) => {
                // No artifact to install: the engine is genuinely absent, and reporting it as absent
                // is the truthful observation. Whether that matches the target build is the
                // consumer's question, not this one's.
                //
                // The extras go with it: `HttpFilter` is what carries the modifier rule sets, so with
                // no engine there is no decision path that could consult them. Reporting their
                // identity here would claim rules are in force that nothing reads.
                next_identities.engine = None;
                next_identities.extras = None;
                "no engine artifact".to_string()
            }
            Err(err) => {
                set_last_error(format!("reload: engine not replaced: {err}"));
                if failure.is_none() {
                    failure = Some(format!("engine: {err}"));
                }
                format!("engine unchanged ({err})")
            }
        },
    };
    // A reload builds a second engine while the first is still installed, so the peak necessarily
    // holds both (`docs/PERF.md` §14 measures it). The old snapshot is gone by now — every in-flight
    // request took its own `Arc` and has since dropped it — so the freed pages are returned to the
    // kernel here rather than left in the allocator's arena until the process dies. This is the
    // single biggest lever on idle PSS: before it, a start whose first compile landed while the
    // tunnel was up kept the compile's ~90 MiB of freed pages resident indefinitely.
    //
    // The fingerprint is recorded only when the swap really installed everything. A failed swap — a
    // corrupt `extras.txt`, an engine that would not deserialize — must not be written down as
    // "these artifacts are loaded": the next `reload` would then match the record and skip, so the
    // failure would never be retried and the previous rules would stay in force until some later
    // compile happened to change an unrelated artifact too (MYS-2859). `None` means "nothing to
    // compare against", which is exactly the state a failed swap leaves the tunnel in.
    *entry
        .loaded_artifacts
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = match failure {
        Some(_) => None,
        None => fingerprint,
    };
    crate::mem::trim_allocator();
    crate::mem::log_rss("after reload (trimmed)");
    // One definition of "unsupported" for the whole app: the figure printed here is the one the
    // compile statistics report and the one the UI shows, because both come from the same per-line
    // tally in `FilterBuilder::add_text` (`docs/JNI.md` §"规则统计"). MYS-2716 fixed a version of this
    // line that reported a *different* number for the same rule set.
    crate::log_msg(
        "info",
        &format!(
            "rules reloaded: {} block, {} exception, {} unsupported (neither layer can use), \
             {} network-only (engine rules); {invalidated} cache entries dropped; {engine_note}",
            stats.block_rules,
            stats.exception_rules,
            stats.unsupported,
            stats.network_only
        ),
    );
    // The readiness observation (`MYS-2825`): what this swap installed, and the generation a sample
    // batch has to match. A swap that installed nothing advances no generation and says why, so a run
    // cannot mistake "the reload was attempted" for "the new rules are in force".
    let event_identities;
    let generation = {
        let mut state = entry.rules.lock().unwrap_or_else(|e| e.into_inner());
        match &failure {
            // Nothing is decided by a half-applied swap: the DNS side did change, but the engine did
            // not, so the rule set in force is a mixture. It is recorded as the mixture (the state is
            // updated so a later event reports the same truth) and the generation does **not** move —
            // a consumer that pinned generation N must not see it advance on a failure.
            Some(_) => {
                event_identities = next_identities.clone();
                state.identities = next_identities;
                state.generation
            }
            None => {
                event_identities = next_identities.clone();
                state.installed(next_identities)
            }
        }
    };
    crate::rules_identity::IdentityEvent {
        event: "swap",
        ok: failure.is_none(),
        handle: entry.id,
        generation,
        identities: event_identities,
        reason: failure.clone(),
    }
    .log();
    // `false` when a component the compile produced could not be installed. The DNS side may have
    // swapped by then, so this is not "nothing happened" — it is "the rule set in force is not the
    // one that was compiled", which is what the Kotlin side acts on (`CompileState.Failed` with the
    // reason from `lastError`). Returning `true` here would report a reload as done while the
    // user's modifiers were the previous ones (MYS-2859).
    failure.is_none()
}

/// Report a reload that could not install anything, with the identities that are still in force.
fn report_failed_reload(entry: &Arc<EngineHandle>, reason: String) {
    let state = entry
        .rules
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    crate::rules_identity::IdentityEvent {
        event: "swap",
        ok: false,
        handle: entry.id,
        generation: state.generation,
        identities: state.identities,
        reason: Some(reason),
    }
    .log();
}

/// `recentRequestsJson(handle: Long, sinceId: Long): String?`
///
/// The ring buffer of recent requests as a JSON array, newest last, filtered to entries newer than
/// `sinceId` (pass `0` for everything the buffer holds). Serialization happens inside this call and
/// nowhere else — there is no push, so nothing runs while the UI is not asking (`docs/DESIGN.md`
/// decision 10).
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn recent_requests_json<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    since_id: jlong,
) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        let json = recent_requests_json_for(handle as u64, since_id as u64);
        Ok(to_jstring(env, &json))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("recentRequestsJson: {err}"));
            std::ptr::null_mut()
        }
        Outcome::Panic(_) => {
            set_last_error("recentRequestsJson: native panic");
            std::ptr::null_mut()
        }
    }
}

/// Testable core of `Native.recentRequestsJson`.
///
/// An unknown handle returns an empty array and records the reason, matching every other read-only
/// entry point: the Kotlin side never needs try/catch around a JNI call.
pub fn recent_requests_json_for(handle: u64, since_id: u64) -> String {
    match find_handle(handle) {
        Some(entry) => entry.http_log.to_json(since_id),
        None => {
            set_last_error(format!("recentRequests: unknown handle {handle}"));
            "[]".to_string()
        }
    }
}

/// `generateCa(): String?`
///
/// Generates the device's root CA (task card §1). Returns `{"certPem": "...", "keyPkcs8B64": "..."}`
/// on success and `{"error": "..."}` on failure. The private key leaves this call **once**, for the
/// Kotlin side to wrap with an Android-Keystore AES-GCM key; it never appears in a log line, in
/// `configJson`, or in `statsJson`.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn generate_ca<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        let json = generate_ca_json();
        Ok(to_jstring(env, &json))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("generateCa: {err}"));
            std::ptr::null_mut()
        }
        Outcome::Panic(_) => {
            set_last_error("generateCa: native panic");
            std::ptr::null_mut()
        }
    }
}

/// Testable core of `Native.generateCa`.
pub fn generate_ca_json() -> String {
    use base64::Engine as _;
    match crate::https::ca::generate() {
        Ok(generated) => {
            crate::log_msg(
                "info",
                &format!(
                    "generated root CA {} (valid until {})",
                    generated.fingerprint_sha256, generated.not_after_ms
                ),
            );
            serde_json::json!({
                "certPem": generated.cert_pem,
                "keyPkcs8B64": base64::engine::general_purpose::STANDARD
                    .encode(generated.key.as_pkcs8_der()),
                "fingerprintSha256": generated.fingerprint_sha256,
                "notAfterMs": generated.not_after_ms,
            })
            .to_string()
        }
        Err(err) => {
            set_last_error(format!("generateCa: {err}"));
            error_json(&err.to_string())
        }
    }
}

/// `loadCa(certPem: String, keyPkcs8: ByteArray): Boolean`
///
/// Installs the CA the control plane stored, before every `start`. Returns `false` and sets
/// `lastError` when the material is unusable; the previously loaded CA (if any) then stays in force,
/// which is the safer failure — a tunnel with the old CA still filters, a tunnel with none does not.
#[jni_mangle("top.zztweb.zshield.core.Native")]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn load_ca<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    cert_pem: JString<'local>,
    key_pkcs8: jni::sys::jbyteArray,
) -> jboolean {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jboolean> {
        let pem = cert_pem.try_to_string(env)?;
        let key = if key_pkcs8.is_null() {
            Vec::new()
        } else {
            // SAFETY: the JNI contract guarantees a non-null array argument is a valid local
            // reference belonging to the current thread and this call's frame.
            let array = unsafe { jni::objects::JPrimitiveArray::from_raw(env, key_pkcs8) };
            env.convert_byte_array(&array)?
        };
        Ok(if load_ca_material(&pem, &key) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("loadCa: {err}"));
            JNI_FALSE
        }
        Outcome::Panic(_) => {
            set_last_error("loadCa: native panic");
            JNI_FALSE
        }
    }
}

/// The installed CA, shared by every handle that starts after [`load_ca_material`].
///
/// A process-wide slot rather than a per-handle field because the CA outlives one tunnel: the app
/// loads it once per start, and a restart must not require reloading it.
static INSTALLED_CA: OnceLock<Mutex<Option<Arc<crate::https::ca::Ca>>>> = OnceLock::new();

fn installed_ca() -> &'static Mutex<Option<Arc<crate::https::ca::Ca>>> {
    INSTALLED_CA.get_or_init(|| Mutex::new(None))
}

/// Testable core of `Native.loadCa`.
pub fn load_ca_material(cert_pem: &str, key_pkcs8: &[u8]) -> bool {
    let key = crate::https::ca::CaKey::from_pkcs8_der(key_pkcs8.to_vec());
    match crate::https::ca::load(cert_pem, &key) {
        Ok(ca) => {
            crate::log_msg(
                "info",
                &format!(
                    "root CA loaded: {} (valid until {})",
                    ca.info().fingerprint_sha256,
                    ca.info().not_after_ms
                ),
            );
            *installed_ca().lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(ca));
            true
        }
        Err(err) => {
            set_last_error(format!("loadCa: {err}"));
            false
        }
    }
}

/// Serialises access to the process-wide installed CA.
///
/// `load_ca_material` writes it and several tests read or clear it, so cargo's parallel test threads
/// race: `the_https_pipeline_is_built_when_everything_is_present` installs a CA while
/// `the_https_pipeline_is_not_built_without_its_prerequisites` clears it, and whichever lost the race
/// failed with a message about the wrong state. Every test that touches the slot holds this lock for
/// its whole body.
#[cfg(test)]
static CA_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Take [`CA_TEST_LOCK`], ignoring poisoning: a failed test must not cascade into unrelated ones.
#[cfg(test)]
fn lock_installed_ca() -> std::sync::MutexGuard<'static, ()> {
    CA_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// The CA currently installed, if any.
pub fn current_ca() -> Option<Arc<crate::https::ca::Ca>> {
    installed_ca()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// `httpsBypassJson(handle: Long): String?`
///
/// The live auto-bypass table: one object per `(uid, host)` pair with its expiry and reason, for the
/// UI's "why is this app not filtered" screen (task card §4).
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn https_bypass_json<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        let json = https_bypass_json_for(handle as u64);
        Ok(to_jstring(env, &json))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("httpsBypassJson: {err}"));
            std::ptr::null_mut()
        }
        Outcome::Panic(_) => {
            set_last_error("httpsBypassJson: native panic");
            std::ptr::null_mut()
        }
    }
}

/// Testable core of `Native.httpsBypassJson`.
pub fn https_bypass_json_for(handle: u64) -> String {
    let Some(entry) = find_handle(handle) else {
        set_last_error(format!("httpsBypassJson: unknown handle {handle}"));
        return "[]".to_string();
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let entries = match entry.pipelines.https() {
        Some(pipeline) => pipeline.bypass.snapshot(now_ms),
        None => Vec::new(),
    };
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
}

/// `clearHttpsBypass(handle: Long): Boolean`
///
/// Empties the auto-bypass table, so the next connection for a pair is decrypted again.
///
/// Needed after the user installs (or reinstalls) the CA: every pair that failed while the
/// certificate was missing stays bypassed for 24 h otherwise, and the user would see HTTPS filtering
/// doing nothing with no way to tell why.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn clear_https_bypass<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    let outcome = env.with_env(|_env: &mut Env<'local>| -> jni::errors::Result<jboolean> {
        Ok(if clear_https_bypass_for(handle as u64) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("clearHttpsBypass: {err}"));
            JNI_FALSE
        }
        Outcome::Panic(_) => {
            set_last_error("clearHttpsBypass: native panic");
            JNI_FALSE
        }
    }
}

/// Testable core of `Native.clearHttpsBypass`.
pub fn clear_https_bypass_for(handle: u64) -> bool {
    let Some(entry) = find_handle(handle) else {
        set_last_error(format!("clearHttpsBypass: unknown handle {handle}"));
        return false;
    };
    match entry.pipelines.https() {
        Some(pipeline) => {
            pipeline.bypass.clear();
            crate::log_msg("info", "https auto-bypass table cleared");
            true
        }
        None => {
            // Not an error: there is nothing to clear when HTTPS filtering is off.
            true
        }
    }
}

/// `updateHttpsPolicy(handle: Long, policyJson: String): Boolean`
///
/// Hot-replaces the HTTPS selection without rebuilding the tunnel: the browser list, the user's
/// extra applications and the excluded hosts are all re-derived from settings that can change while
/// the tunnel runs (task card §2: 变化时热更新).
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn update_https_policy<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    policy_json: JString<'local>,
) -> jboolean {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jboolean> {
        let json = policy_json.try_to_string(env)?;
        Ok(if update_https_policy_for(handle as u64, &json) {
            JNI_TRUE
        } else {
            JNI_FALSE
        })
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("updateHttpsPolicy: {err}"));
            JNI_FALSE
        }
        Outcome::Panic(_) => {
            set_last_error("updateHttpsPolicy: native panic");
            JNI_FALSE
        }
    }
}

/// The `updateHttpsPolicy` document. Field names are documented in `docs/JNI.md`.
///
/// `excludedHosts` is `Option` on purpose: `null` (or absent) means "leave the list alone", while an
/// array replaces it. Without that distinction a caller that only wants to change the uid set — the
/// common case — would silently wipe the 100+ banking and pinning entries the asset provides, which
/// is a privacy regression, not a cosmetic one.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct HttpsPolicyUpdate {
    enabled: bool,
    uids: Vec<u32>,
    excluded_hosts: Option<Vec<String>>,
}

/// Testable core of `Native.updateHttpsPolicy`.
pub fn update_https_policy_for(handle: u64, json: &str) -> bool {
    let Some(entry) = find_handle(handle) else {
        set_last_error(format!("updateHttpsPolicy: unknown handle {handle}"));
        return false;
    };
    let Some(pipeline) = entry.pipelines.https() else {
        set_last_error("updateHttpsPolicy: HTTPS filtering is not running");
        return false;
    };
    let update: HttpsPolicyUpdate = match serde_json::from_str(json) {
        Ok(update) => update,
        Err(err) => {
            set_last_error(format!("updateHttpsPolicy: invalid JSON: {err}"));
            return false;
        }
    };
    // The policy lives behind a lock so a forwarding task sees either the old or the new set, never
    // a half-applied one.
    let mut policy = pipeline
        .policy
        .write()
        .unwrap_or_else(|e| e.into_inner());
    policy.enabled = update.enabled;
    policy.uids = update.uids.clone();
    if let Some(hosts) = update.excluded_hosts.as_ref() {
        policy.excluded_hosts =
            crate::https::policy::HttpsPolicy::parse_list(&hosts.join("\n"));
    }
    crate::log_msg(
        "info",
        &format!(
            "https policy updated: enabled {}, {} uids, {} excluded hosts",
            policy.enabled,
            policy.uids.len(),
            policy.excluded_hosts.len()
        ),
    );
    true
}

/// `lastError(): String?`
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn last_error<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>) -> jstring {
    let outcome = env.with_env(|env: &mut Env<'local>| -> jni::errors::Result<jstring> {
        Ok(to_jstring(env, &take_last_error()))
    });
    match outcome.into_outcome() {
        Outcome::Ok(value) => value,
        Outcome::Err(err) => {
            set_last_error(format!("lastError: {err}"));
            std::ptr::null_mut()
        }
        Outcome::Panic(_) => {
            set_last_error("lastError: native panic");
            std::ptr::null_mut()
        }
    }
}

/// `trimMemory()`: return allocator-owned free pages, retaining every live engine and connection.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn trim_memory<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>) {
    let outcome = env.with_env(|_env: &mut Env<'local>| -> jni::errors::Result<()> {
        let before = crate::mem::rss_kib();
        let started = std::time::Instant::now();
        crate::mem::trim_unused_memory();
        crate::mem::log_rss_delta(
            "background unused pages released", before, crate::mem::rss_kib(),
        );
        crate::log_msg(
            "info", &format!("background allocator trim: {} ms", started.elapsed().as_millis()),
        );
        Ok(())
    });
    let _ = outcome.into_outcome();
}

/// `releaseAll()`: stop every engine. Called from the app's `onDestroy` as a safety net so a
/// leaked handle cannot keep a tunnel alive after the process is done with it.
#[jni_mangle("top.zztweb.zshield.core.Native")]
pub fn release_all<'local>(mut env: EnvUnowned<'local>, _class: JClass<'local>) {
    let outcome = env.with_env(|_env: &mut Env<'local>| -> jni::errors::Result<()> {
        let ids: Vec<u64> = handles()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|entry| entry.id)
            .collect();
        for id in ids {
            stop_engine(id);
        }
        Ok(())
    });
    let _ = outcome.into_outcome();
}

/// Suppress the unused-import warning for `jobject`, which is only needed on some JNI versions.
const _: fn() -> jobject = || std::ptr::null_mut();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_reported() {
        // The build injects version.properties; a plain cargo build gets the documented fallback.
        assert!(!VERSION.is_empty());
        assert!(VERSION.split('.').count() >= 2, "unexpected version {VERSION}");
    }

    #[test]
    fn last_error_is_readable_and_writable() {
        set_last_error("something went wrong");
        assert_eq!(take_last_error(), "something went wrong");
    }

    #[test]
    fn start_with_bad_config_fails_cleanly() {
        // A real (owned) descriptor, because `start` takes ownership of it before validating the
        // config and closes it on the error path.
        let fd = open_dev_null();
        let err = start_engine(fd, "{not json").expect_err("must fail");
        assert!(err.contains("config"), "{err}");
    }

    /// Opens `/dev/null` and returns the raw descriptor, which the caller transfers away.
    fn open_dev_null() -> jint {
        let file = std::fs::File::open("/dev/null").expect("open /dev/null");
        use std::os::fd::IntoRawFd;
        file.into_raw_fd()
    }

    // ---- the unified request log through the JNI surface (MYS-2742 §修复②) ----

    /// Answers every A query with `203.0.113.7`, so a query through `start` needs no network.
    #[derive(Debug)]
    struct FixedResolver;

    impl crate::upstream::Resolver for FixedResolver {
        fn query<'a>(
            &'a self,
            message: &'a [u8],
            _timeout: std::time::Duration,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<u8>, crate::upstream::UpstreamError>> + Send + 'a>,
        > {
            // Echo the query id and the question, with one A record: enough for the engine to treat
            // it as a resolved answer and to cache it.
            let parsed = crate::dns::wire::Message::parse(message);
            let answer = parsed.map(|query| {
                crate::dns::wire::build_response(
                    &query,
                    crate::dns::wire::RCODE_NOERROR,
                    &[crate::dns::wire::Record {
                        name: query.question().map(|q| q.name.clone()).unwrap_or_default(),
                        rtype: crate::dns::wire::TYPE_A,
                        rclass: crate::dns::wire::CLASS_IN,
                        ttl: 60,
                        rdata: vec![203, 0, 113, 7],
                    }],
                    &[],
                )
            });
            Box::pin(async move { answer.map_err(|err| crate::upstream::UpstreamError::Http(err.to_string())) })
        }

        fn label(&self) -> &str {
            "fixed"
        }
    }

    fn raw_a_query(id: u16, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&[0u8; 6]);
        out.extend_from_slice(&crate::dns::wire::encode_name(name).expect("name"));
        out.extend_from_slice(&crate::dns::wire::TYPE_A.to_be_bytes());
        out.extend_from_slice(&crate::dns::wire::CLASS_IN.to_be_bytes());
        out
    }

    #[test]
    fn the_request_log_records_every_layer_and_matches_the_blocked_counters() {
        // The acceptance criterion for MYS-2742 §修复②, proven across the whole stack rather than
        // layer by layer: three DNS queries (one blocked, one allowed, one cached hit) plus one
        // connection-level block must appear in `recentRequestsJson`, and the number of
        // `outcome = blocked` entries must equal the increase of
        // `dnsBlocked + blockedConnections + httpBlocked`.
        let filter = {
            let mut filter = Filter::new();
            filter.load_text("||ads.example^\n");
            Arc::new(filter)
        };
        let log = Arc::new(RequestLog::new());
        let base_stats = crate::dns::engine::Stats::default();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let engine = Arc::new(
            runtime
                .block_on(async {
                    crate::dns::engine::Engine::with_resolvers(
                        &Config::default().validate().expect("config"),
                        filter,
                        vec![Arc::new(FixedResolver)],
                    )
                })
                .expect("engine")
                .with_log(log.clone()),
        );

        let forward_stats = Arc::new(ForwardStats::default());
        runtime.block_on(async {
            let (_, blocked) = engine.handle(&raw_a_query(1, "ads.example")).await;
            assert!(matches!(blocked, crate::dns::engine::Outcome::Blocked { .. }));
            let (_, allowed) = engine.handle(&raw_a_query(2, "clean.example")).await;
            assert_eq!(allowed, crate::dns::engine::Outcome::Resolved);
            let (_, cached) = engine.handle(&raw_a_query(3, "clean.example")).await;
            assert_eq!(cached, crate::dns::engine::Outcome::Cached);
        });
        // The connection layer counts and logs through the one function every drop site uses.
        assert!(crate::tun::forward::record_connection_block(
            &forward_stats,
            Some(&log),
            "tracker.example",
            crate::tun::policy::DropReason::DomainBlocked,
        ));

        let json = log.to_json(0);
        let entries: serde_json::Value = serde_json::from_str(&json).expect("json");
        let entries = entries.as_array().expect("array");
        assert_eq!(entries.len(), 4, "three DNS entries plus one connection entry: {json}");
        let outcomes: Vec<&str> = entries
            .iter()
            .map(|entry| entry["outcome"].as_str().expect("outcome"))
            .collect();
        assert_eq!(outcomes, vec!["blocked", "allowed", "cached", "blocked"]);
        let kinds: Vec<&str> = entries
            .iter()
            .map(|entry| entry["kind"].as_str().expect("kind"))
            .collect();
        assert_eq!(kinds, vec!["dns", "dns", "dns", "connection"]);

        // The ledger. `httpBlocked` has no traffic to count here, so the sum is the two terms.
        let dns = engine.stats();
        let forward = forward_stats.snapshot();
        let logged_blocked = outcomes.iter().filter(|outcome| **outcome == "blocked").count() as u64;
        let counted =
            (dns.dns_blocked - base_stats.dns_blocked) + forward.blocked_connections;
        assert_eq!(
            logged_blocked, counted,
            "log blocked entries ({logged_blocked}) must equal dnsBlocked + blockedConnections \
             ({counted})"
        );
        assert_eq!(dns.dns_queries, 3);
        assert_eq!(dns.dns_cached, 1);
    }

    #[test]
    fn start_with_bad_fd_fails_cleanly() {
        let err = start_engine(-1, "{}").expect_err("must fail");
        assert!(err.contains("tun fd"), "{err}");
    }

    #[test]
    fn stop_unknown_handle_reports_an_error() {
        stop_engine(999_999);
        assert!(take_last_error().contains("unknown handle"));
    }

    #[test]
    fn stopping_the_tunnel_clears_the_request_log() {
        // MYS-2742 §修复②: the log names every host the device talked to, so it is memory-only and
        // must not survive the tunnel. The handle is dropped on stop anyway, but a caller still
        // holding the `Arc` — the UI, a test — must find it empty rather than reading yesterday's
        // browsing history.
        let dir = TempDir::new("log-clear");
        let handle = start_test_engine(&dir, "||ads.example^\n");
        let entry = find_handle(handle).expect("handle");
        entry
            .http_log
            .record_dns("ads.example", "A", crate::http::log::RequestOutcome::Blocked, None);
        entry
            .http_log
            .record_connection("dns.google", crate::http::log::BlockReason::Dot, None)
            .expect("logged");
        assert_eq!(entry.http_log.len(), 2);

        stop_engine(handle);
        assert!(entry.http_log.is_empty(), "the log must not outlive the tunnel");
    }

    // ---- compile / reload through the JNI-level entry points ----

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "zshield-jni-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or_default()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn compile_request_json(dir: &TempDir, list_path: &str, rules: &str) -> String {
        serde_json::json!({
            "lists": [{"id": "test", "path": list_path}],
            "userRules": rules,
            "allowlist": [],
            "outputDir": dir.path("compiled").to_string_lossy(),
        })
        .to_string()
    }

    #[test]
    fn compile_json_reports_stats_and_errors() {
        let dir = TempDir::new("compile-json");
        let list = dir.path("list.txt");
        std::fs::write(&list, "||jni-block.example^\n").expect("write");

        let json = compile_json(&compile_request_json(&dir, &list.to_string_lossy(), ""));
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(value["dnsBlockRules"], 1);
        assert!(value["dnsBytes"].as_u64().unwrap_or(0) > 0);
        assert!(value["engineBytes"].as_u64().unwrap_or(0) > 0);
        assert_eq!(value["lists"][0]["id"], "test");

        let json = compile_json("{not json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert!(value["error"].as_str().unwrap_or_default().contains("compile request"));
    }

    #[test]
    fn compile_json_reports_a_read_failure_as_an_error() {
        let dir = TempDir::new("compile-json-missing");
        let json = compile_json(&compile_request_json(&dir, "/nonexistent/x.txt", ""));
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert!(value["error"].as_str().unwrap_or_default().contains("cannot read list"));
    }

    /// MYS-2716 #1: a tunnel started before the first compile must pick the engine up when the
    /// compile finishes — `httpEngineLoaded` flips to `true` without restarting the tunnel.
    ///
    /// The old code captured `engine.bin` at `start` as a plain `Option`, so a tunnel started before
    /// the artifact existed could never load it: the debug screen said "引擎 未加载" until the user
    /// restarted the VPN. This is the regression test for exactly that state.
    #[test]
    fn the_engine_is_loaded_into_a_running_tunnel_on_the_first_compile() {
        let dir = TempDir::new("first-compile");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||late-block.example^\n").expect("write");
        let compiled = dir.path("compiled");

        // Start with no compiled artifacts at all: this is the state right after a fresh install,
        // when the tunnel comes up while the first compile is still running.
        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        let handle = start_engine(open_dev_null(), &config).expect("engine starts");
        {
            let entry = find_handle(handle).expect("handle");
            assert!(
                !entry.pipelines.has_http(),
                "there is no engine.bin yet, so nothing can be loaded"
            );
            assert!(
                entry.http_filter().is_none(),
                "the plaintext pipeline must be absent before the first compile"
            );
        }
        // `statsJson` is what the debug screen reads, so the assertion is made on it, not on a
        // private field: a user-visible fix has to be user-visible.
        let before: serde_json::Value =
            serde_json::from_str(&stats_json_for_test(handle)).expect("stats json");
        assert_eq!(
            before["httpEngineLoaded"],
            serde_json::json!(false),
            "before the compile the UI must say the engine is not loaded"
        );

        // Now the first compile lands, exactly as `FilterRepository.compileNow` does it.
        let stats_json = compile_json(&compile_request_json(&dir, &list.to_string_lossy(), ""));
        let stats: serde_json::Value = serde_json::from_str(&stats_json).expect("compile stats");
        assert!(stats.get("error").is_none(), "{stats_json}");

        assert!(
            reload_engine(handle, &compiled.to_string_lossy()),
            "reload must succeed: {}",
            take_last_error()
        );

        {
            let entry = find_handle(handle).expect("handle");
            assert!(
                entry.http_filter().is_some(),
                "the engine must now be installed in the running tunnel"
            );
        }
        let after: serde_json::Value =
            serde_json::from_str(&stats_json_for_test(handle)).expect("stats json");
        assert_eq!(
            after["httpEngineLoaded"],
            serde_json::json!(true),
            "after the first compile the tunnel must report a loaded engine, without a restart"
        );

        // And the loaded engine really decides requests: the artifact was not just deserialized and
        // dropped. This is the "明文 HTTP 拦截生效" half of the acceptance criterion.
        let filter = find_handle(handle)
            .expect("handle")
            .http_filter()
            .expect("engine");
        let request = crate::http::head::HttpRequest {
            method: "GET".to_string(),
            target: "/ad.js".to_string(),
            version: crate::http::head::Version::Http11,
            url: "http://late-block.example/ad.js".to_string(),
            host: "late-block.example".to_string(),
            hostname: "late-block.example".to_string(),
            referer: None,
            fetch_dest: None,
            fetch_site: None,
            fetch_user: None,
            accept: None,
            content_length: None,
            chunked: false,
            upgrade: false,
            expect_continue: false,
            head_len: 0,
        };
        assert!(
            filter.decide(&request).block,
            "the engine loaded on the first compile must block what the list blocks"
        );

        stop_engine(handle);
    }

    /// MYS-2716 #1, second half: the HTTPS pipeline depends on the same engine, so it is built at
    /// the same moment. Without this a user whose first compile finished after the tunnel started
    /// would keep relaying 443 verbatim for the rest of the run.
    #[test]
    fn the_https_pipeline_is_installed_by_the_first_compile_too() {
        let _ca = lock_installed_ca();
        // A CA must be installed for the pipeline to be buildable at all.
        let json: serde_json::Value = serde_json::from_str(&generate_ca_json()).expect("json");
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(json["keyPkcs8B64"].as_str().expect("key"))
            .expect("base64");
        assert!(load_ca_material(json["certPem"].as_str().expect("certPem"), &key));

        let dir = TempDir::new("https-first-compile");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||late-block.example^\n").expect("write");
        let compiled = dir.path("compiled");
        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
            "httpsFiltering": true,
            "httpsUids": [10001],
        })
        .to_string();
        let handle = start_engine(open_dev_null(), &config).expect("engine starts");
        assert!(
            !find_handle(handle).expect("handle").pipelines.has_https(),
            "no engine means no pipeline: this is the state the first compile has to fix"
        );

        compile_json(&compile_request_json(&dir, &list.to_string_lossy(), ""));
        assert!(reload_engine(handle, &compiled.to_string_lossy()));

        // On a host build the platform verifier is unavailable, so the pipeline legitimately cannot
        // be built — the assertion is then that the *reason* is that one, not "no engine".
        match find_handle(handle).expect("handle").pipelines.has_https() {
            true => {
                let stats: serde_json::Value =
                    serde_json::from_str(&stats_json_for_test(handle)).expect("stats");
                assert_eq!(stats["httpsFiltering"], serde_json::json!(true));
            }
            false => {
                let reason = take_last_error();
                assert!(
                    reason.contains("platform verifier"),
                    "the only acceptable reason for no pipeline on a host build is the missing \
                     platform verifier, got: {reason}"
                );
            }
        }
        stop_engine(handle);
    }

    /// `statsJson` for a handle, through the same code path the JNI entry point uses.
    fn stats_json_for_test(handle: u64) -> String {
        match find_handle(handle) {
            Some(entry) => entry.stats_json(),
            None => panic!("handle {handle} is not live"),
        }
    }

    /// Starts an engine on a real fd (`/dev/null`) with no upstream traffic; returns its handle.
    fn start_test_engine(dir: &TempDir, rules: &str) -> u64 {
        let list = dir.path("rules.txt");
        std::fs::write(&list, rules).expect("write rules");
        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        start_engine(open_dev_null(), &config).expect("engine starts")
    }

    #[test]
    fn reload_swaps_the_rule_set_and_invalidates_the_cache() {
        let dir = TempDir::new("reload");
        let handle = start_test_engine(&dir, "||old.example^\n");
        {
            let entry = find_handle(handle).expect("handle");
            assert_eq!(
                entry.engine.filter().match_domain("new.example"),
                crate::dns::filter::Verdict::Allow
            );
        }

        // Compile a new rule set into the directory the reload will read.
        let list = dir.path("new-list.txt");
        std::fs::write(&list, "||new.example^\n").expect("write");
        compile_json(&compile_request_json(&dir, &list.to_string_lossy(), ""));

        assert!(reload_engine(handle, &dir.path("compiled").to_string_lossy()));
        {
            let entry = find_handle(handle).expect("handle");
            assert_eq!(
                entry.engine.filter().match_domain("new.example"),
                crate::dns::filter::Verdict::Block,
                "the new rules must be in force after a reload"
            );
            assert_eq!(
                entry.engine.filter().match_domain("old.example"),
                crate::dns::filter::Verdict::Allow,
                "the old rules must be gone"
            );
        }

        // The handle still works and is the only handle: no leak from the swap.
        assert_eq!(
            handles()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|entry| entry.id == handle)
                .count(),
            1
        );
        stop_engine(handle);
        assert!(find_handle(handle).is_none());
        stop_engine(handle);
    }

    #[test]
    fn an_unchanged_artifact_does_not_rebuild_the_rule_sets() {
        // The app compiles on every start, so a reload with identical artifacts is the common case.
        // Rebuilding costs a second 41 MB engine on top of the installed one; the fingerprint is what
        // lets the reload return without doing it. This asserts the *observable* consequence: the
        // engine `Arc` the tunnel hands out is the same allocation before and after.
        let dir = TempDir::new("reload-unchanged");
        let handle = start_test_engine(&dir, "||keep.example^\n");
        let compiled = dir.path("compiled");
        std::fs::create_dir_all(&compiled).expect("mkdir");
        let mut filter = crate::dns::filter::Filter::new();
        filter.load_text("||artifact.example^\n");
        std::fs::write(compiled.join(crate::compiled::DNS_FILE), crate::compiled::encode_dns(&filter))
            .expect("write dns.bin");
        std::fs::write(
            compiled.join(crate::compiled::ENGINE_FILE),
            crate::compiled::Envelope::new(
                crate::compiled::Artifact::Engine,
                adblock::Engine::default().serialize(),
            )
            .encode(),
        )
        .expect("write engine.bin");

        // First reload: the artifacts are new, so the rules really are swapped.
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        let after_first = find_handle(handle).expect("handle");
        assert_eq!(
            after_first.engine.filter().match_domain("artifact.example"),
            crate::dns::filter::Verdict::Block
        );
        let first_engine = after_first.engine.filter();
        let first_http = after_first.http_filter().map(|filter| filter.engine());

        // Second reload with the same files: nothing changes, and the same allocations are still in
        // force (a rebuild would hand out a different `Arc`).
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        let after_second = find_handle(handle).expect("handle");
        assert!(
            std::sync::Arc::ptr_eq(&first_engine, &after_second.engine.filter()),
            "an unchanged dns.bin must not rebuild the DNS filter"
        );
        if let Some(first_http) = first_http {
            let second_http = after_second.http_filter().expect("engine still loaded");
            assert!(
                std::sync::Arc::ptr_eq(&first_http, &second_http.engine()),
                "an unchanged engine.bin must not rebuild the adblock engine"
            );
        }

        // A rewritten artifact is picked up again: the fingerprint must not pin stale rules.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut updated = crate::dns::filter::Filter::new();
        updated.load_text("||rewritten.example^\n");
        std::fs::write(compiled.join(crate::compiled::DNS_FILE), crate::compiled::encode_dns(&updated))
            .expect("rewrite dns.bin");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        let after_third = find_handle(handle).expect("handle");
        assert_eq!(
            after_third.engine.filter().match_domain("rewritten.example"),
            crate::dns::filter::Verdict::Block,
            "a rewritten artifact must be loaded"
        );
        stop_engine(handle);
    }

    #[test]
    fn every_extras_transition_reaches_the_tunnel() {
        // The four states an `extras.txt` can move between, each of which the fingerprint has to tell
        // apart from "unchanged". The rule set is edited in place in the compiled directory, so
        // `dns.bin`/`engine.bin` never move and the extras are the only thing that differs — the
        // compression of the four cases into one test is deliberate: each step's starting state is the
        // previous step's ending state, which is what a real sequence of user edits looks like.
        //
        // 1. first appearance — no extras at all, then rules
        // 2. content change  — a different rule
        // 3. deletion to empty — a compile that finds no modifier rules writes an empty file
        // 4. file removed    — an older artifact set, or a user clearing the directory
        let dir = TempDir::new("extras-transitions");
        let compiled = dir.path("compiled");
        std::fs::create_dir_all(&compiled).expect("mkdir");
        // Start from a directory with **no** `extras.txt` at all — what an artifact set written before
        // this file existed looks like, and the state a user reaches by clearing the compiled
        // directory's extras. The compile always writes one (empty when it found no modifier rules), so
        // step 1 below is what makes it appear.
        compile_rules(&dir, "||plain.test^");
        std::fs::remove_file(compiled.join(crate::compiled::EXTRAS_FILE)).expect("remove extras");

        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let config = serde_json::json!({
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        use std::os::fd::IntoRawFd;
        let handle = start_engine(tun.into_raw_fd(), &config).expect("engine starts");
        let url = "https://shop.test/p?one=1&two=2&three=3";
        assert_eq!(
            rules_state(handle).identities.extras,
            None,
            "no extras.txt in the directory, so the component is absent at start"
        );

        // --- 1. first appearance -------------------------------------------------------------
        compile_rules(&dir, "||shop.test^$xmlhttprequest,removeparam=/^one=/");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?two=2&three=3",
            "a newly added extras rule must apply after the reload"
        );
        let first_identity = rules_state(handle).identities.extras;
        assert!(
            first_identity.is_some(),
            "the rules are in force, so their identity is reported"
        );

        // --- 2. content change ---------------------------------------------------------------
        compile_rules(&dir, "||shop.test^$xmlhttprequest,removeparam=/^two=/");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?one=1&three=3",
            "the replaced rule must be the one in force"
        );
        assert_ne!(
            rules_state(handle).identities.extras,
            first_identity,
            "different rules, different identity"
        );

        // --- 3. emptied -----------------------------------------------------------------------
        // A compile with no `$removeparam`/`$popup`/`$denyallow` rule writes an empty `extras.txt`
        // rather than none: "the user deleted their rules" has to be installable.
        compile_rules(&dir, "||shop.test^");
        let emptied = extras_payload(&dir).expect("an empty extras.txt is still a file");
        assert!(emptied.is_empty(), "the compile wrote no rules: {emptied:?}");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            url,
            "with no rule in force nothing is removed"
        );
        let empty_identity = rules_state(handle)
            .identities
            .extras
            .expect("an empty extras.txt is a loaded artifact, so it has an identity");
        assert_eq!(empty_identity.bytes, 0, "and the identity describes zero bytes");

        // --- 4. file removed ------------------------------------------------------------------
        std::fs::remove_file(compiled.join(crate::compiled::EXTRAS_FILE)).expect("remove extras");
        compile_rules(&dir, "||shop.test^$xmlhttprequest,removeparam=/^three=/");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?one=1&two=2",
            "a re-added file must be loaded"
        );
        std::fs::remove_file(compiled.join(crate::compiled::EXTRAS_FILE)).expect("remove extras");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            rules_state(handle).identities.extras,
            None,
            "a deleted file is reported as an absent component"
        );
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            url,
            "a deleted file leaves no modifier in force"
        );
        stop_engine(handle);
    }

    #[test]
    fn a_corrupt_extras_keeps_the_rules_in_force_and_is_retried() {
        // The failure semantics this task had to fix. Before, an unusable `extras.txt` installed the
        // empty set and the reload still recorded the new fingerprint — so the modifiers the user had
        // were silently deleted, and the corruption was never retried because the next compile wrote
        // the same artifacts and the fingerprint matched.
        //
        // Now: nothing is installed, the rules already in force keep deciding, the swap is reported
        // with `ok=false`, no fingerprint is recorded, and rewriting the file makes the next reload
        // pick it up.
        let dir = TempDir::new("extras-corrupt");
        let compiled = dir.path("compiled");
        compile_rules(&dir, "||shop.test^$xmlhttprequest,removeparam=keep");
        let good = extras_payload(&dir).expect("extras.txt exists");
        let url = "https://shop.test/p?keep=1&stay=2";

        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let config = serde_json::json!({
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        use std::os::fd::IntoRawFd;
        let handle = start_engine(tun.into_raw_fd(), &config).expect("engine starts");
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?stay=2"
        );
        let identity_before = rules_state(handle).identities.extras.expect("extras identity");
        let generation_before = rules_state(handle).generation;

        // Corrupt the artifact, leaving `dns.bin`/`engine.bin` untouched, so the only thing that
        // differs from the loaded set is the file that cannot be read.
        std::fs::write(
            compiled.join(crate::compiled::EXTRAS_FILE),
            b"ZSEXT\0\0\x01 not a real envelope",
        )
        .expect("corrupt extras.txt");

        let reloaded = reload_engine(handle, &compiled.to_string_lossy());
        // The DNS and engine halves really were identical, but the swap is still a failure: the file
        // the tunnel was asked to install could not be installed. Reporting `true` here is exactly
        // "return true while nothing was applied", which the task card forbids.
        assert!(
            !reloaded,
            "a reload that could not install the modifiers must not report success"
        );
        // The reason is deliberately not asserted through `lastError()`: that slot is process-global
        // and every test running in parallel writes it, so a string assertion here would be flaky
        // for a reason that has nothing to do with this behaviour. The failure is asserted through
        // what it *did* — the identity and generation below — and logged as the `ok=false` swap
        // event, which is what the readiness tooling reads.

        // The rules the user had are still deciding: a checksum failure must not silently delete them.
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?stay=2",
            "the modifiers in force must survive a corrupt artifact"
        );
        let state = rules_state(handle);
        assert_eq!(
            state.identities.extras,
            Some(identity_before),
            "the identity still describes the rules in force"
        );
        assert_eq!(
            state.generation, generation_before,
            "a failed swap advances no generation"
        );

        // The retry: with the bytes the tunnel was asked for written back, the *same* call now
        // succeeds without any other artifact changing. This is what the old code could not do — it
        // had already recorded the corrupt set as loaded and would have skipped here.
        //
        // The envelope is rebuilt around the payload the compile produced, so the rules the retry
        // parses are the same rules, not a hand-written approximation.
        let repaired =
            crate::compiled::Envelope::new(crate::compiled::Artifact::Extras, good).encode();
        std::fs::write(compiled.join(crate::compiled::EXTRAS_FILE), repaired)
            .expect("restore extras.txt");
        assert!(
            reload_engine(handle, &compiled.to_string_lossy()),
            "the retry must succeed once the artifact is readable again"
        );
        assert!(
            rules_state(handle).generation > generation_before,
            "and a successful retry does advance the generation"
        );
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?stay=2"
        );
        stop_engine(handle);
    }

    #[test]
    fn extras_that_are_not_utf8_are_not_a_loadable_fingerprint() {
        // A subtle half of the same bug: the skip-fast path and the loader must agree on what counts
        // as a usable `extras.txt`. The file can decode as an envelope (right magic, right length,
        // matching CRC) and still be unusable, because its payload is not text. If the fingerprint
        // accepted it, a reload would match, skip, and report success while the loader would refuse
        // the same bytes — the two answering "usable" differently.
        let dir = TempDir::new("extras-not-utf8");
        let compiled = dir.path("compiled");
        compile_rules(&dir, "||shop.test^$xmlhttprequest,removeparam=/^keep=/");
        let url = "https://shop.test/p?keep=1&stay=2";

        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let config = serde_json::json!({
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        use std::os::fd::IntoRawFd;
        let handle = start_engine(tun.into_raw_fd(), &config).expect("engine starts");
        let identity_before = rules_state(handle).identities.extras.expect("extras identity");
        let generation_before = rules_state(handle).generation;

        // A well-formed envelope whose payload is invalid UTF-8.
        let binary = crate::compiled::Envelope::new(
            crate::compiled::Artifact::Extras,
            vec![0xff, 0xfe, 0x00, 0xba],
        )
        .encode();
        std::fs::write(compiled.join(crate::compiled::EXTRAS_FILE), binary)
            .expect("write binary extras.txt");
        assert!(
            !reload_engine(handle, &compiled.to_string_lossy()),
            "an artifact the loader cannot parse is not a successful reload"
        );
        let state = rules_state(handle);
        assert_eq!(
            state.identities.extras,
            Some(identity_before),
            "the rules in force did not change"
        );
        assert_eq!(state.generation, generation_before, "and no generation advanced");
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?stay=2",
            "the previous modifier must keep deciding"
        );

        // Rewriting the *same* file with valid text is picked up, which is the retry the old code
        // would have skipped.
        let text = crate::compiled::Envelope::new(
            crate::compiled::Artifact::Extras,
            b"||shop.test^$xmlhttprequest,removeparam=/^stay=/\n".to_vec(),
        )
        .encode();
        std::fs::write(compiled.join(crate::compiled::EXTRAS_FILE), text).expect("rewrite");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            removeparam_result(
                &find_handle(handle).expect("handle").http_filter().expect("engine"),
                url
            ),
            "https://shop.test/p?keep=1",
            "the rewritten rule must be the one in force"
        );
        stop_engine(handle);
    }

    #[test]
    fn all_three_unchanged_artifacts_keep_the_same_rule_objects() {
        // The fast path has to survive the fix. Covering `extras.txt` in the fingerprint could easily
        // have been done by hashing it on every reload and comparing hashes — which would still be a
        // fast path, but one that rebuilds when the *text* differs while the *rules* do not. This
        // asserts the observable consequence instead: a reload with all three artifacts byte-identical
        // hands out the same allocations, including the modifier `Arc`.
        //
        // It is the existing `an_unchanged_artifact_does_not_rebuild_the_rule_sets` case with the third
        // artifact present, because that test's directory has no `extras.txt` at all — and the bug this
        // task fixes was invisible precisely when extras *did* exist.
        let dir = TempDir::new("reload-unchanged-extras");
        compile_rules(&dir, "||example.test^$xmlhttprequest,removeparam=/^old=/");
        let compiled = dir.path("compiled");

        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let config = serde_json::json!({
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        use std::os::fd::IntoRawFd;
        let handle = start_engine(tun.into_raw_fd(), &config).expect("engine starts");

        let before = {
            let entry = find_handle(handle).expect("handle");
            (
                entry.engine.filter(),
                entry
                    .http_filter()
                    .map(|filter| (filter.engine(), filter.extras())),
            )
        };
        let generation_before = rules_state(handle).generation;

        // Twenty unchanged reloads: the common case is the app compiling on every start.
        for round in 0..20 {
            assert!(reload_engine(handle, &compiled.to_string_lossy()), "round {round}");
            let after = find_handle(handle).expect("handle");
            assert!(
                Arc::ptr_eq(&before.0, &after.engine.filter()),
                "round {round}: an unchanged dns.bin must not rebuild the DNS filter"
            );
            let (http_before, extras_before) = before.1.as_ref().expect("engine loaded");
            let http_after = after.http_filter().expect("engine still loaded");
            assert!(
                Arc::ptr_eq(http_before, &http_after.engine()),
                "round {round}: an unchanged engine.bin must not rebuild the adblock engine"
            );
            assert!(
                Arc::ptr_eq(extras_before, &http_after.extras()),
                "round {round}: an unchanged extras.txt must not rebuild the modifier rule sets"
            );
        }
        assert_eq!(
            rules_state(handle).generation,
            generation_before,
            "a skipped reload installs nothing, so it advances no generation"
        );

        // And the fast path is not a pin: changing only `extras.txt` still gets through.
        compile_rules(&dir, "||example.test^$xmlhttprequest,removeparam=/^new=/");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        let entry = find_handle(handle).expect("handle");
        let filter = entry.http_filter().expect("engine loaded");
        assert_eq!(
            removeparam_result(&filter, "https://example.test/p?old=1&new=2&keep=3"),
            "https://example.test/p?old=1&keep=3",
            "the twenty skipped reloads must not leave the old modifiers in force"
        );
        assert!(
            rules_state(handle).generation > generation_before,
            "the real swap advances the generation"
        );
        stop_engine(handle);
    }

    #[test]
    fn reload_failures_keep_the_old_filter() {        let dir = TempDir::new("reload-fail");
        let handle = start_test_engine(&dir, "||keep.example^\n");

        // Unknown handle.
        assert!(!reload_engine(999_999, &dir.path("compiled").to_string_lossy()));
        assert!(take_last_error().contains("unknown handle"));

        // Empty and missing directories.
        assert!(!reload_engine(handle, "  "));
        assert!(take_last_error().contains("compiledDir"));
        assert!(!reload_engine(handle, &dir.path("nope").to_string_lossy()));
        assert!(take_last_error().contains("no compiled rules"));

        // A corrupt artifact.
        std::fs::create_dir_all(dir.path("broken")).expect("mkdir");
        std::fs::write(
            dir.path("broken").join(crate::compiled::DNS_FILE),
            b"not an artifact at all",
        )
        .expect("write");
        assert!(!reload_engine(handle, &dir.path("broken").to_string_lossy()));
        // `decode` reports "bad magic (not a ZShield artifact)" — the point is that the failure is
        // surfaced, not that it uses a particular word.
        assert!(
            !take_last_error().is_empty(),
            "a corrupt artifact must be reported through lastError"
        );

        // Through all of that, the original filter is still in force.
        let entry = find_handle(handle).expect("handle");
        assert_eq!(
            entry.engine.filter().match_domain("keep.example"),
            crate::dns::filter::Verdict::Block
        );
        stop_engine(handle);
    }

    #[test]
    fn start_prefers_compiled_rules_over_rule_files() {
        let dir = TempDir::new("start-compiled");
        // A rule file that would block a different name, so it is obvious which one won.
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||from-text.example^\n").expect("write");
        let compile_list = dir.path("compile.txt");
        std::fs::write(&compile_list, "||from-artifact.example^\n").expect("write");
        compile_json(&compile_request_json(&dir, &compile_list.to_string_lossy(), ""));

        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "compiledDir": dir.path("compiled").to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        let handle = start_engine(open_dev_null(), &config).expect("engine starts");
        let entry = find_handle(handle).expect("handle");
        assert_eq!(
            entry.engine.filter().match_domain("from-artifact.example"),
            crate::dns::filter::Verdict::Block
        );
        assert_eq!(
            entry.engine.filter().match_domain("from-text.example"),
            crate::dns::filter::Verdict::Allow,
            "the precompiled artifact must take precedence over rule text"
        );
        stop_engine(handle);
    }

    /// `ipv6` must reach the engine through the real `start` path, not only through `Config`.
    /// A regression here would silently restore the MYS-2710 outage: the tunnel would carry no
    /// IPv6 while the DNS engine still handed out AAAA records.
    #[test]
    fn start_passes_the_ipv6_flag_to_the_dns_engine() {
        let base = serde_json::json!({
            "ruleFiles": [],
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        });
        for (ipv6, expected) in [(false, false), (true, true)] {
            let mut config = base.clone();
            config["ipv6"] = serde_json::Value::Bool(ipv6);
            let handle =
                start_engine(open_dev_null(), &config.to_string()).expect("engine starts");
            let entry = find_handle(handle).expect("handle");
            assert_eq!(entry.engine.ipv6_enabled(), expected, "ipv6={ipv6}");
            stop_engine(handle);
        }

        // Omitting the field keeps the M2a behaviour (IPv6 on), so an older control plane cannot
        // accidentally disable IPv6.
        let handle = start_engine(open_dev_null(), &base.to_string()).expect("engine starts");
        let entry = find_handle(handle).expect("handle");
        assert!(entry.engine.ipv6_enabled());
        stop_engine(handle);
    }

    #[test]
    fn start_falls_back_to_rule_files_when_the_artifact_is_stale() {
        let dir = TempDir::new("start-stale");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||from-text.example^\n").expect("write");
        let compile_list = dir.path("compile.txt");
        std::fs::write(&compile_list, "||from-artifact.example^\n").expect("write");
        compile_json(&compile_request_json(&dir, &compile_list.to_string_lossy(), ""));

        // Bump the version byte so the artifact is rejected.
        let artifact = dir.path("compiled").join(crate::compiled::DNS_FILE);
        let mut raw = std::fs::read(&artifact).expect("read");
        raw[8] = raw[8].wrapping_add(9);
        std::fs::write(&artifact, raw).expect("write");

        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "compiledDir": dir.path("compiled").to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        let handle = start_engine(open_dev_null(), &config).expect("engine starts");
        let entry = find_handle(handle).expect("handle");
        assert_eq!(
            entry.engine.filter().match_domain("from-text.example"),
            crate::dns::filter::Verdict::Block,
            "a stale artifact must fall back to rule text, not silently disable filtering"
        );
        // The reason must be reportable so Kotlin can trigger a recompile. Checked directly rather
        // than through `lastError()`, which is process-global and shared with the other tests.
        let err = crate::compile::load_dns_filter(&dir.path("compiled"))
            .expect_err("a stale artifact must not load");
        assert!(err.contains("recompile"), "{err}");
        stop_engine(handle);
    }
    // ---- M3a: the HTTPS entry points ----

    #[test]
    fn generate_ca_returns_a_usable_certificate_and_key() {
        let json = generate_ca_json();
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert!(value.get("error").is_none(), "{json}");

        let cert_pem = value["certPem"].as_str().expect("certPem");
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        let fingerprint = value["fingerprintSha256"].as_str().expect("fingerprint");
        assert_eq!(fingerprint.len(), 64);
        assert!(value["notAfterMs"].as_i64().unwrap_or(0) > 0);

        // The key is base64 PKCS#8 and really loads back into a CA.
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(value["keyPkcs8B64"].as_str().expect("key"))
            .expect("base64");
        let ca = crate::https::ca::load(cert_pem, &crate::https::ca::CaKey::from_pkcs8_der(key))
            .expect("the generated material loads");
        assert_eq!(ca.info().fingerprint_sha256, fingerprint);
    }

    #[test]
    fn load_ca_installs_the_root_and_rejects_bad_material() {
        // The installed CA is process-wide, so this test owns it for its whole body.
        let _ca = lock_installed_ca();
        let json: serde_json::Value = serde_json::from_str(&generate_ca_json()).expect("json");
        use base64::Engine as _;
        let cert_pem = json["certPem"].as_str().expect("certPem");
        let key = base64::engine::general_purpose::STANDARD
            .decode(json["keyPkcs8B64"].as_str().expect("key"))
            .expect("base64");

        assert!(load_ca_material(cert_pem, &key));
        let installed = current_ca().expect("a CA is installed");
        assert_eq!(
            installed.info().fingerprint_sha256,
            json["fingerprintSha256"].as_str().expect("fingerprint")
        );

        // A PEM that is not a certificate, and a key that is not PKCS#8: both are refused, and the
        // previously installed CA stays in force (a tunnel with the old CA still filters).
        assert!(!load_ca_material("not a certificate", &key));
        assert!(take_last_error().contains("loadCa"));
        assert!(!load_ca_material(cert_pem, b"not a key"));
        assert_eq!(
            current_ca().expect("still installed").info().fingerprint_sha256,
            json["fingerprintSha256"].as_str().expect("fingerprint")
        );
    }

    #[test]
    fn the_https_pipeline_is_not_built_without_its_prerequisites() {
        // The installed CA is process-wide, so this test owns it for its whole body.
        let _ca = lock_installed_ca();
        let dir = TempDir::new("https-prereq");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||ads.example^
").expect("write");

        // 1. Filtering off: no pipeline, and no error (this is the default state).
        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
            "compiledDir": dir.path("compiled").to_string_lossy(),
        })
        .to_string();
        let config = Config::from_json(&config).expect("valid");
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list("||ads.example^".to_string(), adblock::lists::ParseOptions::default());
        let filter = Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set)));
        let log = Arc::new(RequestLog::new());
        let stats = Arc::new(HttpStats::default());
        let context = HttpContext {
            cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
            framing: crate::cosmetic::OutFraming::Chunked,
            filter: filter.clone(),
            log,
            stats,
            head_limit: 8 * 1024,
            scheme: crate::http::head::Scheme::Http,
            modifiers: None,
        };
        let removeheader = Arc::new(crate::https::modifiers::collect_removeheader(
            std::iter::empty(),
        ));
        assert!(matches!(
            build_https_pipeline_inner(&config, Some(&filter), Some(&context), &removeheader),
            PipelineOutcome::Off
        ));

        // 2. Filtering on but no CA installed: reported through lastError, still not fatal.
        *installed_ca().lock().unwrap_or_else(|e| e.into_inner()) = None;
        let config = Config::from_json(
            &serde_json::json!({
                "ruleFiles": [list.to_string_lossy()],
                "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
                "httpsFiltering": true,
                "httpsUids": [10001],
            })
            .to_string(),
        )
        .expect("valid");
        match build_https_pipeline_inner(&config, Some(&filter), Some(&context), &removeheader) {
            PipelineOutcome::Unavailable(reason) => {
                assert!(reason.contains("loadCa"), "the reason must name the missing CA: {reason}")
            }
            PipelineOutcome::Built(_) => panic!("a pipeline must not be built without a CA"),
            PipelineOutcome::Off => panic!("filtering was requested, so it cannot be off"),
        }
    }

    #[test]
    fn the_https_pipeline_is_built_when_everything_is_present() {
        // The installed CA is process-wide, so this test owns it for its whole body.
        let _ca = lock_installed_ca();
        // A CA for the process (the test above may have cleared it).
        let json: serde_json::Value = serde_json::from_str(&generate_ca_json()).expect("json");
        use base64::Engine as _;
        let key = base64::engine::general_purpose::STANDARD
            .decode(json["keyPkcs8B64"].as_str().expect("key"))
            .expect("base64");
        assert!(load_ca_material(json["certPem"].as_str().expect("certPem"), &key));

        let dir = TempDir::new("https-built");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||ads.example^
").expect("write");
        let config = Config::from_json(
            &serde_json::json!({
                "ruleFiles": [list.to_string_lossy()],
                "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
                "httpsFiltering": true,
                "httpsUids": [10001, 10002],
                "httpsExcludedHosts": ["bank.example"],
            })
            .to_string(),
        )
        .expect("valid");
        let mut set = adblock::lists::FilterSet::new(false);
        set.add_filter_list("||ads.example^".to_string(), adblock::lists::ParseOptions::default());
        let filter = Arc::new(HttpFilter::new(adblock::Engine::new_with_filter_set(set)));
        let context = HttpContext {
            cosmetic: Arc::new(crate::cosmetic::CosmeticStats::default()),
            framing: crate::cosmetic::OutFraming::Chunked,
            filter: filter.clone(),
            log: Arc::new(RequestLog::new()),
            stats: Arc::new(HttpStats::default()),
            head_limit: 8 * 1024,
            scheme: crate::http::head::Scheme::Http,
            modifiers: None,
        };
        let removeheader = Arc::new(crate::https::modifiers::collect_removeheader(
            std::iter::empty(),
        ));

        // The upstream config needs the platform verifier, which only exists on Android; a host
        // build therefore reports the reason instead of building one. Both answers are correct, and
        // the test accepts either — what must never happen is a pipeline that trusts everything.
        match build_https_pipeline_inner(&config, Some(&filter), Some(&context), &removeheader) {
            PipelineOutcome::Built(pipeline) => {
                let policy = pipeline.policy();
                assert!(policy.enabled);
                assert_eq!(policy.uids, vec![10001, 10002]);
                assert_eq!(policy.excluded_hosts, vec!["bank.example".to_string()]);
                assert_eq!(pipeline.policy().uids, vec![10001, 10002]);
                assert!(pipeline.context.http.modifiers.is_some());
            }
            PipelineOutcome::Unavailable(reason) => {
                assert!(
                    reason.contains("platform verifier"),
                    "a missing platform verifier is the only reason a host build may refuse: {reason}"
                );
            }
            PipelineOutcome::Off => panic!("filtering was requested"),
        }
    }

    #[test]
    fn the_bypass_json_reports_the_table_and_unknown_handles() {
        assert_eq!(https_bypass_json_for(999_999), "[]");
        assert!(take_last_error().contains("unknown handle"));

        let dir = TempDir::new("bypass-json");
        let handle = start_test_engine(&dir, "||ads.example^
");
        // No HTTPS pipeline: an empty array, not an error.
        assert_eq!(https_bypass_json_for(handle), "[]");
        stop_engine(handle);
    }

    #[test]
    fn updating_the_https_policy_needs_a_running_pipeline() {
        let dir = TempDir::new("https-policy");
        let handle = start_test_engine(&dir, "||ads.example^
");
        assert_eq!(https_bypass_json_for(handle), "[]");

        // No pipeline on this handle: refused and reported, rather than silently accepted.
        assert!(!update_https_policy_for(handle, r#"{"enabled":true,"uids":[1]}"#));
        assert!(take_last_error().contains("not running"));
        assert!(!update_https_policy_for(999_999, "{}"));
        assert!(take_last_error().contains("unknown handle"));
        stop_engine(handle);
    }

    // ---- the rule-generation observation (MYS-2825) -------------------------------------------

    /// The state a consumer reads: which generation is in force, and of what content.
    fn rules_state(handle: u64) -> crate::rules_identity::RulesState {
        find_handle(handle)
            .expect("handle")
            .rules
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Start a handle over a *real* compiled artifact set, so the identity is a real hash of real
    /// payload bytes rather than a value the test wrote into a struct.
    fn start_compiled_engine(dir: &TempDir, rules: &str) -> u64 {
        let list = dir.path("rules.txt");
        std::fs::write(&list, rules).expect("write rules");
        let compiled = dir.path("compiled");
        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        let stats = compile_json(&compile_request_json(dir, &list.to_string_lossy(), ""));
        let value: serde_json::Value = serde_json::from_str(&stats).expect("compile stats");
        assert!(value.get("error").is_none(), "{stats}");
        // A start that finds no artifact would report every component absent; the caller wants the
        // artifact path, so the compile has to have produced one first.
        start_engine(open_dev_null(), &config).expect("engine starts")
    }

    #[test]
    fn a_start_records_the_content_it_installed() {
        let dir = TempDir::new("identity-start");
        let handle = start_compiled_engine(&dir, "||ads.example^\n");
        let state = rules_state(handle);
        assert!(state.generation > 0, "a successful start must install generation 1 or later");
        let dns = state.identities.dns.expect("dns.bin was loaded, so it has an identity");
        let engine = state
            .identities
            .engine
            .expect("engine.bin was loaded, so it has an identity");
        // The identity is a hash of the payload the loader read — not of the file, which also carries a
        // 20-byte envelope header, and not of the path or the size.
        let payload = crate::compiled::Envelope::read_payload(
            &dir.path("compiled").join(crate::compiled::DNS_FILE),
            crate::compiled::Artifact::Dns,
        )
        .expect("read dns payload");
        assert_eq!(dns, crate::compiled::PayloadIdentity::of_payload(&payload));
        assert_eq!(dns.bytes, payload.len() as u64);
        assert!(engine.bytes > 0);
        assert_eq!(dns.sha256_hex.len(), 64);
        stop_engine(handle);
    }

    #[test]
    fn equal_length_rule_sets_get_different_identities() {
        // The stage-4 review's counter-example, on the real compile: two lists of the same length and
        // the same rule count, different rules. A size or a count cannot tell them apart; the
        // identity must.
        let a = TempDir::new("identity-same-len-a");
        let b = TempDir::new("identity-same-len-b");
        let rules_a = "||ads.example^\n";
        let rules_b = "||cms.example^\n";
        assert_eq!(rules_a.len(), rules_b.len());
        let handle_a = start_compiled_engine(&a, rules_a);
        let handle_b = start_compiled_engine(&b, rules_b);
        let state_a = rules_state(handle_a);
        let state_b = rules_state(handle_b);
        let engine_a = state_a.identities.engine.expect("engine");
        let engine_b = state_b.identities.engine.expect("engine");
        assert_ne!(
            engine_a.sha256_hex, engine_b.sha256_hex,
            "different rules of the same length must not share an identity"
        );
        // The DNS artifact carries the rule counts, so this is the "same count" half of the premise.
        assert_eq!(
            crate::compile::load_dns_filter(&a.path("compiled"))
                .expect("load")
                .expect("artifact")
                .stats()
                .block_rules,
            crate::compile::load_dns_filter(&b.path("compiled"))
                .expect("load")
                .expect("artifact")
                .stats()
                .block_rules,
            "the two rule sets must really have the same rule count for this test to mean anything"
        );
        stop_engine(handle_a);
        stop_engine(handle_b);
    }

    #[test]
    fn a_successful_swap_advances_the_generation_and_a_failed_one_does_not() {
        let dir = TempDir::new("identity-swap");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||first.example^\n").expect("write");
        let handle = start_compiled_engine(&dir, "||first.example^\n");
        let started = rules_state(handle);
        let first_engine = started.identities.engine.clone().expect("engine");

        // A real swap: write a different list, compile, reload.
        std::fs::write(&list, "||second.example^\n").expect("write");
        compile_json(&compile_request_json(&dir, &list.to_string_lossy(), ""));
        assert!(reload_engine(handle, &dir.path("compiled").to_string_lossy()));
        let swapped = rules_state(handle);
        assert!(
            swapped.generation > started.generation,
            "a successful swap must advance the generation"
        );
        let second_engine = swapped.identities.engine.clone().expect("engine");
        assert_ne!(
            first_engine.sha256_hex, second_engine.sha256_hex,
            "the swap installed different rules, so the identity must differ"
        );

        // A reload that cannot install anything: the artifacts are gone. The generation must not move,
        // and the identity in force must still describe what is really deciding requests.
        std::fs::remove_dir_all(dir.path("compiled")).expect("remove artifacts");
        assert!(!reload_engine(handle, &dir.path("compiled").to_string_lossy()));
        let failed = rules_state(handle);
        assert_eq!(
            failed.generation, swapped.generation,
            "a failed reload must not advance the generation"
        );
        assert_eq!(
            failed.identities, swapped.identities,
            "a failed reload leaves the previous rule set in force, so the identity must not change"
        );
        stop_engine(handle);
    }

    #[test]
    fn a_partial_swap_is_reported_as_the_mixture_it_is() {
        // The DNS artifact swaps and the engine one does not: the tunnel then decides hostnames with
        // one rule set and URLs with another. That is a real state (the engine swap can fail on its
        // own), and the observation has to show it rather than a clean-looking single identity.
        let dir = TempDir::new("identity-partial");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||first.example^\n").expect("write");
        let handle = start_compiled_engine(&dir, "||first.example^\n");
        let before = rules_state(handle);

        // New DNS rules, but an engine artifact this build cannot use.
        std::fs::write(&list, "||second.example^\n").expect("write");
        let compiled = dir.path("compiled");
        let mut new_filter = crate::dns::filter::Filter::new();
        new_filter.load_text("||second.example^\n||third.example^\n");
        std::fs::write(
            compiled.join(crate::compiled::DNS_FILE),
            crate::compiled::encode_dns(&new_filter),
        )
        .expect("write dns.bin");
        std::fs::write(compiled.join(crate::compiled::ENGINE_FILE), b"not an artifact")
            .expect("write engine.bin");

        // `reload_engine` returns false: the rule set in force is not the one that was compiled, and
        // `false` is what `docs/JNI.md` promises for a failed reload. It used to return true here, on
        // the reading that "the DNS half happened" — but the Kotlin caller turns `true` into "hot
        // reload finished" and shows the user their new rules, which is exactly the misreport
        // MYS-2859 is about. The DNS half really did swap, and the identity/generation below are how
        // that partial state is described.
        let reloaded = reload_engine(handle, &compiled.to_string_lossy());
        let after = rules_state(handle);
        assert!(
            !reloaded,
            "a swap that could not install every component is not a successful reload"
        );
        assert_ne!(
            before.identities.dns, after.identities.dns,
            "the DNS rules were replaced, so their identity must change"
        );
        assert_eq!(
            before.identities.engine, after.identities.engine,
            "the engine could not be replaced, so it still runs the previous rules"
        );
        assert_eq!(
            after.generation, before.generation,
            "a swap that left the rule set inconsistent is not a successful generation"
        );
        stop_engine(handle);
    }

    #[test]
    fn a_tunnel_started_without_an_artifact_reports_absent_components() {
        // A fresh install: the tunnel comes up before the first compile. Reporting a made-up identity
        // here would let a run claim it measured a rule set that does not exist yet.
        let dir = TempDir::new("identity-absent");
        let list = dir.path("rules.txt");
        std::fs::write(&list, "||ads.example^\n").expect("write");
        let config = serde_json::json!({
            "ruleFiles": [list.to_string_lossy()],
            "compiledDir": dir.path("compiled").to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        let handle = start_engine(open_dev_null(), &config).expect("engine starts");
        let state = rules_state(handle);
        assert!(state.generation > 0, "the start itself succeeded");
        assert_eq!(state.identities.dns, None, "no dns.bin exists yet");
        assert_eq!(state.identities.engine, None, "no engine.bin exists yet");
        assert_eq!(state.identities.extras, None, "no extras.txt exists yet");
        stop_engine(handle);
    }

    // ---- MYS-2859: an extras-only change must reload ----

    /// Compile `rules` into `dir`'s `compiled/`, the way the Kotlin repository does.
    ///
    /// Returns the statistics so a test can assert what the compile actually produced; a failure here
    /// is the test's own setup failing, never the behaviour under test.
    fn compile_rules(dir: &TempDir, rules: &str) -> serde_json::Value {
        let stats = compile_json(&serde_json::json!({
            "lists": [],
            "userRules": rules,
            "outputDir": dir.path("compiled").to_string_lossy(),
        })
        .to_string());
        let value: serde_json::Value = serde_json::from_str(&stats).expect("compile stats");
        assert!(value.get("error").is_none(), "compile failed: {stats}");
        value
    }

    /// `extras.txt` as the loader would read it, or `None` when the file is not there.
    fn extras_payload(dir: &TempDir) -> Option<Vec<u8>> {
        crate::compiled::Envelope::read(
            &dir.path("compiled").join(crate::compiled::EXTRAS_FILE),
            crate::compiled::Artifact::Extras,
        )
        .ok()
        .map(|envelope| envelope.payload)
    }

    /// A GET for `url`, as the decrypted pipeline builds one.
    fn decrypted_request(url: &str) -> crate::http::head::HttpRequest {
        let authority = url
            .split("//")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .expect("absolute url");
        crate::http::head::HttpRequest {
            method: "GET".into(),
            target: format!("/{}", url.splitn(4, '/').nth(3).unwrap_or("")),
            version: crate::http::head::Version::Http11,
            url: url.into(),
            host: authority.into(),
            hostname: authority.split(':').next().unwrap_or(authority).into(),
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
        }
    }

    /// What the request's `$removeparam` rules leave of `url`, through the production evaluation path.
    ///
    /// `HttpsModifiers::edits` is exactly what the HTTP/1.1 and HTTP/2 relays call, and it reads the
    /// modifier sets **live** from the filter, so this observes the rule content in force rather than
    /// a snapshot. That is the point: the reload's job is to make the live set the new one.
    fn removeparam_result(
        filter: &Arc<HttpFilter>,
        url: &str,
    ) -> String {
        let modifiers = crate::https::modifiers::HttpsModifiers::new(
            filter.clone(),
            Arc::new(crate::https::modifiers::collect_removeheader(
                std::iter::empty(),
            )),
            filter.extras_arc(),
        );
        let request = decrypted_request(url);
        use crate::http::rewrite::ModifierSource;
        modifiers
            .edits(&request, crate::http::resource::RequestKind::Xhr)
            .and_then(|edits| edits.url)
            .unwrap_or_else(|| url.to_string())
    }

    #[test]
    fn an_extras_only_change_is_reloaded_through_the_production_path() {
        // The regression this whole task exists for (MYS-2859). A `$removeparam` rule lives in
        // `extras.txt` and in nothing else, so editing one rewrites that file and leaves `dns.bin`
        // and `engine.bin` byte-identical. The old `ArtifactFingerprint` covered the latter two only,
        // matched, and the reload returned "artifacts unchanged, keeping the loaded rule sets" — the
        // new parameter was never removed for the life of the tunnel.
        //
        // Everything here is the production path: `compile_request` writes the artifacts,
        // `start_engine` loads them into a real handle (over a `UnixDatagram` pair, a descriptor the
        // tokio reactor can register like a TUN fd), and `reload_engine` swaps them into that handle.
        let dir = TempDir::new("extras-only-reload");
        let compiled = dir.path("compiled");
        let old_rule = "||example.test^$xmlhttprequest,removeparam=/^old=/";
        let new_rule = "||example.test^$xmlhttprequest,removeparam=/^new=/";
        compile_rules(&dir, old_rule);

        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let config = serde_json::json!({
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        use std::os::fd::IntoRawFd;
        let handle = start_engine(tun.into_raw_fd(), &config).expect("engine starts over a real fd");

        let entry = find_handle(handle).expect("handle");
        let filter = entry.http_filter().expect("engine.bin was loaded");
        let url = "https://example.test/p?old=1&new=2&keep=3";
        // The starting rule removes `old` and leaves `new` — asserted, not assumed, so the test cannot
        // pass because both rules happened to behave the same.
        assert_eq!(
            removeparam_result(&filter, url),
            "https://example.test/p?new=2&keep=3",
            "the first compile's rule must be the one in force at start"
        );
        let dns_before = std::fs::read(compiled.join(crate::compiled::DNS_FILE)).expect("dns.bin");
        let engine_before =
            std::fs::read(compiled.join(crate::compiled::ENGINE_FILE)).expect("engine.bin");
        let extras_before = extras_payload(&dir).expect("extras.txt exists after the first compile");
        let identity_before = rules_state(handle).identities.extras.expect("extras identity");
        let generation_before = rules_state(handle).generation;

        // Only the parameter name changes: same anchor, same options, same list — so the DNS filter
        // and the engine see the same rules and serialize to the same bytes.
        compile_rules(&dir, new_rule);
        assert_eq!(
            std::fs::read(compiled.join(crate::compiled::DNS_FILE)).expect("dns.bin"),
            dns_before,
            "this case is only about extras, so dns.bin must be byte-identical"
        );
        assert_eq!(
            std::fs::read(compiled.join(crate::compiled::ENGINE_FILE)).expect("engine.bin"),
            engine_before,
            "this case is only about extras, so engine.bin must be byte-identical"
        );
        let extras_after = extras_payload(&dir).expect("extras.txt exists after the second compile");
        assert_ne!(
            extras_after, extras_before,
            "the point of the case: extras.txt really did change"
        );

        assert!(
            reload_engine(handle, &compiled.to_string_lossy()),
            "the reload must report success"
        );

        // The new rule is the one deciding now, through the same evaluation path a real request takes.
        let entry = find_handle(handle).expect("handle");
        let filter = entry.http_filter().expect("engine still loaded");
        assert_eq!(
            removeparam_result(&filter, url),
            "https://example.test/p?old=1&keep=3",
            "an extras-only edit must reach the tunnel: the new rule removes `new`, the old one `old`"
        );
        // And the observation says so: a new extras identity and a new generation, not the old pair
        // kept alive by a skipped reload.
        let state = rules_state(handle);
        assert_ne!(
            state.identities.extras,
            Some(identity_before),
            "the extras identity must describe the rules now in force"
        );
        assert!(
            state.generation > generation_before,
            "a reload that installed new rules advances the generation ({} -> {})",
            generation_before,
            state.generation
        );
        // The identity is over the payload the loader read, not over the file: it must equal the hash
        // of exactly those bytes.
        assert_eq!(
            state.identities.extras,
            Some(crate::compiled::PayloadIdentity::of_payload(&extras_after)),
            "the reported identity must be the content that was installed"
        );
        stop_engine(handle);
    }

    #[test]
    fn a_navigation_request_keeps_its_302_semantics_across_an_extras_only_reload() {
        // The same swap, but for a navigation. `$removeparam` rewrites a subresource in place and a
        // document by redirect, and both read the rule set from the same place — so a fix that only
        // worked for `Xhr` would be half a fix. This asserts the *rule content* changed for the
        // document path too, without restating the relay's 302 behaviour (that is covered where the
        // relay is tested).
        let dir = TempDir::new("extras-only-navigation");
        let compiled = dir.path("compiled");
        compile_rules(&dir, "||shop.test^$removeparam=/^old=/");

        let (tun, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let config = serde_json::json!({
            "compiledDir": compiled.to_string_lossy(),
            "upstreams": [{"type": "udp", "address": "127.0.0.1:53"}],
        })
        .to_string();
        use std::os::fd::IntoRawFd;
        let handle = start_engine(tun.into_raw_fd(), &config).expect("engine starts over a real fd");

        let url = "https://shop.test/p?old=1&keep=2";
        let document_result = |handle: u64, url: &str| -> String {
            let entry = find_handle(handle).expect("handle");
            let filter = entry.http_filter().expect("engine loaded");
            let modifiers = crate::https::modifiers::HttpsModifiers::new(
                filter.clone(),
                Arc::new(crate::https::modifiers::collect_removeheader(
                    std::iter::empty(),
                )),
                filter.extras_arc(),
            );
            let request = decrypted_request(url);
            use crate::http::rewrite::ModifierSource;
            modifiers
                .edits(&request, crate::http::resource::RequestKind::Document)
                .and_then(|edits| edits.url)
                .unwrap_or_else(|| url.to_string())
        };
        assert_eq!(document_result(handle, url), "https://shop.test/p?keep=2");

        compile_rules(&dir, "||shop.test^$removeparam=/^keep=/");
        assert!(reload_engine(handle, &compiled.to_string_lossy()));
        assert_eq!(
            document_result(handle, url),
            "https://shop.test/p?old=1",
            "the navigation path must decide by the reloaded rules too"
        );
        stop_engine(handle);
    }
}
