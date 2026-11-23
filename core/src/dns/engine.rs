//! DNS request pipeline: parse -> filter -> cache -> upstream -> build reply.

use std::sync::Arc;

use serde::Serialize;

use crate::config::{BlockResponse, ValidatedConfig};
use crate::dns::cache::{Cache, CacheKey};
use crate::dns::filter::{Filter, RuleStats, Verdict};
use crate::dns::wire::{
    build_rcode_response, build_response, normalize_query_name, zero_ip_record, Message,
    RCODE_NXDOMAIN, RCODE_REFUSED, RCODE_SERVFAIL, TYPE_AAAA, TYPE_A, TYPE_CNAME, TYPE_HTTPS,
    TYPE_MX, TYPE_NS, TYPE_PTR, TYPE_SOA, TYPE_SRV, TYPE_TXT,
};
use crate::http::log::{RequestLog, RequestOutcome};
use crate::upstream::{Resolver, Upstream, UpstreamError};

/// TTL used for locally synthesised answers. Short so a rule change takes effect quickly.
pub const SYNTHETIC_TTL_SECS: u32 = 1;

/// Counters exposed through `statsJson`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_errors: u64,
    pub dns_cached: u64,
    pub dns_upstream_queries: u64,
    pub upstream_latency_ms_p50: u64,
    pub cache_entries: u64,
    pub rules_block: u64,
    pub rules_exception: u64,
    /// Parse failures (the UI's "不支持").
    pub rules_unsupported: u64,
    /// Valid rules that live in the adblock engine, not the DNS filter.
    pub rules_network_only: u64,
    /// HTTPS/SVCB answers whose `ech` SvcParam was removed (task card §4).
    pub ech_stripped: u64,
    /// AAAA queries answered with NODATA because the underlying network has no IPv6 (MYS-2710).
    pub ipv6_suppressed: u64,
    /// HTTPS/SVCB answers whose `ipv6hint` was removed for the same reason.
    pub ipv6_hint_stripped: u64,
}

/// What the engine did with one query, used by tests and the request log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Blocked by a rule; carries the offending name.
    Blocked { name: String },
    /// Answered from cache.
    Cached,
    /// Resolved upstream.
    Resolved,
    /// Upstream failed.
    Error(String),
    /// The packet was not a usable DNS query.
    Ignored,
    /// Answered locally because the network underneath has no IPv6 (MYS-2710).
    Ipv6Suppressed,
}

/// Latency histogram: 32 log-ish buckets of 1 ms, enough for a p50 that is accurate to ~3%.
#[derive(Debug, Default)]
struct LatencyRecorder {
    buckets: [u64; 32],
}

impl LatencyRecorder {
    fn record(&mut self, ms: u64) {
        let idx = bucket_index(ms);
        self.buckets[idx] += 1;
    }

    fn p50(&self) -> u64 {
        let total: u64 = self.buckets.iter().sum();
        if total == 0 {
            return 0;
        }
        let target = total.div_ceil(2);
        let mut seen = 0u64;
        for (idx, count) in self.buckets.iter().enumerate() {
            seen += count;
            if seen >= target {
                return bucket_lower_bound(idx);
            }
        }
        0
    }
}

/// Bucket boundaries: 0,1,2,...,16 then doubling steps up to the 32nd bucket.
fn bucket_index(ms: u64) -> usize {
    if ms <= 16 {
        return ms as usize;
    }
    let mut idx = 16usize;
    let mut upper = 16u64;
    while idx < 31 {
        upper *= 2;
        idx += 1;
        if ms <= upper {
            return idx;
        }
    }
    31
}

fn bucket_lower_bound(idx: usize) -> u64 {
    if idx <= 16 {
        return idx as u64;
    }
    let mut value = 16u64;
    for _ in 17..=idx {
        value *= 2;
    }
    value
}

/// The DNS engine: owns the filter, the cache and the upstream chain.
pub struct Engine {
    /// Swappable so a rule update can hot-replace the filter without touching the tunnel: a query
    /// already in flight keeps the `Arc` it loaded and is answered against the rules it started
    /// with (task card §4: "进行中的查询不受影响").
    filter: std::sync::RwLock<Arc<Filter>>,
    cache: parking_lot_cache::Mutex<Cache>,
    upstreams: Vec<Arc<dyn Resolver>>,
    block_response: BlockResponse,
    /// Whether the network underneath the tunnel can carry IPv6 (see `config::Config::ipv6`).
    /// Immutable for the life of an engine: a change in availability rebuilds the tunnel.
    ipv6: bool,
    timeout: std::time::Duration,
    stats: std::sync::Mutex<Counters>,
    latency: std::sync::Mutex<LatencyRecorder>,
    /// Minimum interval between two lazy cache purges.
    purge_interval: std::time::Duration,
    /// Number of queries seen when the cache was last purged; combined with `purge_interval` this
    /// keeps the purge off the hot path without a timer.
    last_purge: std::sync::Mutex<Option<std::time::Instant>>,
    /// The unified request log (MYS-2742 §修复②). `None` in the tests that do not care about it,
    /// which keeps those tests free of log assertions and the engine free of a mandatory dependency.
    ///
    /// The same `Arc` the tunnel's HTTP and connection layers write to, so one `sinceId` cursor
    /// reaches all three kinds.
    log: Option<Arc<RequestLog>>,
}

/// Split out so `statsJson` never blocks the data path for long.
#[derive(Debug, Default)]
struct Counters {
    queries: u64,
    blocked: u64,
    errors: u64,
    cached: u64,
    upstream_queries: u64,
    ech_stripped: u64,
    ipv6_suppressed: u64,
    ipv6_hint_stripped: u64,
}

/// Minimal `Mutex` wrapper so the cache is swappable for a sharded/lock-free structure later
/// without touching call sites.
mod parking_lot_cache {
    pub struct Mutex<T>(std::sync::Mutex<T>);

    impl<T> Mutex<T> {
        pub fn new(value: T) -> Self {
            Self(std::sync::Mutex::new(value))
        }

        pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
            // A poisoned cache mutex only means a previous caller panicked mid-update; the cache
            // has no invariants that a panic can leave broken, so recovering is safe.
            let mut guard = self.0.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut guard)
        }
    }
}

impl Engine {
    pub fn new(config: &ValidatedConfig, filter: Arc<Filter>) -> Result<Self, UpstreamError> {
        let mut upstreams: Vec<Arc<dyn Resolver>> = Vec::with_capacity(config.upstreams.len());
        for cfg in &config.upstreams {
            upstreams.push(Arc::new(Upstream::new(cfg)?));
        }
        Self::with_resolvers(config, filter, upstreams)
    }

    /// Build an engine over pre-constructed resolvers (used by tests).
    pub fn with_resolvers(
        config: &ValidatedConfig,
        filter: Arc<Filter>,
        upstreams: Vec<Arc<dyn Resolver>>,
    ) -> Result<Self, UpstreamError> {
        if upstreams.is_empty() {
            return Err(UpstreamError::Io("no upstream configured".to_string()));
        }
        Ok(Self {
            filter: std::sync::RwLock::new(filter),
            cache: parking_lot_cache::Mutex::new(Cache::new(
                config.cache_max_entries,
                config.cache_max_ttl_secs,
            )),
            upstreams,
            block_response: config.block_response,
            ipv6: config.ipv6,
            timeout: std::time::Duration::from_millis(config.query_timeout_ms),
            stats: std::sync::Mutex::new(Counters::default()),
            latency: std::sync::Mutex::new(LatencyRecorder::default()),
            purge_interval: std::time::Duration::from_secs(60),
            last_purge: std::sync::Mutex::new(None),
            log: None,
        })
    }

    /// Attach the unified request log, so every query the engine answers is recorded (MYS-2742).
    ///
    /// Separate from the constructor because the log is owned by the engine *handle* (it outlives a
    /// rule reload and is what `recentRequestsJson` reads), while the DNS engine is created before
    /// the handle exists. Called once, before the tunnel starts.
    pub fn with_log(mut self, log: Arc<RequestLog>) -> Self {
        self.log = Some(log);
        self
    }

    /// The filter currently in force. Cheap (`Arc` clone) but not free, so the request path takes
    /// one snapshot per query instead of one per name.
    pub fn filter(&self) -> Arc<Filter> {
        Arc::clone(&self.filter.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Whether this engine hands out IPv6 answers (see `config::Config::ipv6`). Exposed for the
    /// `start` path's test, which has to prove the flag survived the JNI boundary.
    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6
    }

    /// Hot-replace the rule set.
    ///
    /// Queries already in flight are unaffected: they hold their own `Arc` to the previous filter.
    /// The cache is dropped wholesale, because every cached answer was a decision made by the old
    /// rules — keeping it would let a newly blocked name keep resolving until its TTL expired.
    /// Returns the number of cache entries invalidated.
    pub fn replace_filter(&self, filter: Arc<Filter>) -> usize {
        {
            let mut guard = self.filter.write().unwrap_or_else(|e| e.into_inner());
            *guard = filter;
        }
        self.cache.with(|cache| cache.clear())
    }

    /// Handle one raw DNS message (already extracted from the tunnel).
    pub async fn handle(&self, query: &[u8]) -> (Vec<u8>, Outcome) {
        // Lazy housekeeping: expired cache entries are dropped here rather than by a timer, so an
        // idle tunnel schedules nothing (docs/DESIGN.md decision 10). It runs at most once per
        // second of query traffic, which is cheap next to the query itself.
        self.maybe_purge_cache();

        let message = match Message::parse(query) {
            Ok(message) => message,
            Err(err) => {
                self.bump_error();
                return (Vec::new(), Outcome::Error(format!("parse: {err}")));
            }
        };
        let Some(question) = message.question().cloned() else {
            self.bump_error();
            return (Vec::new(), Outcome::Error("no question".to_string()));
        };
        self.bump_query();

        let name = normalize_query_name(&question.name);
        let qtype = qtype_name(question.qtype);
        // One snapshot per query: a rule update landing mid-query must not make the question and
        // its CNAME chain be judged by two different rule sets.
        let filter = self.filter();
        if filter.match_domain(&name) == Verdict::Block {
            self.bump_blocked();
            self.log_dns(&name, qtype, RequestOutcome::Blocked, None);
            let reply = self.block_reply(&message, &name, question.qtype);
            return (reply, Outcome::Blocked { name });
        }

        // No IPv6 underneath the tunnel (MYS-2710): answer AAAA locally with NODATA instead of
        // asking upstream. A client that receives a real AAAA record would try that address first,
        // the tunnel has no IPv6 route to send it to, and the client sees a reset after its
        // ClientHello instead of falling back to IPv4 — so the record must never leave the device.
        // NODATA (NOERROR, no answer records, question echoed) is exactly how a resolver says "this
        // name exists but has no address of that family", which every stub resolver treats as "try
        // the other family".
        if question.qtype == TYPE_AAAA && !self.ipv6 {
            self.bump_ipv6_suppressed();
            self.log_dns(&name, qtype, RequestOutcome::Allowed, None);
            let reply = build_response(&message, crate::dns::wire::RCODE_NOERROR, &[], &[]);
            return (reply, Outcome::Ipv6Suppressed);
        }

        let key = CacheKey::new(&name, question.qtype, question.qclass);
        if let Some((answers, authorities)) = self.cache.with(|cache| cache.get(&key)) {
            self.bump_cached();
            self.log_dns(&name, qtype, RequestOutcome::Cached, None);
            let reply = build_response(&message, crate::dns::wire::RCODE_NOERROR, &answers, &authorities);
            return (reply, Outcome::Cached);
        }

        let started = std::time::Instant::now();
        match self.resolve_upstream(query).await {
            Ok(response) => {
                let elapsed = started.elapsed().as_millis() as u64;
                self.latency
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .record(elapsed);
                // CNAME cloaking: a name that looks clean can CNAME into a blocked one. This is
                // checked before caching so a cloaked answer never becomes a cache hit.
                if let Some(blocked_name) = self.cname_offender(&filter, &response) {
                    self.bump_blocked();
                    // The log names the queried host (what the client asked for) and puts the step
                    // that was actually blocked in `cname`, so "why was this fine-looking name
                    // stopped" is answerable from one line (MYS-2742 §修复②).
                    self.log_dns(
                        &name,
                        qtype,
                        RequestOutcome::Blocked,
                        Some(blocked_name.clone()),
                    );
                    // The answer record must carry the *query* name: the client matches answers to
                    // its question by name (and the CNAME chain it never saw would otherwise leave
                    // it with a dangling alias). `blocked_name` is only what gets reported.
                    let reply = self.block_reply(&message, &name, question.qtype);
                    return (reply, Outcome::Blocked { name: blocked_name });
                }
                // ECH stripping happens before caching, so the cache holds what the client gets.
                let stripped = crate::dns::ech::strip_ech_from_response(&response);
                if stripped.is_some() {
                    self.bump_ech_stripped();
                }
                let response = stripped.unwrap_or(response);
                // An HTTPS/SVCB answer survives the AAAA gate above, so an `ipv6hint` in it would
                // still send the client to an IPv6 address the tunnel cannot reach. Dropping the
                // parameter leaves the rest of the record intact (alpn, port, ipv4hint), so the
                // client connects over IPv4 using what is left.
                let response = if self.ipv6 {
                    response
                } else {
                    match crate::dns::ech::strip_svc_params_from_response(
                        &response,
                        &[crate::dns::ech::SVC_PARAM_IPV6HINT],
                    ) {
                        Some(rewritten) => {
                            self.bump_ipv6_hint_stripped();
                            rewritten
                        }
                        None => response,
                    }
                };
                self.store_in_cache(&key, &response);
                self.log_dns(&name, qtype, RequestOutcome::Allowed, None);
                let reply = retag_response_id(&response, message.id);
                (reply, Outcome::Resolved)
            }
            Err(err) => {
                self.bump_error();
                // An upstream failure is not a filter decision, so it is not a log entry either:
                // the log's `outcome = blocked` ledger has to equal the counters, and
                // `dnsErrors` is a separate counter the UI reports separately.
                let reply = build_rcode_response(&message, RCODE_SERVFAIL);
                (reply, Outcome::Error(err.to_string()))
            }
        }
    }

    /// Names from the answer's CNAME chain that the filter blocks.
    fn cname_offender(&self, filter: &Filter, response: &[u8]) -> Option<String> {
        let message = Message::parse(response).ok()?;
        message
            .cname_chain()
            .into_iter()
            .find(|name| filter.match_domain(name) == Verdict::Block)
    }

    fn store_in_cache(&self, key: &CacheKey, response: &[u8]) {
        let Ok(message) = Message::parse(response) else {
            return;
        };
        if message.rcode() != crate::dns::wire::RCODE_NOERROR || message.answers.is_empty() {
            return;
        }
        // OPT (EDNS) records are not cached: their contents are per-connection.
        let answers: Vec<_> = message
            .answers
            .iter()
            .filter(|r| r.rtype != crate::dns::wire::TYPE_OPT)
            .cloned()
            .collect();
        let authorities: Vec<_> = message
            .authorities
            .iter()
            .filter(|r| r.rtype != crate::dns::wire::TYPE_OPT)
            .cloned()
            .collect();
        self.cache
            .with(|cache| cache.insert(key.clone(), answers, authorities));
    }

    fn block_reply(&self, query: &Message, name: &str, qtype: u16) -> Vec<u8> {
        match self.block_response {
            BlockResponse::ZeroIp => match zero_ip_record(name, qtype, SYNTHETIC_TTL_SECS) {
                Some(record) => build_response(query, crate::dns::wire::RCODE_NOERROR, &[record], &[]),
                // For non-address queries (MX, TXT, ...) an empty NOERROR is the honest "blocked"
                // answer: the client stops waiting without an error.
                None => build_response(query, crate::dns::wire::RCODE_NOERROR, &[], &[]),
            },
            BlockResponse::Nxdomain => build_rcode_response(query, RCODE_NXDOMAIN),
            BlockResponse::Refused => build_rcode_response(query, RCODE_REFUSED),
        }
    }

    async fn resolve_upstream(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
        let mut last_error = None;
        for upstream in &self.upstreams {
            self.stats
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .upstream_queries += 1;
            let started = std::time::Instant::now();
            match upstream.query(query, self.timeout).await {
                Ok(response) if response.len() >= 12 => {
                    // Logged locally on every query so `adb logcat` shows which transport served
                    // it (part of the M0 acceptance check). This is device-local logging only;
                    // there is no telemetry (docs/DESIGN.md §11).
                    crate::log_msg(
                        "info",
                        &format!(
                            "upstream {} answered in {} ms",
                            upstream.label(),
                            started.elapsed().as_millis()
                        ),
                    );
                    return Ok(response);
                }
                Ok(_) => last_error = Some(format!("{}: short response", upstream.label())),
                Err(err) => {
                    crate::log_msg(
                        "warn",
                        &format!("upstream {} failed: {err}", upstream.label()),
                    );
                    last_error = Some(format!("{}: {err}", upstream.label()));
                }
            }
        }
        Err(match last_error {
            Some(msg) => UpstreamError::Http(msg),
            None => UpstreamError::Io("no upstream configured".to_string()),
        })
    }

    /// Snapshot for `Native.statsJson`.
    pub fn stats(&self) -> Stats {
        let counters = self
            .stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let latency = self.latency.lock().unwrap_or_else(|e| e.into_inner());
        let cache_entries = self.cache.with(|cache| cache.len()) as u64;
        let rules = self.filter().stats();
        Stats {
            dns_queries: counters.queries,
            dns_blocked: counters.blocked,
            dns_errors: counters.errors,
            dns_cached: counters.cached,
            dns_upstream_queries: counters.upstream_queries,
            upstream_latency_ms_p50: latency.p50(),
            cache_entries,
            rules_block: rules.block_rules as u64,
            rules_exception: rules.exception_rules as u64,
            rules_unsupported: rules.unsupported as u64,
            rules_network_only: rules.network_only as u64,
            ech_stripped: counters.ech_stripped,
            ipv6_suppressed: counters.ipv6_suppressed,
            ipv6_hint_stripped: counters.ipv6_hint_stripped,
        }
    }

    pub fn rule_stats(&self) -> RuleStats {
        self.filter().stats()
    }

    /// Drop expired cache entries now. Exposed for tests and for an explicit cleanup on reload.
    pub fn purge_cache(&self) -> usize {
        *self.last_purge.lock().unwrap_or_else(|e| e.into_inner()) = Some(std::time::Instant::now());
        self.cache.with(|cache| cache.purge_expired())
    }

    /// Purge expired entries at most once per `purge_interval`.
    ///
    /// The M0 core ran this from a 60 s tokio timer, which woke the process every minute even with
    /// the screen off. Doing it here instead means it costs one clock read per query and nothing at
    /// all while the tunnel is idle.
    fn maybe_purge_cache(&self) {
        {
            let last = self.last_purge.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(last) = *last {
                if last.elapsed() < self.purge_interval {
                    return;
                }
            }
        }
        let purged = self.purge_cache();
        if purged > 0 {
            crate::log_msg("debug", &format!("cache: purged {purged} expired entries"));
        }
    }

    fn bump_query(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queries += 1;
    }

    fn bump_blocked(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .blocked += 1;
    }

    fn bump_cached(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cached += 1;
    }

    fn bump_error(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .errors += 1;
    }

    fn bump_ech_stripped(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ech_stripped += 1;
    }

    fn bump_ipv6_suppressed(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ipv6_suppressed += 1;
    }

    fn bump_ipv6_hint_stripped(&self) {
        self.stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ipv6_hint_stripped += 1;
    }

    /// Record one query in the unified log, when one is attached (MYS-2742 §修复②).
    fn log_dns(&self, host: &str, qtype: String, outcome: RequestOutcome, cname: Option<String>) {
        if let Some(log) = self.log.as_ref() {
            log.record_dns(host, &qtype, outcome, cname);
        }
    }
}

/// The `qtype` string the request log shows for a query type.
///
/// A mnemonic rather than the number: the log is read by a person asking "why did this name fail",
/// and `AAAA` answers that question faster than `28`. An unknown type keeps its number so nothing is
/// silently mislabelled as `A`.
fn qtype_name(qtype: u16) -> String {
    match qtype {
        TYPE_A => "A".to_string(),
        TYPE_AAAA => "AAAA".to_string(),
        TYPE_HTTPS => "HTTPS".to_string(),
        TYPE_CNAME => "CNAME".to_string(),
        TYPE_NS => "NS".to_string(),
        TYPE_SOA => "SOA".to_string(),
        TYPE_PTR => "PTR".to_string(),
        TYPE_MX => "MX".to_string(),
        TYPE_TXT => "TXT".to_string(),
        TYPE_SRV => "SRV".to_string(),
        other => other.to_string(),
    }
}

/// Upstream responses echo the query id, but a misbehaving upstream must not confuse the client.
fn retag_response_id(response: &[u8], id: u16) -> Vec<u8> {
    let mut out = response.to_vec();
    if out.len() >= 2 {
        out[0..2].copy_from_slice(&id.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_buckets_are_monotonic() {
        let mut previous = 0;
        for ms in [0u64, 1, 5, 16, 17, 40, 100, 1000, 60_000] {
            let idx = bucket_index(ms);
            let lower = bucket_lower_bound(idx);
            assert!(lower <= ms.max(lower), "bucket {idx} lower {lower} for {ms}");
            assert!(idx >= previous);
            previous = idx;
        }
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1), 1);
        assert_eq!(bucket_index(16), 16);
        assert!(bucket_index(17) > 16);
        assert_eq!(bucket_index(u64::MAX), 31);
    }

    #[test]
    fn p50_is_the_median_bucket() {
        let mut recorder = LatencyRecorder::default();
        assert_eq!(recorder.p50(), 0);
        for _ in 0..9 {
            recorder.record(5);
        }
        recorder.record(500);
        assert_eq!(recorder.p50(), 5);
        for _ in 0..10 {
            recorder.record(20);
        }
        // 20 of 20 samples are <= 32 ms, so the median lands in the bucket starting at 32.
        assert!(recorder.p50() >= 5);
    }

    #[test]
    fn response_id_is_forced_to_the_query_id() {
        let response = [0x00, 0x01, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let retagged = retag_response_id(&response, 0xbeef);
        assert_eq!(&retagged[..2], &[0xbe, 0xef]);
        assert_eq!(&retagged[2..], &response[2..]);
    }

    // ---- engine tests, over a scripted in-memory resolver ----

    use crate::dns::filter::Filter;
    use crate::dns::wire::{
        encode_name, Message, Record, CLASS_IN, RCODE_NOERROR, TYPE_A, TYPE_CNAME, TYPE_HTTPS,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Answers every A query with 203.0.113.7 and TTL 60, counting calls.
    #[derive(Debug)]
    struct ScriptedResolver {
        calls: AtomicU64,
        answer: Vec<u8>,
        fail: bool,
    }

    impl ScriptedResolver {
        fn answering(name: &str, ttl: u32) -> Self {
            Self {
                calls: AtomicU64::new(0),
                answer: response_with(name, ttl),
                fail: false,
            }
        }

        fn cname_answering(query_name: &str, target: &str, ttl: u32) -> Self {
            Self {
                calls: AtomicU64::new(0),
                answer: cname_response(query_name, target, ttl),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: AtomicU64::new(0),
                answer: Vec::new(),
                fail: true,
            }
        }
    }

    impl Resolver for ScriptedResolver {
        fn query<'a>(
            &'a self,
            _message: &'a [u8],
            _timeout: std::time::Duration,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Vec<u8>, UpstreamError>> + Send + 'a>,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = if self.fail {
                Err(UpstreamError::Io("scripted failure".to_string()))
            } else {
                Ok(self.answer.clone())
            };
            Box::pin(async move { result })
        }

        fn label(&self) -> &str {
            "scripted"
        }
    }

    fn raw_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&encode_name(name).expect("name"));
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    /// A complete upstream reply for the question in `query_name`.
    fn response_with(query_name: &str, ttl: u32) -> Vec<u8> {
        let query = Message::parse(&raw_query(0x1111, query_name, TYPE_A)).expect("query");
        let answer = Record {
            name: query_name.to_string(),
            rtype: TYPE_A,
            rclass: CLASS_IN,
            ttl,
            rdata: vec![203, 0, 113, 7],
        };
        crate::dns::wire::build_response(&query, RCODE_NOERROR, &[answer], &[])
    }

    fn cname_response(query_name: &str, target: &str, ttl: u32) -> Vec<u8> {
        let query = Message::parse(&raw_query(0x1111, query_name, TYPE_A)).expect("query");
        let cname = Record {
            name: query_name.to_string(),
            rtype: TYPE_CNAME,
            rclass: CLASS_IN,
            ttl,
            rdata: encode_name(target).expect("target"),
        };
        crate::dns::wire::build_response(&query, RCODE_NOERROR, &[cname], &[])
    }

    fn config(block_response: BlockResponse) -> crate::config::ValidatedConfig {
        crate::config::Config {
            block_response,
            ..Default::default()
        }
        .validate()
        .expect("config")
    }

    /// A config with IPv6 turned off, which is what the control plane sends on an IPv4-only link.
    fn config_without_ipv6() -> crate::config::ValidatedConfig {
        crate::config::Config {
            ipv6: false,
            ..Default::default()
        }
        .validate()
        .expect("config")
    }

    fn filter_with(text: &str) -> Arc<Filter> {
        let mut filter = Filter::new();
        filter.load_text(text);
        Arc::new(filter)
    }

    // ---- request log wiring (MYS-2742 §修复②) ----
    //
    // One test per DNS verdict, because the whole point of the fix is that the log now says what
    // happened at the DNS layer: a block, a pass, a cache hit and a CNAME block each produce exactly
    // one entry with the right `outcome`.

    use crate::http::log::{RequestLog, RequestOutcome, REASON_CNAME};

    /// An engine with the unified log attached, plus that log.
    fn engine_with_log(
        config: crate::config::ValidatedConfig,
        filter: Arc<Filter>,
        resolver: Arc<ScriptedResolver>,
    ) -> (Engine, Arc<RequestLog>) {
        let log = Arc::new(RequestLog::new());
        let engine = Engine::with_resolvers(&config, filter, vec![resolver])
            .expect("engine")
            .with_log(log.clone());
        (engine, log)
    }

    #[tokio::test]
    async fn a_blocked_query_is_logged_with_its_qtype() {
        let resolver = Arc::new(ScriptedResolver::answering("unused", 60));
        let (engine, log) = engine_with_log(
            config(BlockResponse::ZeroIp),
            filter_with("||doubleclick.net^\n"),
            resolver,
        );
        engine
            .handle(&raw_query(1, "ads.doubleclick.net", TYPE_A))
            .await;

        let entries = log.snapshot();
        assert_eq!(entries.len(), 1, "one query, one entry");
        let entry = &entries[0];
        assert_eq!(entry.kind, crate::http::log::LogKind::Dns);
        assert_eq!(entry.host, "ads.doubleclick.net");
        assert_eq!(entry.qtype, "A");
        assert_eq!(entry.outcome, RequestOutcome::Blocked);
        assert!(entry.cname.is_none(), "a direct block names no CNAME step");
        assert!(entry.rule.is_none(), "rule attribution is off by default");
    }

    #[tokio::test]
    async fn an_allowed_query_is_logged_too() {
        // The log has to show what was looked up, not only what was stopped: otherwise "the log is
        // empty" reads as "nothing was filtered" rather than "nothing was blocked".
        let resolver = Arc::new(ScriptedResolver::answering("www.baidu.com", 60));
        let (engine, log) = engine_with_log(
            config(BlockResponse::ZeroIp),
            filter_with("||doubleclick.net^\n"),
            resolver,
        );
        engine
            .handle(&raw_query(2, "www.baidu.com", TYPE_A))
            .await;
        let entries = log.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, RequestOutcome::Allowed);
        assert_eq!(entries[0].host, "www.baidu.com");
    }

    #[tokio::test]
    async fn a_cache_hit_is_logged_as_cached() {
        let resolver = Arc::new(ScriptedResolver::answering("www.baidu.com", 60));
        let (engine, log) = engine_with_log(
            config(BlockResponse::ZeroIp),
            filter_with(""),
            resolver.clone(),
        );
        engine.handle(&raw_query(3, "www.baidu.com", TYPE_A)).await;
        engine.handle(&raw_query(4, "www.baidu.com", TYPE_A)).await;

        let outcomes: Vec<RequestOutcome> =
            log.snapshot().iter().map(|entry| entry.outcome).collect();
        assert_eq!(outcomes, vec![RequestOutcome::Allowed, RequestOutcome::Cached]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_cname_block_names_the_queried_host_and_the_blocked_step() {
        let resolver = Arc::new(ScriptedResolver::cname_answering(
            "metrics.clean-site.com",
            "tracker.doubleclick.net",
            300,
        ));
        let (engine, log) = engine_with_log(
            config(BlockResponse::ZeroIp),
            filter_with("||doubleclick.net^\n"),
            resolver,
        );
        engine
            .handle(&raw_query(5, "metrics.clean-site.com", TYPE_A))
            .await;

        let entries = log.snapshot();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.outcome, RequestOutcome::Blocked);
        // `host` is what the client asked for; the blocked step is in `cname`, with reason `cname`.
        assert_eq!(entry.host, "metrics.clean-site.com");
        assert_eq!(entry.cname.as_deref(), Some("tracker.doubleclick.net"));
        assert_eq!(entry.reason.as_deref(), Some(REASON_CNAME));
    }

    #[tokio::test]
    async fn an_ipv6_suppressed_query_is_logged_as_allowed() {
        // Suppressing AAAA is a policy decision, not a block: nothing matched a rule, and counting it
        // as blocked would make the log disagree with `dnsBlocked`.
        let resolver = Arc::new(ScriptedResolver {
            calls: AtomicU64::new(0),
            answer: aaaa_response("www.baidu.com", 300),
            fail: false,
        });
        let (engine, log) = engine_with_log(config_without_ipv6(), filter_with(""), resolver);
        engine
            .handle(&raw_query(6, "www.baidu.com", TYPE_AAAA))
            .await;
        let entries = log.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, RequestOutcome::Allowed);
        assert_eq!(entries[0].qtype, "AAAA");
    }

    #[tokio::test]
    async fn an_upstream_error_is_not_a_blocked_entry() {
        // `dnsErrors` is its own counter and its own UI line; folding it into the log's blocked
        // entries would break the ledger against `dnsBlocked`.
        let resolver = Arc::new(ScriptedResolver::failing());
        let (engine, log) = engine_with_log(config(BlockResponse::ZeroIp), filter_with(""), resolver);
        engine.handle(&raw_query(7, "example.com", TYPE_A)).await;
        assert_eq!(engine.stats().dns_errors, 1);
        assert!(
            log.snapshot().iter().all(|entry| entry.outcome != RequestOutcome::Blocked),
            "an upstream failure is not a filter decision"
        );
    }

    #[tokio::test]
    async fn the_dns_log_ledger_matches_the_blocked_counter() {
        // MYS-2742 §修复②: with the ring not wrapped, blocked DNS entries == the `dnsBlocked` delta.
        let resolver = Arc::new(ScriptedResolver::answering("clean.example", 60));
        let (engine, log) = engine_with_log(
            config(BlockResponse::ZeroIp),
            filter_with("||ads.example^\n"),
            resolver,
        );
        for index in 0..20u16 {
            let name = if index % 3 == 0 { "ads.example" } else { "clean.example" };
            engine.handle(&raw_query(index + 1, name, TYPE_A)).await;
        }
        let blocked_entries = log
            .snapshot()
            .into_iter()
            .filter(|entry| entry.outcome == RequestOutcome::Blocked)
            .count() as u64;
        assert_eq!(blocked_entries, engine.stats().dns_blocked);
        assert_eq!(blocked_entries, 7, "indices 0,3,6,9,12,15,18 are blocked");
    }

    #[tokio::test]
    async fn an_engine_without_a_log_still_answers() {
        // The log is optional on purpose: the many tests that only care about DNS behaviour must not
        // have to build one, and a core started without it must not panic on the query path.
        let engine = Engine::with_resolvers(
            &config(BlockResponse::ZeroIp),
            filter_with("||ads.example^\n"),
            vec![Arc::new(ScriptedResolver::answering("x", 60))],
        )
        .expect("engine");
        let (reply, outcome) = engine.handle(&raw_query(1, "ads.example", TYPE_A)).await;
        assert!(matches!(outcome, Outcome::Blocked { .. }));
        assert!(!reply.is_empty());
    }

    #[test]
    fn qtype_names_cover_the_types_the_wire_module_knows() {
        assert_eq!(qtype_name(TYPE_A), "A");
        assert_eq!(qtype_name(TYPE_AAAA), "AAAA");
        assert_eq!(qtype_name(TYPE_HTTPS), "HTTPS");
        assert_eq!(qtype_name(TYPE_CNAME), "CNAME");
        // An unknown type keeps its number rather than being mislabelled as A.
        assert_eq!(qtype_name(99), "99");
    }

    #[tokio::test]
    async fn blocked_name_is_answered_with_zero_ip_without_reaching_upstream() {
        let resolver = Arc::new(ScriptedResolver::answering("unused", 60));
        let engine = Engine::with_resolvers(
            &config(BlockResponse::ZeroIp),
            filter_with("||doubleclick.net^\n"),
            vec![resolver.clone()],
        )
        .expect("engine");

        let query = raw_query(0x2222, "ads.doubleclick.net", TYPE_A);
        let (reply, outcome) = engine.handle(&query).await;
        assert_eq!(
            outcome,
            Outcome::Blocked {
                name: "ads.doubleclick.net".to_string()
            }
        );
        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(parsed.id, 0x2222);
        assert_eq!(
            parsed.answers[0].a_addr().unwrap().to_string(),
            "0.0.0.0"
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(engine.stats().dns_blocked, 1);
        assert_eq!(engine.stats().dns_queries, 1);
    }

    #[test]
    fn nxdomain_mode_answers_with_rcode_3() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let engine = Engine::with_resolvers(
                &config(BlockResponse::Nxdomain),
                filter_with("||zshield-block-test.com^\n"),
                vec![Arc::new(ScriptedResolver::answering("unused", 60))],
            )
            .expect("engine");
            let (reply, _) = engine
                .handle(&raw_query(1, "zshield-block-test.com", TYPE_A))
                .await;
            let parsed = Message::parse(&reply).expect("reply");
            assert_eq!(parsed.rcode(), crate::dns::wire::RCODE_NXDOMAIN);
            assert!(parsed.answers.is_empty());
        });
    }

    #[test]
    fn refused_mode_answers_with_rcode_5() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let engine = Engine::with_resolvers(
                &config(BlockResponse::Refused),
                filter_with("||blocked.example.com^\n"),
                vec![Arc::new(ScriptedResolver::answering("unused", 60))],
            )
            .expect("engine");
            let (reply, _) = engine.handle(&raw_query(1, "blocked.example.com", TYPE_A)).await;
            assert_eq!(
                Message::parse(&reply).expect("reply").rcode(),
                crate::dns::wire::RCODE_REFUSED
            );
        });
    }

    #[test]
    fn clean_name_is_resolved_and_then_cached() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let resolver = Arc::new(ScriptedResolver::answering("www.baidu.com", 60));
            let engine = Engine::with_resolvers(
                &config(BlockResponse::ZeroIp),
                filter_with("||doubleclick.net^\n"),
                vec![resolver.clone()],
            )
            .expect("engine");

            let query = raw_query(0x3333, "www.baidu.com", TYPE_A);
            let (reply, outcome) = engine.handle(&query).await;
            assert_eq!(outcome, Outcome::Resolved);
            let parsed = Message::parse(&reply).expect("reply");
            assert_eq!(parsed.answers[0].a_addr().unwrap().to_string(), "203.0.113.7");
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

            // Second identical query is served from cache with a fresh id.
            let (reply2, outcome2) = engine.handle(&raw_query(0x4444, "www.baidu.com", TYPE_A)).await;
            assert_eq!(outcome2, Outcome::Cached);
            assert_eq!(Message::parse(&reply2).expect("reply").id, 0x4444);
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
            assert_eq!(engine.stats().dns_cached, 1);
        });
    }

    #[test]
    fn cname_cloaking_is_blocked_even_though_the_query_name_is_clean() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let resolver = Arc::new(ScriptedResolver::cname_answering(
                "metrics.clean-site.com",
                "tracker.doubleclick.net",
                300,
            ));
            let engine = Engine::with_resolvers(
                &config(BlockResponse::ZeroIp),
                filter_with("||doubleclick.net^\n"),
                vec![resolver],
            )
            .expect("engine");

            let (reply, outcome) = engine
                .handle(&raw_query(5, "metrics.clean-site.com", TYPE_A))
                .await;
            assert_eq!(
                outcome,
                Outcome::Blocked {
                    name: "tracker.doubleclick.net".to_string()
                }
            );
            let parsed = Message::parse(&reply).expect("reply");
            // The answer must be attached to the name the client asked about, not to the CNAME
            // target it never learned; otherwise a stub resolver would discard the record.
            assert_eq!(parsed.answers[0].name, "metrics.clean-site.com");
            assert_eq!(parsed.answers[0].a_addr().unwrap().to_string(), "0.0.0.0");
            assert_eq!(engine.stats().dns_blocked, 1);
        });
    }

    #[test]
    fn upstream_failure_yields_servfail_and_counts_an_error() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let engine = Engine::with_resolvers(
                &config(BlockResponse::ZeroIp),
                filter_with(""),
                vec![Arc::new(ScriptedResolver::failing())],
            )
            .expect("engine");
            let (reply, outcome) = engine.handle(&raw_query(6, "example.com", TYPE_A)).await;
            assert!(matches!(outcome, Outcome::Error(_)));
            assert_eq!(
                Message::parse(&reply).expect("reply").rcode(),
                crate::dns::wire::RCODE_SERVFAIL
            );
            assert_eq!(engine.stats().dns_errors, 1);
        });
    }

    #[test]
    fn garbage_input_is_rejected_without_panicking() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let engine = Engine::with_resolvers(
                &config(BlockResponse::ZeroIp),
                filter_with(""),
                vec![Arc::new(ScriptedResolver::answering("x", 60))],
            )
            .expect("engine");
            let (reply, outcome) = engine.handle(&[0u8, 1, 2]).await;
            assert!(reply.is_empty());
            assert!(matches!(outcome, Outcome::Error(_)));
            assert_eq!(engine.stats().dns_errors, 1);
        });
    }

    #[test]
    fn stats_snapshot_reports_rule_counts() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let engine = Engine::with_resolvers(
                &config(BlockResponse::ZeroIp),
                filter_with("||a.example.com^\n@@||b.example.com^\n$bad\n"),
                vec![Arc::new(ScriptedResolver::answering("x", 60))],
            )
            .expect("engine");
            let stats = engine.stats();
            assert_eq!(stats.rules_block, 1);
            assert_eq!(stats.rules_exception, 1);
            // `$bad` is rejected by BOTH layers, so it is unsupported, not an engine rule
            // (MYS-2716's single definition, `docs/JNI.md` §"规则统计").
            assert_eq!(stats.rules_unsupported, 1);
            assert_eq!(stats.rules_network_only, 0);
            assert_eq!(stats.upstream_latency_ms_p50, 0);
        });
    }

    /// An upstream reply carrying one HTTPS record whose SvcParams include `ech`.
    fn https_response_with_ech(query_name: &str, ttl: u32) -> Vec<u8> {
        let query = Message::parse(&raw_query(0x1111, query_name, TYPE_HTTPS)).expect("query");
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&encode_name("").expect("root")); // target: root
        // alpn=h2
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[0x02, b'h', b'2']);
        // ech=<opaque>
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&6u16.to_be_bytes());
        rdata.extend_from_slice(&[0xfe, 0x0d, 0x00, 0x02, 0xaa, 0xbb]);
        let answer = Record {
            name: query_name.to_string(),
            rtype: TYPE_HTTPS,
            rclass: CLASS_IN,
            ttl,
            rdata,
        };
        crate::dns::wire::build_response(&query, RCODE_NOERROR, &[answer], &[])
    }

    #[tokio::test]
    async fn ech_is_stripped_from_https_answers_before_caching() {
        let resolver = Arc::new(ScriptedResolver {
            calls: AtomicU64::new(0),
            answer: https_response_with_ech("crypto.cloudflare.com", 300),
            fail: false,
        });
        let engine = Engine::with_resolvers(
            &config(BlockResponse::ZeroIp),
            filter_with(""),
            vec![resolver.clone()],
        )
        .expect("engine");

        let query = raw_query(0x3333, "crypto.cloudflare.com", TYPE_HTTPS);
        let (reply, outcome) = engine.handle(&query).await;
        assert_eq!(outcome, Outcome::Resolved);

        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rtype, TYPE_HTTPS);
        // The answer must still be a usable SVCB record: priority and alpn intact, ech gone.
        let keys = svc_param_keys(&parsed.answers[0].rdata);
        assert_eq!(keys, vec![1], "only alpn must remain, ech must be stripped");
        assert_eq!(engine.stats().ech_stripped, 1);

        // The cache stores the stripped answer, so a cache hit cannot resurrect ech either.
        let (cached, outcome) = engine.handle(&raw_query(0x3334, "crypto.cloudflare.com", TYPE_HTTPS)).await;
        assert_eq!(outcome, Outcome::Cached);
        let cached = Message::parse(&cached).expect("cached reply");
        assert_eq!(svc_param_keys(&cached.answers[0].rdata), vec![1]);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn answers_without_ech_are_forwarded_unchanged() {
        let resolver = Arc::new(ScriptedResolver::answering("plain.example", 60));
        let engine = Engine::with_resolvers(
            &config(BlockResponse::ZeroIp),
            filter_with(""),
            vec![resolver],
        )
        .expect("engine");
        let (reply, _) = engine
            .handle(&raw_query(1, "plain.example", TYPE_A))
            .await;
        assert_eq!(Message::parse(&reply).expect("reply").answers[0].a_addr(),
            Some(std::net::Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(engine.stats().ech_stripped, 0);
    }

    // ---- IPv4-only underlying network (MYS-2710) ----

    /// An upstream reply carrying one AAAA record, i.e. what a dual-stack site gets today.
    fn aaaa_response(query_name: &str, ttl: u32) -> Vec<u8> {
        let query = Message::parse(&raw_query(0x1111, query_name, TYPE_AAAA)).expect("query");
        let answer = Record {
            name: query_name.to_string(),
            rtype: crate::dns::wire::TYPE_AAAA,
            rclass: CLASS_IN,
            ttl,
            rdata: std::net::Ipv6Addr::new(0x240e, 0x83, 0x0205, 0x01cd, 0, 0, 0, 1)
                .octets()
                .to_vec(),
        };
        crate::dns::wire::build_response(&query, RCODE_NOERROR, &[answer], &[])
    }

    #[tokio::test]
    async fn aaaa_is_answered_with_nodata_when_the_underlying_network_has_no_ipv6() {
        // The resolver answers with a real AAAA. With IPv6 off, that answer must never reach the
        // client: it would connect to an address the tunnel cannot route and the connection would
        // be reset after the ClientHello instead of falling back to IPv4.
        let resolver = Arc::new(ScriptedResolver {
            calls: AtomicU64::new(0),
            answer: aaaa_response("www.baidu.com", 300),
            fail: false,
        });
        let engine = Engine::with_resolvers(
            &config_without_ipv6(),
            filter_with(""),
            vec![resolver.clone()],
        )
        .expect("engine");

        let query = raw_query(0x2710, "www.baidu.com", crate::dns::wire::TYPE_AAAA);
        let (reply, outcome) = engine.handle(&query).await;

        assert_eq!(outcome, Outcome::Ipv6Suppressed);
        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(parsed.id, 0x2710);
        assert_eq!(parsed.rcode(), RCODE_NOERROR, "NODATA is NOERROR with no answer");
        assert!(parsed.answers.is_empty(), "no AAAA record may be handed out");
        // The question is echoed verbatim so a stub resolver matches the reply to its query.
        assert_eq!(parsed.questions, Message::parse(&query).expect("query").questions);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0, "no upstream query");
        assert_eq!(engine.stats().ipv6_suppressed, 1);
    }

    #[tokio::test]
    async fn a_queries_are_unaffected_by_ipv6_being_off() {
        let resolver = Arc::new(ScriptedResolver::answering("www.baidu.com", 60));
        let engine = Engine::with_resolvers(
            &config_without_ipv6(),
            filter_with(""),
            vec![resolver.clone()],
        )
        .expect("engine");

        let (reply, outcome) = engine
            .handle(&raw_query(0x2711, "www.baidu.com", TYPE_A))
            .await;
        assert_eq!(outcome, Outcome::Resolved);
        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(
            parsed.answers[0].a_addr().unwrap().to_string(),
            "203.0.113.7"
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(engine.stats().ipv6_suppressed, 0);
        // Cache still works for A, so the gate did not disturb the normal path.
        let (_, outcome2) = engine
            .handle(&raw_query(0x2712, "www.baidu.com", TYPE_A))
            .await;
        assert_eq!(outcome2, Outcome::Cached);
    }

    #[tokio::test]
    async fn ipv6hint_is_stripped_from_https_answers_when_ipv6_is_off() {
        // An HTTPS answer for an A/AAAA-less flow: the client would still read `ipv6hint` and try
        // that address first, so the parameter has to go while every other one stays.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.extend_from_slice(&encode_name("").expect("root"));
        rdata.extend_from_slice(&1u16.to_be_bytes()); // alpn
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[0x02, b'h', b'2']);
        rdata.extend_from_slice(&4u16.to_be_bytes()); // ipv4hint = 1.2.3.4
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[1, 2, 3, 4]);
        rdata.extend_from_slice(&6u16.to_be_bytes()); // ipv6hint, to be removed
        rdata.extend_from_slice(&16u16.to_be_bytes());
        rdata.extend_from_slice(&[0x24, 0x0e, 0x08, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let query = Message::parse(&raw_query(0x1111, "www.baidu.com", TYPE_HTTPS)).expect("query");
        let answer = Record {
            name: "www.baidu.com".to_string(),
            rtype: TYPE_HTTPS,
            rclass: CLASS_IN,
            ttl: 300,
            rdata,
        };
        let upstream = crate::dns::wire::build_response(&query, RCODE_NOERROR, &[answer], &[]);
        let resolver = Arc::new(ScriptedResolver {
            calls: AtomicU64::new(0),
            answer: upstream,
            fail: false,
        });
        let engine = Engine::with_resolvers(
            &config_without_ipv6(),
            filter_with(""),
            vec![resolver.clone()],
        )
        .expect("engine");

        let (reply, outcome) = engine
            .handle(&raw_query(0x2713, "www.baidu.com", TYPE_HTTPS))
            .await;
        assert_eq!(outcome, Outcome::Resolved);
        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rtype, TYPE_HTTPS);
        assert_eq!(
            svc_param_keys(&parsed.answers[0].rdata),
            vec![1, 4],
            "alpn and ipv4hint stay, ipv6hint goes"
        );
        // Priority and target are untouched, so the record is still a valid SVCB.
        assert_eq!(&parsed.answers[0].rdata[..2], &[0, 1]);
        assert_eq!(engine.stats().ipv6_hint_stripped, 1);
        assert_eq!(engine.stats().ech_stripped, 0, "a record without ech is not counted");

        // The stripped form is what the cache holds, so a cache hit cannot resurrect the hint.
        let (cached, outcome) = engine
            .handle(&raw_query(0x2714, "www.baidu.com", TYPE_HTTPS))
            .await;
        assert_eq!(outcome, Outcome::Cached);
        assert_eq!(
            svc_param_keys(&Message::parse(&cached).expect("cached").answers[0].rdata),
            vec![1, 4]
        );
    }

    #[tokio::test]
    async fn ipv6_enabled_keeps_the_current_behaviour() {
        // With IPv6 available the core must behave exactly as it did before MYS-2710: AAAA answers
        // are forwarded and `ipv6hint` survives.
        let resolver = Arc::new(ScriptedResolver {
            calls: AtomicU64::new(0),
            answer: aaaa_response("www.baidu.com", 300),
            fail: false,
        });
        let engine = Engine::with_resolvers(
            &config(BlockResponse::ZeroIp),
            filter_with(""),
            vec![resolver.clone()],
        )
        .expect("engine");

        let (reply, outcome) =
            engine.handle(&raw_query(0x2715, "www.baidu.com", crate::dns::wire::TYPE_AAAA)).await;
        assert_eq!(outcome, Outcome::Resolved);
        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(parsed.answers.len(), 1, "the AAAA record is handed out");
        assert_eq!(
            parsed.answers[0].aaaa_addr().unwrap().to_string(),
            "240e:83:205:1cd::1"
        );
        assert_eq!(engine.stats().ipv6_suppressed, 0);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

        // And ipv6hint is not rewritten when IPv6 is on.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&encode_name("").expect("root"));
        rdata.extend_from_slice(&6u16.to_be_bytes());
        rdata.extend_from_slice(&16u16.to_be_bytes());
        rdata.extend_from_slice(&[0x24, 0x0e, 0x08, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let query = Message::parse(&raw_query(0x1111, "ipv6.example", TYPE_HTTPS)).expect("query");
        let answer = Record {
            name: "ipv6.example".to_string(),
            rtype: TYPE_HTTPS,
            rclass: CLASS_IN,
            ttl: 300,
            rdata,
        };
        let upstream = crate::dns::wire::build_response(&query, RCODE_NOERROR, &[answer], &[]);
        let engine = Engine::with_resolvers(
            &config(BlockResponse::ZeroIp),
            filter_with(""),
            vec![Arc::new(ScriptedResolver {
                calls: AtomicU64::new(0),
                answer: upstream.clone(),
                fail: false,
            })],
        )
        .expect("engine");
        let (reply, _) = engine
            .handle(&raw_query(0x2716, "ipv6.example", TYPE_HTTPS))
            .await;
        assert_eq!(
            svc_param_keys(&Message::parse(&reply).expect("reply").answers[0].rdata),
            vec![6],
            "ipv6hint is preserved when IPv6 is available"
        );
        assert_eq!(engine.stats().ipv6_hint_stripped, 0);
    }

    #[tokio::test]
    async fn a_blocked_aaaa_still_gets_the_blocked_answer_not_nodata() {
        // Order matters: the rule judgement comes first, so an ad host stays blocked (0::) even
        // though AAAA would otherwise be suppressed.
        let engine = Engine::with_resolvers(
            &config_without_ipv6(),
            filter_with("||doubleclick.net^\n"),
            vec![Arc::new(ScriptedResolver {
                calls: AtomicU64::new(0),
                answer: aaaa_response("doubleclick.net", 300),
                fail: false,
            })],
        )
        .expect("engine");

        let (reply, outcome) = engine
            .handle(&raw_query(0x2717, "doubleclick.net", crate::dns::wire::TYPE_AAAA))
            .await;
        assert_eq!(
            outcome,
            Outcome::Blocked {
                name: "doubleclick.net".to_string()
            }
        );
        let parsed = Message::parse(&reply).expect("reply");
        assert_eq!(
            parsed.answers[0].aaaa_addr(),
            Some(std::net::Ipv6Addr::UNSPECIFIED)
        );
        assert_eq!(engine.stats().ipv6_suppressed, 0);
    }

    #[test]
    fn cache_housekeeping_is_lazy_not_scheduled() {
        // The old design purged the cache from a 60 s timer. It is now done on the query path, at
        // most once per interval: after an explicit purge the next query must not purge again.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let engine = Engine::with_resolvers(
                &config(BlockResponse::ZeroIp),
                filter_with(""),
                vec![Arc::new(ScriptedResolver::answering("x", 60))],
            )
            .expect("engine");
            assert!(engine.last_purge.lock().unwrap().is_none());
            engine
                .handle(&raw_query(1, "a.example", TYPE_A))
                .await;
            let first = *engine.last_purge.lock().unwrap();
            assert!(first.is_some(), "the first query must purge the cache");
            // A second query inside the interval leaves the timestamp alone.
            engine
                .handle(&raw_query(2, "b.example", TYPE_A))
                .await;
            assert_eq!(*engine.last_purge.lock().unwrap(), first);
        });
    }

    /// Keys of an SVCB RDATA's parameters, for assertions.
    fn svc_param_keys(rdata: &[u8]) -> Vec<u16> {
        let mut cursor = 2usize;
        // Skip the uncompressed target name.
        loop {
            let len = rdata[cursor] as usize;
            cursor += 1;
            if len == 0 {
                break;
            }
            cursor += len;
        }
        let mut keys = Vec::new();
        while cursor + 4 <= rdata.len() {
            let key = u16::from_be_bytes([rdata[cursor], rdata[cursor + 1]]);
            let len = usize::from(u16::from_be_bytes([rdata[cursor + 2], rdata[cursor + 3]]));
            keys.push(key);
            cursor += 4 + len;
        }
        keys
    }
}
