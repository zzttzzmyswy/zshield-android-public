//! The unified recent-request ring buffer behind `recentRequestsJson` (MYS-2742).
//!
//! Fixed capacity, no allocation per entry beyond the strings it stores, and **no push**: the UI
//! polls with `sinceId` when it is visible and nothing runs while it is not (`docs/DESIGN.md`
//! decision 10: 屏幕关闭时不做任何定时 UI 统计推送). Serialization happens only inside the JNI call,
//! which is why the entries keep plain fields instead of pre-rendered JSON.
//!
//! Ids are monotonically increasing across the whole run so `sinceId` is a valid cursor even after
//! the buffer has wrapped: a client that asks for everything newer than the last id it saw gets
//! exactly the new entries, or an empty list when they have already been overwritten.
//!
//! # Three kinds of entry (MYS-2742 §修复②)
//!
//! Before this, only the HTTP layer wrote to the log, so with HTTPS filtering off — where almost
//! every block happens at the DNS layer — the log looked empty while the "blocked" counter kept
//! climbing. The log now records all three layers under one id sequence and one capacity:
//!
//! | `kind` | written by | `outcome` |
//! |---|---|---|
//! | `dns` | [`crate::dns::engine::Engine`], once per query | `blocked` / `allowed` / `cached` |
//! | `connection` | the forwarding layer, once per blocked connection | `blocked` |
//! | `http` | the plaintext and decrypted HTTP pipelines (M2b) | `allowed` / `blocked` / `redirected` / `exception` |
//!
//! The ledger holds: with the ring not wrapped, the number of `outcome = blocked` entries equals the
//! increase of `dnsBlocked + blockedConnections + httpBlocked`. That is what makes the log and the
//! home screen's "已拦截" answer the same question.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::http::head::HttpRequest;
use crate::http::resource::RequestKind;

/// How many entries are kept across all three kinds (MYS-2742: 500 → 2000).
pub const REQUEST_LOG_CAPACITY: usize = 2000;

/// Longest URL kept per entry.
///
/// A request target can be tens of kilobytes (`?data=` in a URL is common). The log is a diagnostic
/// surface for "why was this blocked", and no rule decision depends on the part beyond this cut, so
/// the URL is truncated rather than letting one request displace the whole ring.
pub const MAX_LOGGED_URL: usize = 512;

/// QUIC drops are recorded at most once per destination tuple in this window (task card §修复②):
/// a browser retrying HTTP/3 over the same IP:port emits datagrams continuously, and one line per
/// datagram would flush the whole ring in a second.
pub const QUIC_DEDUPE_WINDOW: Duration = Duration::from_secs(60);

/// Which layer produced an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LogKind {
    /// One DNS query (blocked, answered or served from cache).
    Dns,
    /// One blocked connection or datagram (SNI/Host rule, refused DoT, dropped QUIC).
    Connection,
    /// One HTTP request judged by the plaintext or decrypted pipeline (M2b).
    Http,
}

/// What happened to one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RequestOutcome {
    /// Resolved / forwarded.
    Allowed,
    /// Blocked.
    Blocked,
    /// Blocked and answered with a `$redirect` substitute.
    Redirected,
    /// A rule matched but an exception cancelled it; forwarded.
    Exception,
    /// Answered from the DNS cache (MYS-2742).
    Cached,
}

/// Why a connection-level block happened (MYS-2742 §修复②).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    /// A filtering rule matched the SNI / `Host`.
    Rule,
    /// The SNI is on the built-in DoH/DoT endpoint list (or a parent domain is).
    EncryptedDns,
    /// A TCP connection to port 853 (DNS over TLS) with the bypass block on.
    Dot,
    /// UDP/443 dropped to force the browser off HTTP/3.
    Quic,
}

impl BlockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockReason::Rule => "rule",
            BlockReason::EncryptedDns => "encrypted_dns",
            BlockReason::Dot => "dot",
            BlockReason::Quic => "quic",
        }
    }
}

/// The `reason` value a DNS entry carries when the block came from the CNAME chain rather than from
/// the queried name itself.
pub const REASON_CNAME: &str = "cname";

/// One entry, as the log and `recentRequestsJson` expose it.
///
/// A single flat shape for all three kinds, because the Kotlin side reads one array and the JSON
/// stays flat. Fields a kind does not use are omitted rather than written as `null`/`false`, so a
/// `dns` line carries nine keys instead of eighteen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestLogEntry {
    /// Monotonic id; the `sinceId` cursor. Shared by all three kinds.
    pub id: u64,
    pub kind: LogKind,
    /// Milliseconds since the tunnel started. Present on **every** entry.
    pub time_ms: u64,
    pub host: String,
    pub outcome: RequestOutcome,
    /// The blocking rule, when the layer can name it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Why it was blocked: `cname` (DNS), or `rule` / `encrypted_dns` / `dot` / `quic`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `kind = "http"` only: the M2b field, same value as [`time_ms`](Self::time_ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_ms: Option<u64>,
    /// `kind = "http"` only: the matched URL, truncated to [`MAX_LOGGED_URL`].
    #[serde(skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// `kind = "http"` only: true when the URL was cut.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    /// `kind = "http"` only.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// `kind = "http"` only: the inferred resource type (`script`, `image`, ...).
    ///
    /// Named `resourceType`, not `kind`: `kind` now identifies the *layer* (MYS-2742), and the two
    /// meanings cannot share one key.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub resource_type: String,
    /// `kind = "http"` only: the exception rule that cancelled a block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_rule: Option<String>,
    /// `kind = "http"` only: whether the request came from another site.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party: Option<bool>,
    /// `kind = "http"` only: whether the response body was rewritten to inject cosmetic rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cosmetic: Option<bool>,
    /// `kind = "dns"` only: `A`, `AAAA`, `HTTPS`, ...
    #[serde(skip_serializing_if = "String::is_empty")]
    pub qtype: String,
    /// `kind = "dns"` only: the CNAME step that was blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
}

impl RequestLogEntry {
    fn new(id: u64, kind: LogKind, time_ms: u64, host: impl Into<String>, outcome: RequestOutcome) -> Self {
        Self {
            id,
            kind,
            time_ms,
            host: host.into(),
            outcome,
            rule: None,
            reason: None,
            at_ms: None,
            url: String::new(),
            truncated: None,
            method: String::new(),
            resource_type: String::new(),
            exception_rule: None,
            third_party: None,
            cosmetic: None,
            qtype: String::new(),
            cname: None,
        }
    }
}

/// The bounded log.
///
/// A `Mutex` around the deque rather than a lock-free ring: entries are pushed once per *event*
/// (tens per second at most next to the work that produced them), and the lock is never held across
/// an await.
pub struct RequestLog {
    entries: Mutex<VecDeque<RequestLogEntry>>,
    next_id: AtomicU64,
    /// Events seen since the tunnel started, including ones dropped because the ring wrapped.
    total: AtomicU64,
    /// Last time each QUIC destination tuple was recorded (see [`QUIC_DEDUPE_WINDOW`]).
    quic_seen: Mutex<HashMap<String, Instant>>,
    started: Instant,
}

impl Default for RequestLog {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::with_capacity(REQUEST_LOG_CAPACITY)),
            next_id: AtomicU64::new(1),
            total: AtomicU64::new(0),
            quic_seen: Mutex::new(HashMap::new()),
            started: Instant::now(),
        }
    }

    /// Milliseconds since the tunnel started, the timestamp every entry carries.
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn allocate_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn push(&self, entry: RequestLogEntry) {
        self.total.fetch_add(1, Ordering::Relaxed);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= REQUEST_LOG_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Record one HTTP request. Returns the entry's id.
    pub fn record(
        &self,
        request: &HttpRequest,
        kind: RequestKind,
        outcome: RequestOutcome,
        rule: Option<String>,
        exception_rule: Option<String>,
        third_party: bool,
    ) -> u64 {
        let id = self.allocate_id();
        let time_ms = self.now_ms();
        let (url, truncated) = truncate(&request.url, MAX_LOGGED_URL);
        let mut entry = RequestLogEntry::new(id, LogKind::Http, time_ms, request.hostname.clone(), outcome);
        entry.at_ms = Some(time_ms);
        entry.url = url;
        entry.truncated = Some(truncated);
        entry.method = request.method.clone();
        entry.resource_type = kind.as_str().to_string();
        entry.rule = rule;
        entry.exception_rule = exception_rule;
        entry.third_party = Some(third_party);
        entry.cosmetic = Some(false);
        self.push(entry);
        id
    }

    /// Record one DNS query (MYS-2742 §修复②).
    ///
    /// Called for every query the engine answers, including the allowed and cache-hit ones, so the
    /// log shows what was *looked up* as well as what was stopped. `cname` is the CNAME step that
    /// was blocked, when the block came from the chain rather than the queried name.
    pub fn record_dns(
        &self,
        host: &str,
        qtype: &str,
        outcome: RequestOutcome,
        cname: Option<String>,
    ) -> u64 {
        let id = self.allocate_id();
        let mut entry = RequestLogEntry::new(id, LogKind::Dns, self.now_ms(), host, outcome);
        entry.qtype = qtype.to_string();
        entry.reason = cname.as_ref().map(|_| REASON_CNAME.to_string());
        entry.cname = cname;
        self.push(entry);
        id
    }

    /// Record one connection-level block.
    ///
    /// `dedupe_key` is `Some(destination)` for QUIC, where the same tuple emits a datagram stream:
    /// only the first datagram per [`QUIC_DEDUPE_WINDOW`] is recorded and `None` is returned for the
    /// rest, which is also what keeps the blocked-entry ledger equal to the counters (the caller
    /// only counts a block when this returns an id).
    pub fn record_connection(
        &self,
        host: &str,
        reason: BlockReason,
        dedupe_key: Option<&str>,
    ) -> Option<u64> {
        if let Some(key) = dedupe_key {
            if !self.first_in_window(key) {
                return None;
            }
        }
        let id = self.allocate_id();
        let mut entry = RequestLogEntry::new(id, LogKind::Connection, self.now_ms(), host, RequestOutcome::Blocked);
        entry.reason = Some(reason.as_str().to_string());
        self.push(entry);
        Some(id)
    }

    /// True when `key` has not been recorded within the dedupe window (and marks it as recorded).
    fn first_in_window(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut seen = self.quic_seen.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(last) = seen.get(key) {
            if now.duration_since(*last) < QUIC_DEDUPE_WINDOW {
                return false;
            }
        }
        // Expired tuples are swept here rather than by a timer: this runs once per dropped datagram
        // and an idle tunnel must not schedule anything (docs/DESIGN.md decision 10).
        if seen.len() >= 64 {
            seen.retain(|_, last| now.duration_since(*last) < QUIC_DEDUPE_WINDOW);
        }
        seen.insert(key.to_string(), now);
        true
    }

    /// Mark one already-recorded request as cosmetically injected.
    ///
    /// Called once the response body has been rewritten, which is after the entry was recorded: the
    /// log is a diagnostic surface for "why was this blocked / why did this page change", and both
    /// facts belong on the same line.
    pub fn mark_cosmetic(&self, id: u64) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
            entry.cosmetic = Some(true);
        }
    }

    /// Entries with `id > since_id`, oldest first.
    pub fn since(&self, since_id: u64) -> Vec<RequestLogEntry> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .filter(|entry| entry.id > since_id)
            .cloned()
            .collect()
    }

    /// Everything currently held, oldest first.
    pub fn snapshot(&self) -> Vec<RequestLogEntry> {
        self.since(0)
    }

    /// Number of entries currently held (not the number ever recorded).
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total events recorded since start (~= events seen, since every event is recorded).
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// The id the next entry will get, so a client can tell "nothing new" from "not started yet".
    pub fn next_id(&self) -> u64 {
        self.next_id.load(Ordering::Relaxed)
    }

    /// Drop every entry (tunnel shutdown, or a `clearRequests`-style request from the control plane).
    ///
    /// The log is memory-only on purpose: it names every host the device talked to, so it must not
    /// survive the tunnel (`docs/DESIGN.md` §11 — no data leaves the device, nothing is persisted).
    pub fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.quic_seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// The log as the JSON array `recentRequestsJson` returns, filtered by `since_id`.
    pub fn to_json(&self, since_id: u64) -> String {
        let entries = self.since(since_id);
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string())
    }
}

/// Cut `text` to at most `limit` bytes on a character boundary.
fn truncate(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_string(), false);
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::head::Version;

    fn request(url: &str) -> HttpRequest {
        let parsed = adblock::url_parser::parse_url(url).expect("test url");
        HttpRequest {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: Version::Http11,
            url: parsed.url.clone(),
            host: parsed.hostname().to_string(),
            hostname: parsed.hostname().to_string(),
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
        }
    }

    fn push(log: &RequestLog, url: &str, outcome: RequestOutcome) -> u64 {
        log.record(
            &request(url),
            RequestKind::Script,
            outcome,
            Some("||ads.example^".to_string()),
            None,
            true,
        )
    }

    #[test]
    fn ids_are_monotonic_and_since_filters_by_them() {
        let log = RequestLog::new();
        let first = push(&log, "http://a.example/1.js", RequestOutcome::Blocked);
        let second = push(&log, "http://a.example/2.js", RequestOutcome::Allowed);
        let third = push(&log, "http://a.example/3.js", RequestOutcome::Blocked);
        assert!(first < second && second < third);

        assert_eq!(log.since(0).len(), 3);
        assert_eq!(log.since(first).len(), 2);
        assert_eq!(log.since(second).len(), 1);
        assert!(log.since(third).is_empty());
        assert!(log.since(u64::MAX).is_empty());
        // A client that has already seen more than we hold gets nothing.
        assert!(log.since(10_000).is_empty());
    }

    #[test]
    fn ids_are_shared_across_kinds() {
        // One cursor, one sequence: a client polling with `sinceId` must not miss a DNS entry just
        // because an HTTP entry took the id before it (MYS-2742).
        let log = RequestLog::new();
        let http = push(&log, "http://a.example/1.js", RequestOutcome::Allowed);
        let dns = log.record_dns("a.example", "A", RequestOutcome::Allowed, None);
        let connection = log
            .record_connection("a.example", BlockReason::Rule, None)
            .expect("logged");
        assert!(http < dns && dns < connection);
        assert_eq!(log.since(http).len(), 2);
        let kinds: Vec<LogKind> = log.snapshot().iter().map(|entry| entry.kind).collect();
        assert_eq!(kinds, vec![LogKind::Http, LogKind::Dns, LogKind::Connection]);
    }

    #[test]
    fn the_ring_wraps_and_keeps_the_newest_entries() {
        let log = RequestLog::new();
        for index in 0..(REQUEST_LOG_CAPACITY + 25) {
            push(&log, &format!("http://a.example/{index}.js"), RequestOutcome::Allowed);
        }
        assert_eq!(log.len(), REQUEST_LOG_CAPACITY);
        let entries = log.snapshot();
        assert_eq!(entries.len(), REQUEST_LOG_CAPACITY);
        // The oldest entries are gone; the newest is the last one pushed.
        assert_eq!(entries.last().expect("last").url, format!("http://a.example/{}.js", REQUEST_LOG_CAPACITY + 24));
        assert!(entries.first().expect("first").id > 1);
        assert_eq!(log.total() as usize, REQUEST_LOG_CAPACITY + 25);
    }

    #[test]
    fn the_capacity_is_two_thousand() {
        // The card fixes N = 2000 (was 500): every DNS query is recorded now, so 500 would wrap in
        // a couple of minutes of browsing.
        assert_eq!(REQUEST_LOG_CAPACITY, 2000);
        let log = RequestLog::new();
        for index in 0..2000 {
            log.record_dns(&format!("h{index}.example"), "A", RequestOutcome::Allowed, None);
        }
        assert_eq!(log.len(), 2000, "the buffer holds exactly its capacity");
        log.record_dns("overflow.example", "A", RequestOutcome::Allowed, None);
        assert_eq!(log.len(), 2000, "and never grows past it");
        let entries = log.snapshot();
        assert_eq!(entries.first().expect("first").host, "h1.example", "the oldest entry was dropped");
        assert_eq!(entries.last().expect("last").host, "overflow.example");
    }

    #[test]
    fn a_wrapped_buffer_still_answers_since_correctly() {
        let log = RequestLog::new();
        for index in 0..(REQUEST_LOG_CAPACITY + 10) {
            push(&log, &format!("http://a.example/{index}.js"), RequestOutcome::Allowed);
        }
        let entries = log.snapshot();
        let middle = entries[entries.len() / 2].id;
        let newer = log.since(middle);
        assert_eq!(newer.len(), entries.len() - entries.len() / 2 - 1);
        assert!(newer.iter().all(|entry| entry.id > middle));
        // Ids stay strictly increasing across the wrap.
        assert!(entries.windows(2).all(|pair| pair[0].id < pair[1].id));
    }

    #[test]
    fn long_urls_are_truncated_and_flagged() {
        let log = RequestLog::new();
        let long = format!("http://a.example/{}", "q".repeat(4096));
        let id = log.record(
            &request(&long),
            RequestKind::Image,
            RequestOutcome::Blocked,
            None,
            None,
            false,
        );
        assert!(id > 0);
        let entry = log.since(0).into_iter().next().expect("entry");
        assert_eq!(entry.url.len(), MAX_LOGGED_URL);
        assert_eq!(entry.truncated, Some(true));
        // Truncation happens on a character boundary, so the result is still valid UTF-8.
        assert!(entry.url.is_char_boundary(entry.url.len()));
    }

    #[test]
    fn truncation_never_splits_a_multibyte_character() {
        let log = RequestLog::new();
        // Each `中` is three bytes, so a 512-byte cut lands in the middle of one.
        let url = format!("http://a.example/{}", "中".repeat(400));
        log.record(
            &request(&url),
            RequestKind::Document,
            RequestOutcome::Blocked,
            None,
            None,
            false,
        );
        let entry = log.since(0).into_iter().next().expect("entry");
        assert_eq!(entry.truncated, Some(true));
        assert!(entry.url.len() <= MAX_LOGGED_URL);
        assert_eq!(entry.url.len() % 3, "http://a.example/".len() % 3);
        // The string is valid UTF-8 by construction; the round trip proves nothing was mangled.
        assert_eq!(entry.url.clone().into_bytes().len(), entry.url.len());
    }

    #[test]
    fn a_short_url_is_not_marked_truncated() {
        let log = RequestLog::new();
        push(&log, "http://a.example/short.js", RequestOutcome::Allowed);
        let entry = log.since(0).into_iter().next().expect("entry");
        assert_eq!(entry.truncated, Some(false));
        assert_eq!(entry.url, "http://a.example/short.js");
    }

    #[test]
    fn a_dns_entry_carries_the_query_fields_and_no_http_ones() {
        let log = RequestLog::new();
        log.record_dns("ads.example.com", "AAAA", RequestOutcome::Blocked, None);
        let entry = log.since(0).into_iter().next().expect("entry");
        assert_eq!(entry.kind, LogKind::Dns);
        assert_eq!(entry.host, "ads.example.com");
        assert_eq!(entry.qtype, "AAAA");
        assert_eq!(entry.outcome, RequestOutcome::Blocked);
        assert!(entry.url.is_empty() && entry.method.is_empty() && entry.resource_type.is_empty());
        assert!(entry.at_ms.is_none() && entry.third_party.is_none() && entry.cosmetic.is_none());
    }

    #[test]
    fn a_cname_block_names_the_step_and_marks_the_reason() {
        let log = RequestLog::new();
        log.record_dns(
            "metrics.clean-site.com",
            "A",
            RequestOutcome::Blocked,
            Some("tracker.doubleclick.net".to_string()),
        );
        let entry = log.since(0).into_iter().next().expect("entry");
        assert_eq!(entry.host, "metrics.clean-site.com");
        assert_eq!(entry.reason.as_deref(), Some(REASON_CNAME));
        assert_eq!(entry.cname.as_deref(), Some("tracker.doubleclick.net"));
    }

    #[test]
    fn a_connection_entry_records_the_reason() {
        let log = RequestLog::new();
        for reason in [
            BlockReason::Rule,
            BlockReason::EncryptedDns,
            BlockReason::Dot,
            BlockReason::Quic,
        ] {
            log.record_connection("ads.example.com", reason, None)
                .expect("logged");
        }
        let reasons: Vec<String> = log
            .snapshot()
            .iter()
            .filter_map(|entry| entry.reason.clone())
            .collect();
        assert_eq!(reasons, vec!["rule", "encrypted_dns", "dot", "quic"]);
        assert!(log.snapshot().iter().all(|entry| entry.kind == LogKind::Connection));
        assert!(log.snapshot().iter().all(|entry| entry.outcome == RequestOutcome::Blocked));
    }

    #[test]
    fn quic_drops_are_deduplicated_per_destination_within_the_window() {
        let log = RequestLog::new();
        assert!(log.record_connection("142.250.74.4", BlockReason::Quic, Some("142.250.74.4:443")).is_some());
        // The same tuple: suppressed, so a browser's HTTP/3 stream cannot flush the ring.
        for _ in 0..100 {
            assert!(log
                .record_connection("142.250.74.4", BlockReason::Quic, Some("142.250.74.4:443"))
                .is_none());
        }
        // A different tuple is a different block.
        assert!(log.record_connection("142.250.74.5", BlockReason::Quic, Some("142.250.74.5:443")).is_some());
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn the_quic_window_expires() {
        // The dedupe table is swept by age, so a tuple recorded before the window is recorded again.
        let log = RequestLog::new();
        assert!(log.record_connection("1.1.1.1", BlockReason::Quic, Some("1.1.1.1:443")).is_some());
        {
            let mut seen = log.quic_seen.lock().expect("lock");
            // Backdate the entry by more than the window instead of sleeping in a unit test.
            seen.insert(
                "1.1.1.1:443".to_string(),
                Instant::now() - QUIC_DEDUPE_WINDOW - Duration::from_secs(1),
            );
        }
        assert!(log.record_connection("1.1.1.1", BlockReason::Quic, Some("1.1.1.1:443")).is_some());
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn non_quic_connection_blocks_are_never_deduplicated() {
        let log = RequestLog::new();
        for _ in 0..3 {
            assert!(log.record_connection("dns.google", BlockReason::EncryptedDns, None).is_some());
        }
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn to_json_is_a_flat_array_with_the_documented_field_names() {
        let log = RequestLog::new();
        log.record(
            &request("http://ads.example.com/banner.js"),
            RequestKind::Script,
            RequestOutcome::Redirected,
            Some("||ads.example.com^$script,redirect=noopjs".to_string()),
            None,
            true,
        );
        let json = log.to_json(0);
        let value: serde_json::Value = serde_json::from_str(&json).expect("json array");
        let array = value.as_array().expect("array");
        assert_eq!(array.len(), 1);
        let entry = &array[0];
        assert_eq!(entry["host"], "ads.example.com");
        assert_eq!(entry["kind"], "http");
        assert_eq!(entry["resourceType"], "script");
        assert_eq!(entry["outcome"], "redirected");
        assert_eq!(entry["method"], "GET");
        assert_eq!(entry["thirdParty"], true);
        assert_eq!(entry["truncated"], false);
        assert_eq!(entry["cosmetic"], false);
        assert_eq!(
            entry["rule"],
            "||ads.example.com^$script,redirect=noopjs"
        );
        assert!(entry["id"].as_u64().unwrap_or(0) > 0);
        // Absent fields are omitted rather than written as null.
        assert!(entry.get("exceptionRule").is_none());
        // Both timestamps are present and identical: `atMs` is the M2b name, `timeMs` the shared one.
        assert!(entry["atMs"].is_u64());
        assert!(entry["timeMs"].is_u64());
        assert_eq!(entry["atMs"], entry["timeMs"]);
    }

    #[test]
    fn a_dns_entry_serializes_without_http_keys() {
        let log = RequestLog::new();
        log.record_dns("ads.example.com", "A", RequestOutcome::Blocked, None);
        let value: serde_json::Value = serde_json::from_str(&log.to_json(0)).expect("json");
        let entry = &value[0];
        assert_eq!(entry["kind"], "dns");
        assert_eq!(entry["qtype"], "A");
        assert_eq!(entry["outcome"], "blocked");
        assert!(entry["timeMs"].is_u64());
        for absent in [
            "atMs", "url", "truncated", "method", "resourceType", "thirdParty", "cosmetic", "rule",
            "cname",
        ] {
            assert!(entry.get(absent).is_none(), "{absent} must be omitted on a dns entry");
        }
    }

    #[test]
    fn a_connection_entry_serializes_the_reason() {
        let log = RequestLog::new();
        log.record_connection("dns.google", BlockReason::Dot, None)
            .expect("logged");
        let value: serde_json::Value = serde_json::from_str(&log.to_json(0)).expect("json");
        let entry = &value[0];
        assert_eq!(entry["kind"], "connection");
        assert_eq!(entry["reason"], "dot");
        assert_eq!(entry["outcome"], "blocked");
        assert_eq!(entry["host"], "dns.google");
    }

    #[test]
    fn outcomes_serialize_in_camel_case() {
        assert_eq!(
            serde_json::to_string(&RequestOutcome::Allowed).expect("json"),
            "\"allowed\""
        );
        assert_eq!(
            serde_json::to_string(&RequestOutcome::Blocked).expect("json"),
            "\"blocked\""
        );
        assert_eq!(
            serde_json::to_string(&RequestOutcome::Redirected).expect("json"),
            "\"redirected\""
        );
        assert_eq!(
            serde_json::to_string(&RequestOutcome::Exception).expect("json"),
            "\"exception\""
        );
        assert_eq!(
            serde_json::to_string(&RequestOutcome::Cached).expect("json"),
            "\"cached\""
        );
    }

    #[test]
    fn kinds_serialize_in_camel_case() {
        assert_eq!(serde_json::to_string(&LogKind::Dns).expect("json"), "\"dns\"");
        assert_eq!(
            serde_json::to_string(&LogKind::Connection).expect("json"),
            "\"connection\""
        );
        assert_eq!(serde_json::to_string(&LogKind::Http).expect("json"), "\"http\"");
    }

    #[test]
    fn an_empty_log_serializes_to_an_empty_array() {
        let log = RequestLog::new();
        assert_eq!(log.to_json(0), "[]");
        assert!(log.is_empty());
        assert_eq!(log.next_id(), 1);
    }

    #[test]
    fn clear_empties_the_buffer_but_not_the_cursor() {
        let log = RequestLog::new();
        push(&log, "http://a.example/1.js", RequestOutcome::Allowed);
        let next = log.next_id();
        log.clear();
        assert!(log.is_empty());
        // A client polling with the id it saw last still gets the entries recorded after the clear.
        let fresh = push(&log, "http://a.example/2.js", RequestOutcome::Allowed);
        assert!(fresh >= next);
        assert_eq!(log.since(next - 1).len(), 1);
    }

    #[test]
    fn clear_forgets_the_quic_dedupe_state() {
        // The dedupe table is part of the log: a stopped tunnel must not leave the next run believing
        // it already reported a destination.
        let log = RequestLog::new();
        assert!(log.record_connection("1.1.1.1", BlockReason::Quic, Some("1.1.1.1:443")).is_some());
        log.clear();
        assert!(log.record_connection("1.1.1.1", BlockReason::Quic, Some("1.1.1.1:443")).is_some());
    }

    #[test]
    fn every_outcome_can_be_recorded() {
        let log = RequestLog::new();
        for outcome in [
            RequestOutcome::Allowed,
            RequestOutcome::Blocked,
            RequestOutcome::Redirected,
            RequestOutcome::Exception,
        ] {
            push(&log, "http://a.example/x.js", outcome);
        }
        let entries = log.snapshot();
        assert_eq!(entries[1].outcome, RequestOutcome::Blocked);
        assert_eq!(entries[2].outcome, RequestOutcome::Redirected);
    }

    #[test]
    fn mark_cosmetic_only_touches_the_named_entry() {
        let log = RequestLog::new();
        let first = push(&log, "http://a.example/1.js", RequestOutcome::Allowed);
        let second = push(&log, "http://a.example/2.js", RequestOutcome::Allowed);
        log.mark_cosmetic(first);
        let entries = log.snapshot();
        assert_eq!(entries[0].cosmetic, Some(true));
        assert_eq!(entries[1].cosmetic, Some(false));
        assert!(entries[0].id < second);
    }
}
