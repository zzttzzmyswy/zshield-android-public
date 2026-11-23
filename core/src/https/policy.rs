//! Which 443 connections are decrypted, and which are left alone.
//!
//! The decision is a pure function of the connection plus the current policy, so every branch is
//! unit-testable without a socket (task card §2):
//!
//! ```text
//! 443 + TLS + httpsFiltering off                    ─▶ passthrough (Resolve::Skip)
//! SNI is on the excluded-host list                  ─▶ passthrough
//! (uid, host) is in the auto-bypass table           ─▶ passthrough
//! owner uid is unknown (API 28, or the lookup failed) ─▶ passthrough
//! owner uid is in `httpsUids` (browsers ∪ user apps) ─▶ decrypt
//! otherwise                                          ─▶ passthrough
//! ```
//!
//! # Owner lookups are expensive and are done once per connection
//!
//! `ConnectivityManager.getConnectionOwnerUid` is a Binder call into the network stack, and a page
//! load opens dozens of connections in a burst. It is therefore asked exactly once for each 443 TLS
//! connection that gets past the local checks, off the worker thread and with a timeout
//! ([`crate::tun::forward`]) — but the *answer* is not cached. See [`UidSelection`] for why a
//! `(source port, remote address)` cache is not safe.
//!
//! # Auto-bypass is per (uid, host), for 24 h
//!
//! A client that does not trust a user CA answers our leaf with `unknown_ca` / `bad_certificate` and
//! retries. Decrypting that host again for that app would break it on every connection, so the pair
//! is remembered and passed through instead (`docs/DESIGN.md` decision 7: 客户端握手失败时该 host 自动
//! 进入临时直通名单). The table is bounded and expired lazily on lookup: no timer runs.
//!
//! # A disconnect is only evidence when the client had no reason to trust us and judged the leaf
//!
//! A browser opens several TLS connections to the same host at once and abandons the losers as soon
//! as one handshake wins. On the wire that is indistinguishable from a pinned app rejecting our
//! certificate — and it used to bypass a host that had *just* been decrypted, so CDN hosts escaped
//! filtering for 24 h. Two facts separate the two, and both are required by [`AutoBypass::observe`]:
//!
//! 1. the same (uid, host) pair did **not** complete a handshake recently ([`AutoBypass`] keeps a
//!    bounded table of the last successful handshakes). A client that just accepted our leaf trusts
//!    it; a disconnect is then a lost race, not a verdict;
//! 2. the client had **already been sent our certificate** ([`HandshakePhase`]). A connection that
//!    died before that never saw the leaf, so it cannot have judged it.
//!
//! An explicit alert (`unknown_ca` / `bad_certificate` / `certificate_unknown`) still bypasses on the
//! spot: it is the client's stated verdict and neither rule above applies to it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long an auto-bypass entry lasts (task card §4: 24 h).
pub const AUTO_BYPASS_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long a `client_disconnect` is remembered while waiting for its second occurrence.
///
/// A bare disconnect is not evidence of anything: closing a tab, switching networks and a client's
/// own handshake timeout all look the same on the wire. Two of them for the same (uid, host) inside
/// this window is evidence; one is not.
pub const DISCONNECT_PROBATION: Duration = Duration::from_secs(10 * 60);

/// How long one completed downstream handshake vouches for the client's trust in our leaf.
///
/// A client that finished a handshake for this (uid, host) a moment ago does accept our certificate,
/// so a disconnect in the same window is a connection that lost a race, not a verdict. Same ten
/// minutes as the second-strike window: one window, one meaning — "recent enough to be the same
/// page load".
pub const SUCCESS_TRUST_WINDOW: Duration = DISCONNECT_PROBATION;

/// Upper bound of the successful-handshake table. One entry is a uid plus a hostname; the cap only
/// exists so a client that cycles through hostnames cannot grow it without bound.
pub const MAX_RECENT_SUCCESS: usize = 1024;

/// Upper bound of auto-bypass entries. Each entry is a uid plus a hostname, so the table is small;
/// the cap only exists so a client that cycles through hostnames cannot grow it without bound.
pub const MAX_AUTO_BYPASS: usize = 1024;

/// Port of HTTPS.
pub const PORT_HTTPS: u16 = 443;

/// Why a connection was not decrypted. Every variant is a counter or a log line, never a silent drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// `httpsFiltering` is off, or the CA is not installed (the control plane's `httpsFiltering`
    /// flag already folds the CA state in, so this is one check).
    Disabled,
    /// The destination port is not 443.
    NotHttps,
    /// The SNI is on the excluded list (banking, payments, pinned hosts).
    ExcludedHost,
    /// This (app, host) pair already failed a handshake and is passed through for 24 h.
    AutoBypassed,
    /// The owning application could not be determined, so nothing may be decrypted.
    UnknownOwner,
    /// The owning application is not on the browser list and the user did not select it.
    AppNotSelected,
    /// The ClientHello carried no SNI, so there is no name to issue a leaf for. ECH (which would
    /// hide it) is stripped by the DNS layer, and a real browser always sends SNI, but a client
    /// speaking to an IP literal does not.
    NoSni,
}

/// What to do with one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolve {
    /// Decrypt and filter.
    Decrypt,
    /// Relay verbatim.
    Skip(SkipReason),
}

/// Asked for the owner of a live TCP connection: `(local, remote)` → uid.
///
/// A trait rather than a `ConnectivityManager` handle so the decision logic can be tested on the
/// host, where there is no Android network stack. `None` means "unknown", which is always a skip.
pub trait OwnerLookup: Send + Sync {
    fn owner_uid(&self, local: SocketAddr, remote: SocketAddr) -> Option<u32>;
}

/// A lookup that never knows, for builds and tests without a JVM.
#[derive(Debug, Default)]
pub struct NoOwnerLookup;

impl OwnerLookup for NoOwnerLookup {
    fn owner_uid(&self, _local: SocketAddr, _remote: SocketAddr) -> Option<u32> {
        None
    }
}

/// The rule set for "may this connection be decrypted".
#[derive(Debug, Clone, Default)]
pub struct HttpsPolicy {
    /// False when the user turned HTTPS filtering off or the CA is not installed.
    pub enabled: bool,
    /// uids of the selected applications (browser list ∪ the user's own picks).
    pub uids: Vec<u32>,
    /// Lowercased hostnames (and their subdomains) that must never be decrypted.
    pub excluded_hosts: Vec<String>,
}

impl HttpsPolicy {
    /// True when `host` is excluded, or is a subdomain of an excluded name.
    ///
    /// Subdomain matching matters for exactly the reason `Policy::is_encrypted_dns_host` needs it: a
    /// list that names `alipay.com` must also cover `pay.alipay.com`, or the exclusion is worthless.
    pub fn is_excluded(&self, host: &str) -> bool {
        if self.excluded_hosts.is_empty() {
            return false;
        }
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        let mut candidate = host.as_str();
        loop {
            if self
                .excluded_hosts
                .iter()
                .any(|excluded| excluded == candidate)
            {
                return true;
            }
            match candidate.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => candidate = rest,
                _ => return false,
            }
        }
    }

    /// True when `uid` is one of the selected applications.
    pub fn is_selected(&self, uid: u32) -> bool {
        self.uids.contains(&uid)
    }

    /// Parse the `excluded-hosts.txt`/`browsers.txt` line format: one entry per line, `#` comments,
    /// blank lines ignored, names lowercased with a trailing dot removed.
    ///
    /// The parser is shared by both asset files because they have the same shape; what differs is
    /// only how the caller uses the result (a host list vs. a package list).
    pub fn parse_list(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            // Allow a hosts-file style `<ip> <name>` row to be pasted in without breaking.
            let name = line.split_whitespace().last().unwrap_or(line);
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            if !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }
}

/// Holds the selected-uid set so a settings write can hot-reload it without rebuilding the tunnel.
///
/// # Why the owner answer is *not* cached here
///
/// An earlier version cached `getConnectionOwnerUid` by `(source port, remote address)`. That key is
/// not a connection identity: two applications behind the same tunnel can be handed the same source
/// port towards the same `IP:443` once the first connection closes, and the second one would then
/// inherit the first one's uid. The failure mode is exactly the one the whole design tries to avoid —
/// an application the user never selected gets decrypted, which breaks a pinned app or a bank. The
/// lookup therefore runs once per 443 TLS connection and its answer is never reused
/// ([`crate::tun::forward`] does the call off the worker, see `docs/JNI.md` §7.5).
#[derive(Debug, Default)]
pub struct UidSelection {
    selected: Mutex<Vec<u32>>,
}

impl UidSelection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the selected-uid set (a settings change hot-reloads it).
    pub fn set_selected(&self, uids: Vec<u32>) {
        *self.selected.lock().unwrap_or_else(|e| e.into_inner()) = uids;
    }

    /// Selected uids currently in force.
    pub fn selected(&self) -> Vec<u32> {
        self.selected
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// One auto-bypass entry: an application and a host that does not trust our CA.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BypassEntry {
    pub uid: u32,
    pub host: String,
    /// Milliseconds since the Unix epoch, for `httpsBypassJson`.
    pub expires_at_ms: i64,
    /// Why the entry exists (`client_unknown_ca`, `client_bad_certificate`, `client_disconnect`).
    pub reason: &'static str,
}

/// Why a client-side handshake failed, as recorded by [`crate::https::mitm`].
///
/// The distinction is load-bearing: an explicit alert means the client has *judged* our certificate
/// and will judge the next one the same way, while a disconnect means nothing at all. Only the first
/// kind bypasses on the spot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFailure {
    /// The client sent `unknown_ca` / `bad_certificate` / `certificate_unknown`: it does not accept
    /// our CA and will not accept it on the next connection either.
    CertificateRejected(&'static str),
    /// The client went away during the handshake. Closing a tab looks identical.
    Disconnect(&'static str),
    /// Something on our side went wrong (leaf issuance, an internal TLS error). Never a reason to
    /// stop filtering: it is counted and the next connection is decrypted again.
    Local(&'static str),
}

/// How far the downstream handshake had got when the client went away.
///
/// A client that leaves before our Certificate message was sent never saw the leaf, so its departure
/// says nothing about whether it trusts the CA — a connection that is still fetching its DNS answer
/// and gives up looks exactly the same. Only a departure *after* the certificate is evidence, and
/// even then only on the second sighting ([`AutoBypass::observe`]).
///
/// [`crate::https::mitm`] answers it from the certificate resolver: rustls asks it for a leaf exactly
/// when it is building the Certificate message of this handshake, and never before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    /// The client left before rustls selected (and therefore before it sent) our certificate.
    BeforeCertificate,
    /// Our certificate was already on its way to the client when the handshake ended.
    AfterCertificate,
}

/// What one client-side handshake failure did to the auto-bypass table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The pair is now on the auto-bypass list, for [`AUTO_BYPASS_TTL`].
    Bypassed,
    /// A disconnect was recorded as the first strike; nothing is bypassed yet.
    Recorded,
    /// A disconnect that was counted but changed nothing: the client completed a handshake for this
    /// pair recently, or it went away before our certificate reached it.
    DisconnectIgnored,
    /// Our own failure. Counted as a handshake failure, never a reason to stop filtering.
    LocalFailure,
}

impl Verdict {
    /// True when the pair is bypassed now.
    pub fn is_bypassed(self) -> bool {
        matches!(self, Verdict::Bypassed)
    }
}

impl ClientFailure {
    /// The short stable name stored in the bypass table and shown by `httpsBypassJson`.
    pub fn reason(self) -> &'static str {
        match self {
            ClientFailure::CertificateRejected(reason)
            | ClientFailure::Disconnect(reason)
            | ClientFailure::Local(reason) => reason,
        }
    }

    /// True for anything that may put the pair on the bypass list.
    pub fn is_client_caused(self) -> bool {
        !matches!(self, ClientFailure::Local(_))
    }
}

/// One auto-bypass entry as stored: when it was recorded, and why.
type BypassRecord = (Instant, &'static str);
/// The (uid, host) key of the auto-bypass table.
type BypassKey = (u32, String);

/// Lowercase a hostname and drop a trailing root dot, the form every table here is keyed on.
fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The (uid, host) auto-bypass table, plus the two pieces of evidence that qualify a disconnect.
#[derive(Debug)]
pub struct AutoBypass {
    entries: Mutex<HashMap<BypassKey, BypassRecord>>,
    /// Disconnect sightings that have not yet become a bypass entry: `(uid, host)` → first sighting.
    probation: Mutex<HashMap<BypassKey, Instant>>,
    /// `(uid, host)` → the last downstream handshake this pair completed. A pair in this table has
    /// proved it accepts our leaf; see [`AutoBypass::observe`].
    successes: Mutex<HashMap<BypassKey, Instant>>,
    ttl: Duration,
    probation_window: Duration,
    success_window: Duration,
}

impl Default for AutoBypass {
    fn default() -> Self {
        Self::new(AUTO_BYPASS_TTL)
    }
}

impl AutoBypass {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            probation: Mutex::new(HashMap::new()),
            successes: Mutex::new(HashMap::new()),
            ttl,
            probation_window: DISCONNECT_PROBATION,
            success_window: SUCCESS_TRUST_WINDOW,
        }
    }

    /// Override the second-strike window (tests only need this to keep them fast).
    pub fn with_probation(mut self, window: Duration) -> Self {
        self.probation_window = window;
        self
    }

    /// Override how long a completed handshake vouches for the client's trust (tests only).
    pub fn with_success_window(mut self, window: Duration) -> Self {
        self.success_window = window;
        self
    }

    /// Remember that `uid` completed a downstream handshake for `host`, i.e. that it accepts our leaf.
    ///
    /// Called once per decrypted connection, so this is a hot path and does the minimum: one insert
    /// under a short-lived lock. Expired entries are *not* swept on every call — a stale timestamp is
    /// already treated as absent by [`Self::trusted_recently`], so it can only mislead nobody — they
    /// are swept when the table reaches [`MAX_RECENT_SUCCESS`], which is also when an eviction has to
    /// choose a victim anyway.
    pub fn record_success(&self, uid: u32, host: &str) {
        let host = normalize_host(host);
        if host.is_empty() {
            return;
        }
        let key = (uid, host);
        let now = Instant::now();
        {
            let mut successes = self.successes.lock().unwrap_or_else(|e| e.into_inner());
            if successes.len() >= MAX_RECENT_SUCCESS && !successes.contains_key(&key) {
                let window = self.success_window;
                successes.retain(|_, seen| now.duration_since(*seen) < window);
                if successes.len() >= MAX_RECENT_SUCCESS {
                    // Still full of live entries: drop the oldest sighting. It is the one closest to
                    // expiring anyway, and forgetting it only means that pair has to prove itself
                    // again — which its next completed handshake does.
                    let oldest = successes
                        .iter()
                        .min_by_key(|(_, seen)| **seen)
                        .map(|(key, _)| key.clone());
                    if let Some(oldest) = oldest {
                        successes.remove(&oldest);
                    }
                }
            }
            successes.insert(key.clone(), now);
        }
        // A client that just accepted our leaf is not one that rejected it, so half-finished
        // second-strike evidence for this pair is stale: without this, one disconnect from before a
        // successful handshake plus one from after it would still add up to a bypass.
        self.probation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }

    /// True when this pair completed a handshake within [`SUCCESS_TRUST_WINDOW`].
    pub fn trusted_recently(&self, uid: u32, host: &str) -> bool {
        let host = normalize_host(host);
        if host.is_empty() {
            return false;
        }
        let key = (uid, host);
        let now = Instant::now();
        let mut successes = self.successes.lock().unwrap_or_else(|e| e.into_inner());
        match successes.get(&key) {
            Some(seen) if now.duration_since(*seen) < self.success_window => true,
            Some(_) => {
                successes.remove(&key);
                false
            }
            None => false,
        }
    }

    /// Record how one client-side handshake failure affects the bypass table.
    ///
    /// - an explicit certificate alert bypasses immediately, whatever the phase and whatever the
    ///   recent-success table says: it is the client stating that it judged our leaf;
    /// - a disconnect is **ignored** (counted by the caller, but not as evidence) when the same pair
    ///   completed a handshake within [`SUCCESS_TRUST_WINDOW`] — the client trusts us, so this is a
    ///   racing connection losing, not a verdict — or when it happened before our certificate was
    ///   sent ([`HandshakePhase::BeforeCertificate`]), where the client never saw anything to judge;
    /// - any other disconnect bypasses on the second sighting within [`DISCONNECT_PROBATION`]: one
    ///   disconnect is a closed tab, not a verdict;
    /// - a local failure changes nothing.
    pub fn observe(
        &self,
        uid: u32,
        host: &str,
        failure: ClientFailure,
        phase: HandshakePhase,
    ) -> Verdict {
        match failure {
            ClientFailure::CertificateRejected(reason) => {
                self.record(uid, host, reason);
                Verdict::Bypassed
            }
            ClientFailure::Disconnect(reason) => {
                let host = normalize_host(host);
                if host.is_empty() {
                    return Verdict::DisconnectIgnored;
                }
                let key = (uid, host);
                if phase == HandshakePhase::BeforeCertificate
                    || self.trusted_recently(uid, &key.1)
                {
                    return Verdict::DisconnectIgnored;
                }
                let now = Instant::now();
                let mut probation = self.probation.lock().unwrap_or_else(|e| e.into_inner());
                // Expired sightings are dropped on the way past, so no timer is ever needed.
                probation.retain(|_, seen| now.duration_since(*seen) < self.probation_window);
                match probation.remove(&key) {
                    Some(_) => {
                        drop(probation);
                        self.record(uid, &key.1, reason);
                        Verdict::Bypassed
                    }
                    None => {
                        probation.insert(key, now);
                        Verdict::Recorded
                    }
                }
            }
            ClientFailure::Local(_) => Verdict::LocalFailure,
        }
    }

    /// True when this pair is currently bypassed. Expired entries are dropped on the way past.
    pub fn is_bypassed(&self, uid: u32, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        match entries.get(&(uid, host.clone())) {
            Some((added, _)) if now.duration_since(*added) < self.ttl => true,
            Some(_) => {
                entries.remove(&(uid, host));
                false
            }
            None => false,
        }
    }

    /// Remember that `uid` does not accept our certificate for `host`.
    pub fn record(&self, uid: u32, host: &str, reason: &'static str) {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_AUTO_BYPASS && !entries.contains_key(&(uid, host.clone())) {
            // Drop whatever expired first; if nothing has, drop an arbitrary entry. A bound that is
            // occasionally wrong about *which* entry it forgets is fine here — forgetting one means
            // that app gets decrypted once more and re-adds itself if it still fails.
            let now = Instant::now();
            let ttl = self.ttl;
            let expired = entries
                .iter()
                .find(|(_, (added, _))| now.duration_since(*added) >= ttl)
                .map(|(key, _)| key.clone());
            match expired {
                Some(key) => {
                    entries.remove(&key);
                }
                None => {
                    if let Some(key) = entries.keys().next().cloned() {
                        entries.remove(&key);
                    }
                }
            }
        }
        entries.insert((uid, host), (Instant::now(), reason));
    }

    /// The live entries, newest expiry last, for `httpsBypassJson`.
    pub fn snapshot(&self, now_ms: i64) -> Vec<BypassEntry> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, (added, _)| now.duration_since(*added) < self.ttl);
        let mut out: Vec<BypassEntry> = entries
            .iter()
            .map(|((uid, host), (added, reason))| {
                let remaining = self.ttl.saturating_sub(now.duration_since(*added));
                BypassEntry {
                    uid: *uid,
                    host: host.clone(),
                    expires_at_ms: now_ms + remaining.as_millis() as i64,
                    reason,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            a.uid
                .cmp(&b.uid)
                .then_with(|| a.host.cmp(&b.host))
        });
        out
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        // A cleared table must not leave half a second-strike behind: the next disconnect would
        // otherwise bypass a pair the user just un-bypassed.
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.probation
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        self.successes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// How many pairs are currently remembered as having completed a handshake (tests, and the
    /// bound assertion).
    pub fn recent_success_len(&self) -> usize {
        self.successes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

/// How long the owner lookup may take before the connection is passed through.
///
/// `getConnectionOwnerUid` is a Binder call into `system_server` with no timeout of its own. A worker
/// thread is far too expensive to block on that: the runtime defaults to a handful of them, so one
/// slow system call would stall every other connection in the tunnel. 200 ms is far above the
/// observed cost (a local Binder round trip) and far below anything a user would notice.
pub const OWNER_LOOKUP_TIMEOUT: Duration = Duration::from_millis(200);

/// Ask for a connection's owner without blocking the runtime.
///
/// Two problems are solved together: the lookup is a blocking call, so it runs on the blocking pool
/// rather than a worker ([`tokio::task::spawn_blocking`]); and it has no timeout of its own, so the
/// wait is bounded here. A timeout is not an error: it means "unknown owner", and an unknown owner is
/// never decrypted, which is the safe answer.
pub async fn lookup_owner(
    lookup: Arc<dyn OwnerLookup>,
    local: SocketAddr,
    remote: SocketAddr,
) -> Option<u32> {
    let task = tokio::task::spawn_blocking(move || lookup.owner_uid(local, remote));
    match tokio::time::timeout(OWNER_LOOKUP_TIMEOUT, task).await {
        Ok(Ok(uid)) => uid,
        Ok(Err(err)) => {
            // A panicking lookup must not take the connection down with it; "unknown" is enough.
            crate::log_msg("debug", &format!("owner lookup for {remote} failed: {err}"));
            None
        }
        Err(_) => {
            crate::log_msg(
                "debug",
                &format!(
                    "owner lookup for {remote} timed out after {} ms; passing through",
                    OWNER_LOOKUP_TIMEOUT.as_millis()
                ),
            );
            None
        }
    }
}

/// The whole "should this connection be decrypted" decision, as one call.
///
/// The order of the checks is the one in the module docs and it matters: every local check that can
/// be answered from the ClientHello alone comes before the Binder lookup, so a connection that is
/// never going to be decrypted does not cost one.
pub fn decide(
    policy: &HttpsPolicy,
    bypass: &AutoBypass,
    host: Option<&str>,
    target_port: u16,
    owner: impl FnOnce() -> Option<u32>,
) -> (Resolve, Option<u32>) {
    let (needs_owner, decided) = decide_without_owner(policy, bypass, host, target_port);
    match decided {
        Some(resolve) => (resolve, None),
        None if needs_owner => decide_with_owner(policy, bypass, host, target_port, owner()),
        // No owner can change the outcome; answering "unknown" gives the same skip reason.
        None => decide_with_owner(policy, bypass, host, target_port, None),
    }
}

/// The part of [`decide`] that needs no owner lookup.
///
/// Returns `(needs_owner, Some(resolve))` when the answer is already known, and `(true, None)` when
/// the owner is required — which is what lets the caller avoid the blocking Binder call entirely for
/// a connection that is never going to be decrypted. `(false, None)` means the owner cannot change
/// anything either, and the caller may answer without looking it up.
pub fn decide_without_owner(
    policy: &HttpsPolicy,
    _bypass: &AutoBypass,
    host: Option<&str>,
    target_port: u16,
) -> (bool, Option<Resolve>) {
    if !policy.enabled {
        return (false, Some(Resolve::Skip(SkipReason::Disabled)));
    }
    if target_port != PORT_HTTPS {
        return (false, Some(Resolve::Skip(SkipReason::NotHttps)));
    }
    let Some(host) = host else {
        return (false, Some(Resolve::Skip(SkipReason::NoSni)));
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return (false, Some(Resolve::Skip(SkipReason::NoSni)));
    }
    if policy.is_excluded(&host) {
        return (false, Some(Resolve::Skip(SkipReason::ExcludedHost)));
    }
    // An empty selection decrypts nothing, so there is no point asking who owns the connection.
    if policy.uids.is_empty() {
        return (false, Some(Resolve::Skip(SkipReason::AppNotSelected)));
    }
    (true, None)
}

/// [`decide`] once the owner is known (or known to be unknown).
pub fn decide_with_owner(
    policy: &HttpsPolicy,
    bypass: &AutoBypass,
    host: Option<&str>,
    target_port: u16,
    owner: Option<u32>,
) -> (Resolve, Option<u32>) {
    if let (_, Some(resolve)) = decide_without_owner(policy, bypass, host, target_port) {
        return (resolve, None);
    }
    let Some(host) = host else {
        return (Resolve::Skip(SkipReason::NoSni), None);
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let Some(uid) = owner else {
        return (Resolve::Skip(SkipReason::UnknownOwner), None);
    };
    if bypass.is_bypassed(uid, &host) {
        return (Resolve::Skip(SkipReason::AutoBypassed), Some(uid));
    }
    if !policy.is_selected(uid) {
        return (Resolve::Skip(SkipReason::AppNotSelected), Some(uid));
    }
    (Resolve::Decrypt, Some(uid))
}

/// Whether an address family/port pair is worth even asking about: only 443 TCP is decrypted, and
/// the caller uses this to avoid the owner lookup for everything else.
pub fn is_https_port(port: u16) -> bool {
    port == PORT_HTTPS
}

/// True when the address is a loopback or otherwise local address, which never needs decryption.
///
/// A tunnelled connection whose destination is the tunnel itself or a link-local address cannot be
/// a public HTTPS site, and issuing a leaf for it would only add latency.
pub fn is_local_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique-local (fc00::/7) and link-local (fe80::/10).
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn policy() -> HttpsPolicy {
        HttpsPolicy {
            enabled: true,
            uids: vec![10_123, 10_456],
            excluded_hosts: HttpsPolicy::parse_list(
                "# banks\nbank.example\npay.example\n",
            ),
        }
    }

    #[test]
    fn a_selected_application_on_a_normal_host_is_decrypted() {
        let bypass = AutoBypass::default();
        let (resolve, uid) = decide(
            &policy(),
            &bypass,
            Some("www.example.com"),
            443,
            || Some(10_123),
        );
        assert_eq!(resolve, Resolve::Decrypt);
        assert_eq!(uid, Some(10_123));
    }

    #[test]
    fn filtering_off_or_a_non_https_port_is_never_decrypted() {
        let bypass = AutoBypass::default();
        let mut off = policy();
        off.enabled = false;
        assert_eq!(
            decide(&off, &bypass, Some("www.example.com"), 443, || Some(10_123)).0,
            Resolve::Skip(SkipReason::Disabled)
        );
        assert_eq!(
            decide(&policy(), &bypass, Some("www.example.com"), 8443, || Some(10_123)).0,
            Resolve::Skip(SkipReason::NotHttps)
        );
    }

    #[test]
    fn an_excluded_host_is_never_decrypted_even_for_a_browser() {
        let bypass = AutoBypass::default();
        for host in ["bank.example", "pay.example", "secure.bank.example", "BANK.example."] {
            assert_eq!(
                decide(&policy(), &bypass, Some(host), 443, || Some(10_123)).0,
                Resolve::Skip(SkipReason::ExcludedHost),
                "{host} must be excluded"
            );
        }
        // A name that merely contains an excluded one is not excluded.
        assert_eq!(
            decide(&policy(), &bypass, Some("notbank.example"), 443, || Some(10_123)).0,
            Resolve::Decrypt
        );
    }

    #[test]
    fn an_unknown_owner_is_never_decrypted() {
        // API 28 and a failed Binder lookup both land here, and decrypting on a guess would break
        // the application that owns the connection.
        let bypass = AutoBypass::default();
        assert_eq!(
            decide(&policy(), &bypass, Some("www.example.com"), 443, || None).0,
            Resolve::Skip(SkipReason::UnknownOwner)
        );
    }

    #[test]
    fn an_unselected_application_is_not_decrypted() {
        let bypass = AutoBypass::default();
        let (resolve, uid) = decide(
            &policy(),
            &bypass,
            Some("www.example.com"),
            443,
            || Some(10_999),
        );
        assert_eq!(resolve, Resolve::Skip(SkipReason::AppNotSelected));
        assert_eq!(uid, Some(10_999));
    }

    #[test]
    fn a_missing_sni_is_not_decrypted() {
        let bypass = AutoBypass::default();
        assert_eq!(
            decide(&policy(), &bypass, None, 443, || Some(10_123)).0,
            Resolve::Skip(SkipReason::NoSni)
        );
        assert_eq!(
            decide(&policy(), &bypass, Some("  "), 443, || Some(10_123)).0,
            Resolve::Skip(SkipReason::NoSni)
        );
    }

    #[test]
    fn an_auto_bypassed_pair_is_not_decrypted_again() {
        let bypass = AutoBypass::default();
        assert_eq!(
            decide(&policy(), &bypass, Some("www.example.com"), 443, || Some(10_123)).0,
            Resolve::Decrypt
        );
        bypass.record(10_123, "www.example.com", "client_unknown_ca");
        assert_eq!(
            decide(&policy(), &bypass, Some("WWW.Example.com."), 443, || Some(10_123)).0,
            Resolve::Skip(SkipReason::AutoBypassed)
        );
        // Another application is unaffected: the table is per (uid, host).
        assert_eq!(
            decide(&policy(), &bypass, Some("www.example.com"), 443, || Some(10_456)).0,
            Resolve::Decrypt
        );
        // So is another host for the same application.
        assert_eq!(
            decide(&policy(), &bypass, Some("other.example.com"), 443, || Some(10_123)).0,
            Resolve::Decrypt
        );
    }

    #[test]
    fn the_local_checks_come_before_the_owner_lookup() {
        // The owner lookup is a Binder round trip into the network stack, so a connection that is
        // never going to be decrypted for a reason visible in the ClientHello alone must not pay for
        // it. A closure that panics proves the ordering.
        let bypass = AutoBypass::default();
        for (host, port, expected) in [
            ("bank.example", 443, SkipReason::ExcludedHost),
            ("www.example.com", 8443, SkipReason::NotHttps),
        ] {
            let (resolve, _) = decide(&policy(), &bypass, Some(host), port, || {
                panic!("the owner must not be looked up for {host}:{port}")
            });
            assert_eq!(resolve, Resolve::Skip(expected));
        }
        let (resolve, _) = decide(&policy(), &bypass, None, 443, || {
            panic!("the owner must not be looked up without a host name")
        });
        assert_eq!(resolve, Resolve::Skip(SkipReason::NoSni));
    }

    #[test]
    fn an_auto_bypassed_pair_costs_no_second_lookup() {
        // The table is keyed on (uid, host), so the owner has to be known once. What must not happen
        // is the *lookup cache* being consulted again for a pair that is already bypassed: the
        // second call is answered from the bypass table, before the policy's own work.
        let bypass = AutoBypass::default();
        bypass.record(10_123, "www.example.com", "client_bad_certificate");
        let (resolve, uid) = decide(&policy(), &bypass, Some("www.example.com"), 443, || Some(10_123));
        assert_eq!(resolve, Resolve::Skip(SkipReason::AutoBypassed));
        assert_eq!(uid, Some(10_123), "the caller still learns the owner");
    }

    #[test]
    fn bypass_entries_expire() {
        let bypass = AutoBypass::new(Duration::from_millis(30));
        bypass.record(10_123, "www.example.com", "client_unknown_ca");
        assert!(bypass.is_bypassed(10_123, "www.example.com"));
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !bypass.is_bypassed(10_123, "www.example.com"),
            "an expired entry must not bypass anything"
        );
        assert_eq!(bypass.len(), 0, "the expired entry is dropped on lookup");
    }

    #[test]
    fn the_bypass_table_is_bounded() {
        let bypass = AutoBypass::default();
        for index in 0..MAX_AUTO_BYPASS + 16 {
            bypass.record(10_123, &format!("host{index}.example"), "client_unknown_ca");
        }
        assert!(bypass.len() <= MAX_AUTO_BYPASS, "{}", bypass.len());
    }

    #[test]
    fn the_bypass_snapshot_describes_each_entry() {
        let bypass = AutoBypass::default();
        bypass.record(20, "b.example", "client_unknown_ca");
        bypass.record(10, "a.example", "client_bad_certificate");
        let snapshot = bypass.snapshot(1_700_000_000_000);
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].uid, 10, "sorted by uid");
        assert_eq!(snapshot[0].host, "a.example");
        assert_eq!(snapshot[0].reason, "client_bad_certificate");
        assert_eq!(snapshot[1].uid, 20);
        // The expiry is in the future, by at most the TTL.
        for entry in &snapshot {
            assert!(entry.expires_at_ms > 1_700_000_000_000);
            assert!(
                entry.expires_at_ms <= 1_700_000_000_000 + AUTO_BYPASS_TTL.as_millis() as i64
            );
        }
    }

    #[test]
    fn host_lists_are_parsed_like_the_other_asset_lists() {
        let hosts = HttpsPolicy::parse_list(
            "\
# comment
bank.example
  10.0.0.1 hosts.example   # trailing comment
UPPER.example.
",
        );
        assert_eq!(
            hosts,
            vec![
                "bank.example".to_string(),
                "hosts.example".to_string(),
                "upper.example".to_string()
            ]
        );
        // Duplicates collapse.
        assert_eq!(HttpsPolicy::parse_list("a.example\na.example\n"), vec!["a.example"]);
    }

    #[test]
    fn the_selected_uid_set_can_be_replaced() {
        let selection = UidSelection::new();
        assert!(selection.selected().is_empty());
        selection.set_selected(vec![1, 2, 3]);
        assert_eq!(selection.selected(), vec![1, 2, 3]);
        selection.set_selected(vec![4]);
        assert_eq!(selection.selected(), vec![4]);
    }

    #[test]
    fn a_single_disconnect_does_not_bypass_but_a_second_one_does() {
        // Closing a tab and switching networks both end a handshake with an EOF, and neither says
        // anything about whether the client trusts our CA. Bypassing on the first one would turn a
        // normal user action into a day of unfiltered traffic. The pair never completed a handshake,
        // so the M3a second-strike rule is what decides here.
        let bypass = AutoBypass::default();
        let after = HandshakePhase::AfterCertificate;
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Recorded
        );
        assert!(!bypass.is_bypassed(10_123, "www.example.com"));
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Bypassed,
            "the second sighting must bypass"
        );
        assert!(bypass.is_bypassed(10_123, "www.example.com"));
        assert_eq!(bypass.snapshot(0)[0].reason, "client_disconnect");
    }

    #[test]
    fn a_disconnect_window_expires() {
        let bypass = AutoBypass::default().with_probation(Duration::from_millis(30));
        let after = HandshakePhase::AfterCertificate;
        bypass.observe(
            10_123,
            "www.example.com",
            ClientFailure::Disconnect("client_disconnect"),
            after,
        );
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Recorded,
            "a sighting older than the window must not count as the first strike"
        );
        assert!(!bypass.is_bypassed(10_123, "www.example.com"));
    }

    #[test]
    fn an_explicit_certificate_alert_bypasses_at_once() {
        let bypass = AutoBypass::default();
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::CertificateRejected("client_unknown_ca"),
                HandshakePhase::AfterCertificate,
            ),
            Verdict::Bypassed
        );
        assert!(bypass.is_bypassed(10_123, "www.example.com"));
        assert_eq!(bypass.snapshot(0)[0].reason, "client_unknown_ca");
    }

    #[test]
    fn a_local_failure_never_bypasses() {
        // Leaf issuance failing is our bug, not the client's verdict: bypassing would silently stop
        // filtering that host for a day and hide the bug.
        let bypass = AutoBypass::default();
        for _ in 0..5 {
            assert_eq!(
                bypass.observe(
                    10_123,
                    "www.example.com",
                    ClientFailure::Local("local_issue"),
                    HandshakePhase::AfterCertificate,
                ),
                Verdict::LocalFailure
            );
        }
        assert!(!bypass.is_bypassed(10_123, "www.example.com"));
        assert!(bypass.is_empty());
    }

    #[test]
    fn clearing_the_table_also_clears_pending_disconnects() {
        let bypass = AutoBypass::default();
        let after = HandshakePhase::AfterCertificate;
        bypass.observe(
            10_123,
            "www.example.com",
            ClientFailure::Disconnect("client_disconnect"),
            after,
        );
        bypass.clear();
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Recorded,
            "after a clear the next disconnect is a first strike again"
        );
        assert!(!bypass.is_bypassed(10_123, "www.example.com"));
    }

    // -----------------------------------------------------------------------------------------
    // MYS-2727: a racing browser connection is not a certificate verdict
    // -----------------------------------------------------------------------------------------

    #[test]
    fn disconnects_after_a_successful_handshake_are_ignored() {
        // The reported failure: Chrome opens several TLS connections to one host at once, one wins,
        // and it aborts the rest mid-handshake. Five of those used to bypass a host that had just
        // been decrypted, so its CDN assets escaped filtering for 24 h.
        let bypass = AutoBypass::default();
        bypass.record_success(10_123, "github.githubassets.com");
        for attempt in 0..5 {
            assert_eq!(
                bypass.observe(
                    10_123,
                    "github.githubassets.com",
                    ClientFailure::Disconnect("client_disconnect"),
                    HandshakePhase::AfterCertificate,
                ),
                Verdict::DisconnectIgnored,
                "disconnect #{attempt} after a successful handshake must not count"
            );
            assert!(
                !bypass.is_bypassed(10_123, "github.githubassets.com"),
                "the host must stay decrypted"
            );
        }
        assert!(bypass.is_empty(), "nothing may be in the bypass table");
    }

    #[test]
    fn a_host_that_never_succeeded_still_bypasses_on_the_second_disconnect() {
        // The M3a behaviour, unchanged, for the client it was written for: an app that never accepted
        // our leaf and keeps dropping the connection after being shown the certificate.
        let bypass = AutoBypass::default();
        let after = HandshakePhase::AfterCertificate;
        assert_eq!(
            bypass.observe(
                10_123,
                "pinned.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Recorded
        );
        assert_eq!(
            bypass.observe(
                10_123,
                "pinned.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Bypassed
        );
        assert!(bypass.is_bypassed(10_123, "pinned.example.com"));
    }

    #[test]
    fn a_disconnect_before_the_certificate_is_not_counted() {
        // A connection that died before our Certificate message went out never saw the leaf, so it
        // cannot have judged it: a slow DNS answer and a give-up look exactly the same.
        let bypass = AutoBypass::default();
        for _ in 0..10 {
            assert_eq!(
                bypass.observe(
                    10_123,
                    "www.example.com",
                    ClientFailure::Disconnect("client_disconnect"),
                    HandshakePhase::BeforeCertificate,
                ),
                Verdict::DisconnectIgnored
            );
        }
        assert!(!bypass.is_bypassed(10_123, "www.example.com"));
        assert!(bypass.is_empty());
    }

    #[test]
    fn a_recent_success_expires_and_then_disconnects_count_again() {
        // The trust window is what keeps the racing-connection rule from switching filtering off
        // forever: once a pair has not completed a handshake for the whole window, disconnects are
        // evidence again.
        let bypass = AutoBypass::default().with_success_window(Duration::from_millis(30));
        bypass.record_success(10_123, "www.example.com");
        assert!(bypass.trusted_recently(10_123, "www.example.com"));
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !bypass.trusted_recently(10_123, "www.example.com"),
            "an expired success must not vouch for the client any more"
        );
        let after = HandshakePhase::AfterCertificate;
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Recorded
        );
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Bypassed
        );
    }

    #[test]
    fn a_success_discards_half_finished_disconnect_evidence() {
        // One disconnect, then a successful handshake, then one more disconnect is not "two strikes":
        // the client proved in between that it accepts our leaf, so the earlier sighting is stale.
        let bypass = AutoBypass::default();
        let after = HandshakePhase::AfterCertificate;
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::Recorded
        );
        bypass.record_success(10_123, "www.example.com");
        assert_eq!(
            bypass.observe(
                10_123,
                "www.example.com",
                ClientFailure::Disconnect("client_disconnect"),
                after,
            ),
            Verdict::DisconnectIgnored
        );
        assert!(!bypass.is_bypassed(10_123, "www.example.com"));
    }

    #[test]
    fn the_success_table_is_bounded() {
        let bypass = AutoBypass::default();
        for index in 0..MAX_RECENT_SUCCESS + 16 {
            bypass.record_success(10_123, &format!("host{index}.example"));
        }
        assert!(
            bypass.recent_success_len() <= MAX_RECENT_SUCCESS,
            "{}",
            bypass.recent_success_len()
        );
        // The newest entries survive, so a host in active use keeps its protection.
        let newest = format!("host{}.example", MAX_RECENT_SUCCESS + 15);
        assert!(bypass.trusted_recently(10_123, &newest));
    }

    #[test]
    fn an_explicit_alert_still_bypasses_a_host_that_succeeded_before() {
        // Rule 4 of the task card: an explicit alert is the client's verdict and is unaffected by
        // the recent-success table. This is what keeps a certificate that became distrusted after
        // being accepted (a user removing the CA, a CA rotation) from looping.
        for reason in [
            "client_unknown_ca",
            "client_bad_certificate",
            "client_certificate_unknown",
        ] {
            let single = AutoBypass::default();
            single.record_success(10_123, "www.example.com");
            assert_eq!(
                single.observe(
                    10_123,
                    "www.example.com",
                    ClientFailure::CertificateRejected(reason),
                    HandshakePhase::AfterCertificate,
                ),
                Verdict::Bypassed,
                "{reason} must bypass immediately"
            );
            assert!(single.is_bypassed(10_123, "www.example.com"), "{reason}");
        }
    }

    #[test]
    fn loopback_and_local_addresses_are_recognised() {
        assert!(is_local_address(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_local_address(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_local_address(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_local_address("fd00::1".parse().expect("v6")));
        assert!(is_local_address("fe80::1".parse().expect("v6")));
        assert!(!is_local_address(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!is_local_address("2001:db8::1".parse().expect("v6")));
    }

    #[test]
    fn only_443_is_https() {
        assert!(is_https_port(443));
        assert!(!is_https_port(80));
        assert!(!is_https_port(8443));
    }
}
