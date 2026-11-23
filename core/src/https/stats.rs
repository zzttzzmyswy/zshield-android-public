//! HTTPS counters (task card §5), exposed through `statsJson`.
//!
//! Every counter answers one question a user or a reviewer will ask when a page breaks or an ad
//! survives, so they are recorded where the event happens rather than derived later:
//!
//! | Counter | Meaning |
//! |---|---|
//! | `httpsIntercepted` | connections we decrypted and filtered |
//! | `httpsPassthrough` | 443 connections we deliberately did not decrypt (not selected) |
//! | `httpsAutoBypassed` | connections that entered the auto-bypass table |
//! | `httpsUpstreamInvalid` | connections whose upstream certificate failed verification |
//! | `httpsHandshakeFailures` | client-side TLS handshake failures |
//! | `httpsDisconnectsIgnored` | of those, disconnects that did **not** count towards a bypass |
//! | `h2Streams` | HTTP/2 requests judged on a decrypted connection |
//! | `h2Blocked` | of those, the ones answered locally |

use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide-ish HTTPS counters, one set per engine handle.
#[derive(Debug, Default)]
pub struct HttpsStats {
    pub intercepted: AtomicU64,
    pub passthrough: AtomicU64,
    pub auto_bypassed: AtomicU64,
    pub upstream_invalid: AtomicU64,
    pub handshake_failures: AtomicU64,
    pub disconnects_ignored: AtomicU64,
    pub h2_streams: AtomicU64,
    pub h2_blocked: AtomicU64,
}

/// A snapshot of [`HttpsStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HttpsSnapshot {
    pub intercepted: u64,
    pub passthrough: u64,
    pub auto_bypassed: u64,
    pub upstream_invalid: u64,
    pub handshake_failures: u64,
    pub disconnects_ignored: u64,
    pub h2_streams: u64,
    pub h2_blocked: u64,
}

impl HttpsStats {
    pub fn snapshot(&self) -> HttpsSnapshot {
        let relaxed = Ordering::Relaxed;
        HttpsSnapshot {
            intercepted: self.intercepted.load(relaxed),
            passthrough: self.passthrough.load(relaxed),
            auto_bypassed: self.auto_bypassed.load(relaxed),
            upstream_invalid: self.upstream_invalid.load(relaxed),
            handshake_failures: self.handshake_failures.load(relaxed),
            disconnects_ignored: self.disconnects_ignored.load(relaxed),
            h2_streams: self.h2_streams.load(relaxed),
            h2_blocked: self.h2_blocked.load(relaxed),
        }
    }

    pub fn count_intercepted(&self) {
        self.intercepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_passthrough(&self) {
        self.passthrough.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_auto_bypassed(&self) {
        self.auto_bypassed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_upstream_invalid(&self) {
        self.upstream_invalid.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_handshake_failure(&self) {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// One client disconnect that was counted for the operator but *not* as bypass evidence.
    ///
    /// Kept separate from [`Self::count_handshake_failure`] because the two answer different
    /// questions: how often clients leave us mid-handshake, and how many of those we refused to
    /// treat as "this app does not trust our CA". A number that stays at zero on a browser means no
    /// racing connection was seen at all; a number that climbs while `httpsBypassEntries` stays put
    /// means the rule is doing its job.
    pub fn count_disconnect_ignored(&self) {
        self.disconnects_ignored.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_h2_stream(&self, blocked: bool) {
        self.h2_streams.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.h2_blocked.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_independent() {
        let stats = HttpsStats::default();
        stats.count_intercepted();
        stats.count_intercepted();
        stats.count_passthrough();
        stats.count_auto_bypassed();
        stats.count_upstream_invalid();
        stats.count_handshake_failure();
        stats.count_disconnect_ignored();
        stats.count_h2_stream(false);
        stats.count_h2_stream(true);
        stats.count_h2_stream(true);
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.intercepted, 2);
        assert_eq!(snapshot.passthrough, 1);
        assert_eq!(snapshot.auto_bypassed, 1);
        assert_eq!(snapshot.upstream_invalid, 1);
        assert_eq!(snapshot.handshake_failures, 1);
        assert_eq!(snapshot.disconnects_ignored, 1);
        assert_eq!(snapshot.h2_streams, 3);
        assert_eq!(snapshot.h2_blocked, 2);
    }
}
