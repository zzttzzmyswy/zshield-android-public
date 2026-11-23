//! UDP "NAT": the mapping between a tunnelled 5-tuple and one outbound socket.
//!
//! UDP is connectionless, but a tunnel has to remember which socket a reply belongs to, and the
//! phone must not open a fresh socket per datagram (that is both slow and a port-exhaustion
//! hazard). Each (src addr, src port, dst addr, dst port) gets one outbound socket, and the entry
//! is dropped after `idle_timeout` without traffic in either direction.
//!
//! Two bounds keep a hostile or broken client from exhausting the process:
//! - `max_entries` total mappings, and
//! - `REPLY_QUEUE` per mapping, so a socket whose replies nobody reads cannot grow without limit.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Key of one UDP flow. `Option<SocketAddr>` for the outbound local address is not needed: replies
/// are delivered through the socket itself, not looked up by the kernel, so we only need the tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

impl UdpFlowKey {
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self { local, remote }
    }
}

/// A live UDP flow.
#[derive(Debug)]
pub struct UdpFlow {
    pub key: UdpFlowKey,
    pub last_activity: Instant,
    /// Number of datagrams forwarded in each direction, for stats.
    pub datagrams_up: u64,
    pub datagrams_down: u64,
}

/// Table of live UDP flows with idle expiry and a hard size bound.
///
/// Expiry is lazy: an entry is only removed when the table is touched (lookup, insert, or an
/// explicit `reap` — which the tunnel calls from its own socket events, never from a timer). This
/// is what keeps an idle tunnel free of wakeups (`docs/DESIGN.md` decision 10).
#[derive(Debug)]
pub struct UdpNat {
    flows: HashMap<UdpFlowKey, UdpFlow>,
    idle_timeout: Duration,
    max_entries: usize,
    expired_total: u64,
}

/// Outcome of asking the table for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpLookup {
    /// An existing flow; `datagrams_up` has been bumped.
    Existing,
    /// A new flow was created; the caller must open an outbound socket.
    Created,
    /// The table is full of live flows; the datagram is dropped.
    Rejected,
}

impl UdpNat {
    pub fn new(idle_timeout: Duration, max_entries: usize) -> Self {
        Self {
            flows: HashMap::new(),
            idle_timeout,
            max_entries: max_entries.max(1),
            expired_total: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn expired_total(&self) -> u64 {
        self.expired_total
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Register traffic from the tunnel for `key`, creating the flow if needed.
    ///
    /// A new flow is only created when the table has room after expiring idle entries; a table full
    /// of *active* flows rejects the datagram (the sender retries or gives up, which is the correct
    /// UDP behaviour).
    pub fn touch(&mut self, key: UdpFlowKey, now: Instant) -> UdpLookup {
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_activity = now;
            flow.datagrams_up += 1;
            return UdpLookup::Existing;
        }
        if self.flows.len() >= self.max_entries {
            self.reap(now);
            if self.flows.len() >= self.max_entries {
                return UdpLookup::Rejected;
            }
        }
        self.flows.insert(
            key,
            UdpFlow {
                key,
                last_activity: now,
                datagrams_up: 1,
                datagrams_down: 0,
            },
        );
        UdpLookup::Created
    }

    /// Record a reply for `key`; returns false when the flow has already been reaped.
    pub fn reply_seen(&mut self, key: &UdpFlowKey, now: Instant) -> bool {
        match self.flows.get_mut(key) {
            Some(flow) => {
                flow.last_activity = now;
                flow.datagrams_down += 1;
                true
            }
            None => false,
        }
    }

    pub fn contains(&self, key: &UdpFlowKey) -> bool {
        self.flows.contains_key(key)
    }

    pub fn get(&self, key: &UdpFlowKey) -> Option<&UdpFlow> {
        self.flows.get(key)
    }

    /// Drop one flow (socket error, or the outbound port is gone).
    pub fn remove(&mut self, key: &UdpFlowKey) -> Option<UdpFlow> {
        self.flows.remove(key)
    }

    /// Remove every flow idle for longer than the timeout. Returns the keys that were removed so the
    /// caller can close their sockets.
    pub fn reap(&mut self, now: Instant) -> Vec<UdpFlowKey> {
        let timeout = self.idle_timeout;
        let mut expired = Vec::new();
        self.flows.retain(|key, flow| {
            let idle = now.saturating_duration_since(flow.last_activity);
            if idle >= timeout {
                expired.push(*key);
                false
            } else {
                true
            }
        });
        self.expired_total += expired.len() as u64;
        expired
    }

    /// Drop everything (tunnel shutdown).
    pub fn clear(&mut self) -> Vec<UdpFlowKey> {
        let keys = self.flows.keys().copied().collect();
        self.flows.clear();
        keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(local_port: u16, remote_port: u16) -> UdpFlowKey {
        UdpFlowKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 111, 222, 1)), local_port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), remote_port),
        )
    }

    #[test]
    fn creates_and_reuses_one_flow_per_tuple() {
        let now = Instant::now();
        let mut nat = UdpNat::new(Duration::from_secs(60), 16);
        assert_eq!(nat.touch(key(1000, 443), now), UdpLookup::Created);
        assert_eq!(nat.touch(key(1000, 443), now), UdpLookup::Existing);
        assert_eq!(nat.touch(key(1001, 443), now), UdpLookup::Created);
        assert_eq!(nat.len(), 2);
        assert_eq!(nat.get(&key(1000, 443)).expect("flow").datagrams_up, 2);
    }

    #[test]
    fn expires_idle_flows_only() {
        let start = Instant::now();
        let mut nat = UdpNat::new(Duration::from_secs(60), 16);
        nat.touch(key(1000, 53), start);
        nat.touch(key(1001, 53), start + Duration::from_secs(30));
        // Refresh the second flow so it stays alive past the first one's deadline.
        nat.touch(key(1001, 53), start + Duration::from_secs(50));

        let expired = nat.reap(start + Duration::from_secs(61));
        assert_eq!(expired, vec![key(1000, 53)]);
        assert_eq!(nat.len(), 1);
        assert!(nat.contains(&key(1001, 53)));
        assert_eq!(nat.expired_total(), 1);

        // The refreshed flow dies exactly one timeout after its last activity.
        assert!(nat.reap(start + Duration::from_secs(109)).is_empty());
        assert_eq!(nat.reap(start + Duration::from_secs(110)), vec![key(1001, 53)]);
    }

    #[test]
    fn replies_keep_a_flow_alive() {
        let start = Instant::now();
        let mut nat = UdpNat::new(Duration::from_secs(60), 16);
        nat.touch(key(1000, 53), start);
        assert!(nat.reply_seen(&key(1000, 53), start + Duration::from_secs(59)));
        assert!(nat.reap(start + Duration::from_secs(61)).is_empty());
        assert_eq!(nat.get(&key(1000, 53)).expect("flow").datagrams_down, 1);
        // A reply for an unknown flow is reported, not silently stored.
        assert!(!nat.reply_seen(&key(2000, 53), start));
    }

    #[test]
    fn bounded_by_max_entries_and_reaps_before_rejecting() {
        let start = Instant::now();
        let mut nat = UdpNat::new(Duration::from_secs(60), 2);
        assert_eq!(nat.touch(key(1, 53), start), UdpLookup::Created);
        assert_eq!(nat.touch(key(2, 53), start), UdpLookup::Created);
        // Full, and the flows are young: reject.
        assert_eq!(nat.touch(key(3, 53), start), UdpLookup::Rejected);
        assert_eq!(nat.len(), 2);
        // Once they age out, the table has room again without any configuration change.
        assert_eq!(
            nat.touch(key(3, 53), start + Duration::from_secs(61)),
            UdpLookup::Created
        );
        assert_eq!(nat.len(), 1);
    }

    #[test]
    fn clear_returns_the_keys_to_close() {
        let now = Instant::now();
        let mut nat = UdpNat::new(Duration::from_secs(60), 16);
        nat.touch(key(1, 53), now);
        nat.touch(key(2, 53), now);
        let mut keys = nat.clear();
        keys.sort_by_key(|key| key.local.port());
        assert_eq!(keys.len(), 2);
        assert!(nat.is_empty());
    }
}
