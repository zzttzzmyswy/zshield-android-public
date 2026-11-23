//! TTL-respecting DNS answer cache.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::dns::wire::Record;

/// Cache key: lowercased query name plus query type and class.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl CacheKey {
    pub fn new(name: &str, qtype: u16, qclass: u16) -> Self {
        Self {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            qtype,
            qclass,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    answers: Vec<Record>,
    authorities: Vec<Record>,
    inserted: Instant,
    expires: Instant,
    /// TTL actually used, for stats.
    ttl_secs: u32,
}

/// A bounded cache honouring per-record TTLs.
///
/// Live entries expire lazily on read. When the map exceeds its entry budget the entry closest to
/// expiry is evicted, which is O(n) but only runs when the budget is exceeded and keeps the
/// implementation dependency-free and predictable (the LRU crate is used for larger caches later).
#[derive(Debug)]
pub struct Cache {
    entries: HashMap<CacheKey, Entry>,
    max_entries: usize,
    max_ttl: Duration,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl Cache {
    pub fn new(max_entries: usize, max_ttl_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: max_entries.max(1),
            max_ttl: Duration::from_secs(max_ttl_secs.max(1)),
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Look up a stored answer, refreshing its remaining TTL.
    pub fn get(&mut self, key: &CacheKey) -> Option<(Vec<Record>, Vec<Record>)> {
        let now = Instant::now();
        let Some(entry) = self.entries.get(key) else {
            self.misses += 1;
            return None;
        };
        if now >= entry.expires {
            self.entries.remove(key);
            self.misses += 1;
            return None;
        }
        self.hits += 1;
        let remaining = entry.expires.saturating_duration_since(now).as_secs() as u32;
        let mut answers = entry.answers.clone();
        let mut authorities = entry.authorities.clone();
        for record in answers.iter_mut().chain(authorities.iter_mut()) {
            record.ttl = record.ttl.min(remaining);
        }
        Some((answers, authorities))
    }

    /// Store an upstream answer. Answers with no records and no TTL are not cached.
    pub fn insert(&mut self, key: CacheKey, answers: Vec<Record>, authorities: Vec<Record>) {
        let Some(min_ttl) = answers.iter().map(|r| r.ttl).min() else {
            // Empty answer sections (NXDOMAIN etc.) are deliberately not cached in M0: the
            // negative-caching rules are subtle and a wrong TTL here causes visible breakage.
            return;
        };
        if min_ttl == 0 {
            return;
        }
        let ttl = Duration::from_secs(u64::from(min_ttl)).min(self.max_ttl);
        let now = Instant::now();
        self.entries.insert(
            key,
            Entry {
                answers,
                authorities,
                inserted: now,
                expires: now + ttl,
                ttl_secs: ttl.as_secs() as u32,
            },
        );
        self.enforce_budget();
    }

    fn enforce_budget(&mut self) {
        while self.entries.len() > self.max_entries {
            let now = Instant::now();
            let victim = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| {
                    if entry.expires <= now {
                        Duration::ZERO
                    } else {
                        entry.expires.saturating_duration_since(now)
                    }
                })
                .map(|(key, _)| key.clone());
            match victim {
                Some(key) => {
                    self.entries.remove(&key);
                    self.evictions += 1;
                }
                None => break,
            }
        }
    }

    /// Drop every expired entry. Called periodically by the engine housekeeping timer so that a
    /// long-running tunnel does not keep dead entries around.
    pub fn purge_expired(&mut self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.expires > now);
        before - self.entries.len()
    }

    /// Drop every entry. Used when the rule set changes: past answers encode past decisions.
    pub fn clear(&mut self) -> usize {
        let count = self.entries.len();
        self.entries.clear();
        count
    }

    /// TTL of a stored entry in seconds, for tests and stats.
    pub fn ttl_of(&self, key: &CacheKey) -> Option<u32> {
        self.entries.get(key).map(|entry| entry.ttl_secs)
    }

    /// Age of a stored entry, for tests.
    pub fn age_of(&self, key: &CacheKey) -> Option<Duration> {
        self.entries
            .get(key)
            .map(|entry| entry.inserted.elapsed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{CLASS_IN, TYPE_A, TYPE_AAAA};

    fn record(name: &str, ttl: u32) -> Record {
        Record {
            name: name.to_string(),
            rtype: TYPE_A,
            rclass: CLASS_IN,
            ttl,
            rdata: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn stores_and_returns_answers() {
        let mut cache = Cache::new(16, 3600);
        let key = CacheKey::new("a.example.com", TYPE_A, CLASS_IN);
        cache.insert(key.clone(), vec![record("a.example.com", 60)], vec![]);
        let (answers, _) = cache.get(&key).expect("hit");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].a_addr().unwrap().to_string(), "1.2.3.4");
        assert_eq!(cache.hits(), 1);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn miss_on_unknown_key() {
        let mut cache = Cache::new(16, 3600);
        assert!(cache
            .get(&CacheKey::new("nope.example.com", TYPE_A, CLASS_IN))
            .is_none());
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn different_qtype_is_a_different_entry() {
        let mut cache = Cache::new(16, 3600);
        let key4 = CacheKey::new("a.example.com", TYPE_A, CLASS_IN);
        let key6 = CacheKey::new("a.example.com", TYPE_AAAA, CLASS_IN);
        cache.insert(key4.clone(), vec![record("a.example.com", 60)], vec![]);
        assert!(cache.get(&key4).is_some());
        assert!(cache.get(&key6).is_none());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ttl_is_capped_at_configured_maximum() {
        let mut cache = Cache::new(16, 60);
        let key = CacheKey::new("a.example.com", TYPE_A, CLASS_IN);
        cache.insert(key.clone(), vec![record("a.example.com", 86400)], vec![]);
        assert_eq!(cache.ttl_of(&key), Some(60));
    }

    #[test]
    fn zero_ttl_and_empty_answers_are_not_cached() {
        let mut cache = Cache::new(16, 3600);
        let key = CacheKey::new("a.example.com", TYPE_A, CLASS_IN);
        cache.insert(key.clone(), vec![record("a.example.com", 0)], vec![]);
        assert!(cache.is_empty());
        cache.insert(key.clone(), vec![], vec![]);
        assert!(cache.is_empty());
    }

    #[test]
    fn entry_expires_after_its_ttl() {
        let mut cache = Cache::new(16, 3600);
        let key = CacheKey::new("short.example.com", TYPE_A, CLASS_IN);
        // 1s TTL is the smallest cacheable value; age it past expiry by hand.
        cache.insert(key.clone(), vec![record("short.example.com", 1)], vec![]);
        assert!(cache.get(&key).is_some());
        {
            let entry = cache.entries.get_mut(&key).expect("entry");
            entry.expires = Instant::now() - Duration::from_millis(1);
        }
        assert!(cache.get(&key).is_none());
        assert!(cache.is_empty(), "expired entry must be dropped on read");
    }

    #[test]
    fn remaining_ttl_shrinks_with_age() {
        let mut cache = Cache::new(16, 3600);
        let key = CacheKey::new("a.example.com", TYPE_A, CLASS_IN);
        cache.insert(key.clone(), vec![record("a.example.com", 60)], vec![]);
        {
            let entry = cache.entries.get_mut(&key).expect("entry");
            entry.expires = Instant::now() + Duration::from_secs(30);
        }
        let (answers, _) = cache.get(&key).expect("hit");
        assert!(answers[0].ttl <= 30, "ttl was {}", answers[0].ttl);
    }

    #[test]
    fn budget_evicts_the_entry_closest_to_expiry() {
        let mut cache = Cache::new(2, 3600);
        let key_long = CacheKey::new("long.example.com", TYPE_A, CLASS_IN);
        let key_short = CacheKey::new("short.example.com", TYPE_A, CLASS_IN);
        let key_new = CacheKey::new("new.example.com", TYPE_A, CLASS_IN);
        cache.insert(key_long.clone(), vec![record("long.example.com", 600)], vec![]);
        cache.insert(
            key_short.clone(),
            vec![record("short.example.com", 10)],
            vec![],
        );
        cache.insert(key_new.clone(), vec![record("new.example.com", 300)], vec![]);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key_short).is_none(), "shortest TTL evicted");
        assert!(cache.get(&key_long).is_some());
        assert!(cache.get(&key_new).is_some());
        assert_eq!(cache.evictions(), 1);
    }

    #[test]
    fn purge_removes_only_expired_entries() {
        let mut cache = Cache::new(16, 3600);
        let fresh = CacheKey::new("fresh.example.com", TYPE_A, CLASS_IN);
        let stale = CacheKey::new("stale.example.com", TYPE_A, CLASS_IN);
        cache.insert(fresh.clone(), vec![record("fresh.example.com", 600)], vec![]);
        cache.insert(stale.clone(), vec![record("stale.example.com", 600)], vec![]);
        {
            let entry = cache.entries.get_mut(&stale).expect("entry");
            entry.expires = Instant::now() - Duration::from_secs(1);
        }
        assert_eq!(cache.purge_expired(), 1);
        assert!(cache.get(&stale).is_none());
        assert!(cache.get(&fresh).is_some());
    }

    #[test]
    fn key_normalisation() {
        assert_eq!(
            CacheKey::new("A.Example.COM.", TYPE_A, CLASS_IN),
            CacheKey::new("a.example.com", TYPE_A, CLASS_IN)
        );
    }
}
