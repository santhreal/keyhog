//! ROADMAP L2 / E2 — content-hash LRU cache for parsed source.
//!
//! Substrate that any language's parse pipeline can opt into without
//! plumbing a cache through every layer of the parser. The cache is
//! keyed by the BLAKE3 content hash of the source bytes (or any
//! caller-chosen extra-key extension), so two callers with the same
//! source share the parsed artifact even if they hold distinct
//! string allocations.
//!
//! ## Why content hash, not string identity
//!
//! In the surgec scan loop the same `.h` header is included from
//! many translation units. Identity-keyed memoisation misses every
//! caller because each caller holds its own `String`. Content-hash
//! lookup lets every translation unit share a single parse.
//!
//! ## Why LRU, not unbounded
//!
//! Workspace scans touch tens of thousands of distinct files. An
//! unbounded cache grows without bound; an LRU bounded by entry
//! count keeps the working set in memory and evicts cold entries
//! deterministically. Eviction is pay-as-you-go: each `get_or_parse`
//! call does at most one removal.
//!
//! ## Thread safety
//!
//! The cache is `Send + Sync` — backed by a `Mutex<...>` so the
//! parse work proceeds outside the lock and only the lookup /
//! insert / eviction touches it. Two callers asking for the same
//! key concurrently each pay the parse cost (no per-key dedup), but
//! the result of the second writer overwrites the first — both
//! callers observe the same `Arc<T>` because the value is
//! deterministic in the input.

use blake3::Hasher;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

/// 32-byte BLAKE3 content hash used as the cache key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceHash(pub [u8; 32]);

impl SourceHash {
    /// Hash `source` plus the optional `extra` discriminator. The
    /// `extra` channel lets callers separate caches that share source
    /// bytes but differ in build flags (e.g. preprocessor `-D` set).
    #[must_use]
    pub fn of(source: &[u8], extra: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(source);
        hasher.update(&[0u8; 1]);
        hasher.update(extra);
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        Self(out)
    }
}

/// Bounded LRU cache mapping `SourceHash` to `Arc<T>`. Eviction is
/// LRU by last-touched order. Reads and writes are O(1) amortised
/// (the LRU recency queue uses a `VecDeque<SourceHash>`).
pub struct ParsedSourceLru<T> {
    inner: Mutex<LruInner<T>>,
}

struct LruInner<T> {
    capacity: usize,
    entries: HashMap<SourceHash, Arc<T>>,
    recency: VecDeque<SourceHash>,
}

impl<T> ParsedSourceLru<T> {
    /// Build an empty cache that holds at most `capacity` entries.
    /// `capacity == 0` disables caching entirely (every lookup is a
    /// miss and nothing is stored).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(LruInner {
                capacity,
                entries: HashMap::with_capacity(capacity),
                recency: VecDeque::with_capacity(capacity),
            }),
        }
    }

    /// Look up `key`. Returns the cached `Arc<T>` on hit (and bumps
    /// recency); returns `None` on miss.
    #[must_use]
    pub fn get(&self, key: SourceHash) -> Option<Arc<T>> {
        let mut inner = self.lock_inner();
        let value = inner.entries.get(&key)?.clone();
        bump_recency(&mut inner.recency, key);
        Some(value)
    }

    /// Insert `value` for `key`, evicting the oldest entry if the
    /// cache is at capacity. Returns the inserted `Arc<T>`.
    pub fn insert(&self, key: SourceHash, value: T) -> Arc<T> {
        let arc = Arc::new(value);
        let mut inner = self.lock_inner();
        if inner.capacity == 0 {
            return arc;
        }
        if !inner.entries.contains_key(&key) && inner.entries.len() >= inner.capacity {
            if let Some(evicted) = inner.recency.pop_front() {
                inner.entries.remove(&evicted);
            }
        }
        inner.entries.insert(key, arc.clone());
        bump_recency(&mut inner.recency, key);
        arc
    }

    /// Look up `key`; on miss, run `parse(source)` to produce the
    /// value and insert it. Returns the cached or freshly inserted
    /// `Arc<T>`.
    pub fn get_or_parse<F>(&self, source: &[u8], extra: &[u8], parse: F) -> Arc<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        let key = SourceHash::of(source, extra);
        if let Some(hit) = self.get(key) {
            return hit;
        }
        let value = parse(source);
        self.insert(key, value)
    }

    /// Total number of entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock_inner().entries.len()
    }

    /// `true` iff the cache holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock_inner(&self) -> MutexGuard<'_, LruInner<T>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn bump_recency(recency: &mut VecDeque<SourceHash>, key: SourceHash) {
    if let Some(pos) = recency.iter().position(|k| *k == key) {
        recency.remove(pos);
    }
    recency.push_back(key);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Same content + same extra hash to the same key.
    #[test]
    fn source_hash_equal_for_equal_inputs() {
        let a = SourceHash::of(b"int x = 1;", b"");
        let b = SourceHash::of(b"int x = 1;", b"");
        assert_eq!(a, b);
    }

    /// Distinct content hashes to distinct keys.
    #[test]
    fn source_hash_differs_for_different_source() {
        let a = SourceHash::of(b"int x = 1;", b"");
        let b = SourceHash::of(b"int x = 2;", b"");
        assert_ne!(a, b);
    }

    /// Distinct extras hash to distinct keys even with the same source.
    #[test]
    fn source_hash_differs_for_different_extra() {
        let a = SourceHash::of(b"int x = 1;", b"-DA");
        let b = SourceHash::of(b"int x = 1;", b"-DB");
        assert_ne!(a, b);
    }

    /// `get_or_parse` is invoked once per content-hash, even when the
    /// source bytes come from distinct caller `Vec` allocations.
    #[test]
    fn get_or_parse_dedups_across_callers() {
        let cache: ParsedSourceLru<usize> = ParsedSourceLru::with_capacity(4);
        let parse_calls = AtomicUsize::new(0);
        let parse = || {
            parse_calls.fetch_add(1, Ordering::SeqCst);
            42usize
        };
        let src_a = b"hello world".to_vec();
        let src_b = b"hello world".to_vec();
        let a = cache.get_or_parse(&src_a, b"", |_s| parse());
        let b = cache.get_or_parse(&src_b, b"", |_s| parse());
        assert_eq!(*a, 42);
        assert_eq!(*b, 42);
        assert_eq!(parse_calls.load(Ordering::SeqCst), 1);
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// LRU eviction kicks the least-recently-used entry when capacity
    /// is reached.
    #[test]
    fn lru_evicts_oldest_when_capacity_reached() {
        let cache: ParsedSourceLru<u32> = ParsedSourceLru::with_capacity(2);
        let _a = cache.get_or_parse(b"a", b"", |_| 1u32);
        let _b = cache.get_or_parse(b"b", b"", |_| 2u32);
        let _c = cache.get_or_parse(b"c", b"", |_| 3u32);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(SourceHash::of(b"a", b"")).is_none());
        assert!(cache.get(SourceHash::of(b"b", b"")).is_some());
        assert!(cache.get(SourceHash::of(b"c", b"")).is_some());
    }

    /// Re-fetching an entry bumps it to most-recently-used so a
    /// subsequent insertion evicts a different one.
    #[test]
    fn lru_recency_promotes_on_get() {
        let cache: ParsedSourceLru<u32> = ParsedSourceLru::with_capacity(2);
        let _a = cache.get_or_parse(b"a", b"", |_| 1u32);
        let _b = cache.get_or_parse(b"b", b"", |_| 2u32);
        assert!(cache.get(SourceHash::of(b"a", b"")).is_some());
        let _c = cache.get_or_parse(b"c", b"", |_| 3u32);
        assert!(cache.get(SourceHash::of(b"a", b"")).is_some());
        assert!(cache.get(SourceHash::of(b"b", b"")).is_none());
        assert!(cache.get(SourceHash::of(b"c", b"")).is_some());
    }

    /// Capacity 0 disables caching: the parse closure runs every call.
    #[test]
    fn capacity_zero_disables_caching() {
        let cache: ParsedSourceLru<u32> = ParsedSourceLru::with_capacity(0);
        let calls = AtomicUsize::new(0);
        assert_eq!(cache.get_or_parse(b"a", b"", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            7u32
        }), 7);
        assert_eq!(cache.get_or_parse(b"a", b"", |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            7u32
        }), 7);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cache.len(), 0);
    }

    /// `is_empty` reflects emptiness vs. populated-state.
    #[test]
    fn is_empty_tracks_population() {
        let cache: ParsedSourceLru<u32> = ParsedSourceLru::with_capacity(2);
        assert!(cache.is_empty());
        assert_eq!(cache.get_or_parse(b"a", b"", |_| 1u32), 1);
        assert!(!cache.is_empty());
    }

    /// Updating an existing key keeps capacity stable (the `len` stays
    /// at one, no eviction loop fires).
    #[test]
    fn insert_existing_key_does_not_evict() {
        let cache: ParsedSourceLru<u32> = ParsedSourceLru::with_capacity(2);
        assert!(cache.insert(SourceHash::of(b"a", b""), 1).is_none());
        assert_eq!(cache.insert(SourceHash::of(b"a", b""), 2), Some(1));
        assert_eq!(cache.len(), 1);
    }
}
