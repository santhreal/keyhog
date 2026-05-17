//! [`InMemoryPipelineCache`] — sharded zero-persistence cache. The hot
//! path for in-process pipeline reuse.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use rustc_hash::FxHashMap;

use super::fingerprint::PipelineFingerprint;
use super::metrics::{PipelineCacheCounters, PipelineCacheMetrics};
use super::store::PipelineCacheStore;

/// In-memory pipeline cache — zero-persistence, zero-network, sharded
/// `FxHashMap`s behind mutexes so concurrent `get`/`put` on different
/// fingerprints rarely contend (VYRE_RUNTIME / PERF hot-cache audit).
#[derive(Debug)]
pub struct InMemoryPipelineCache {
    shards: [Mutex<InMemoryCacheShard>; Self::SHARD_COUNT],
    max_entries_per_shard: usize,
    max_bytes_per_shard: usize,
    metrics: PipelineCacheCounters,
}

impl InMemoryPipelineCache {
    pub(super) const SHARD_COUNT: usize = 256;
    pub(super) const MAX_ENTRIES_PER_SHARD: usize = 256;
    pub(super) const MAX_BYTES_PER_SHARD: usize = 16 * 1024 * 1024;

    #[inline]
    fn shard_index(fp: &PipelineFingerprint) -> usize {
        (fp.0[0] as usize) % Self::SHARD_COUNT
    }

    /// Construct an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an empty cache with explicit per-shard entry and byte budgets.
    ///
    /// A zero entry budget or zero byte budget creates a disabled cache that
    /// accepts `put` calls but retains no artifacts.
    #[must_use]
    pub fn with_limits(max_entries_per_shard: usize, max_bytes_per_shard: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(InMemoryCacheShard::default())),
            max_entries_per_shard,
            max_bytes_per_shard,
            metrics: PipelineCacheCounters::default(),
        }
    }

    /// Current entry count. Thread-safe snapshot.
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).entries.len())
            .sum()
    }

    /// Current cached artifact bytes. Thread-safe snapshot.
    pub fn cached_bytes(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).bytes)
            .sum()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| {
            s.lock()
                .unwrap_or_else(|e| e.into_inner())
                .entries
                .is_empty()
        })
    }
}

impl Default for InMemoryPipelineCache {
    fn default() -> Self {
        Self::with_limits(Self::MAX_ENTRIES_PER_SHARD, Self::MAX_BYTES_PER_SHARD)
    }
}

#[derive(Debug, Default)]
struct InMemoryCacheShard {
    entries: FxHashMap<PipelineFingerprint, InMemoryCacheEntry>,
    bytes: usize,
    clock: u64,
}

impl InMemoryCacheShard {
    fn next_tick(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    fn evict_to_limits(&mut self, max_entries: usize, max_bytes: usize) -> (u64, u64) {
        let mut evictions = 0_u64;
        let mut evicted_bytes = 0_u64;
        while self.entries.len() > max_entries || self.bytes > max_bytes {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(fp, _)| *fp)
            else {
                self.bytes = 0;
                return (evictions, evicted_bytes);
            };
            if let Some(removed) = self.entries.remove(&victim) {
                self.bytes = self.bytes.saturating_sub(removed.bytes);
                evictions = evictions.saturating_add(1);
                evicted_bytes = evicted_bytes.saturating_add(removed.bytes as u64);
            }
        }
        (evictions, evicted_bytes)
    }
}

#[derive(Debug)]
struct InMemoryCacheEntry {
    artifact: Arc<Vec<u8>>,
    bytes: usize,
    last_used: u64,
}

impl PipelineCacheStore for InMemoryPipelineCache {
    fn get(&self, fp: &PipelineFingerprint) -> Option<Vec<u8>> {
        self.get_arc(fp).map(|artifact| (*artifact).clone())
    }

    /// V7-PERF-009: zero-clone hot-path lookup. The cache already stores
    /// payloads behind `Arc<Vec<u8>>`, so a hit is one refcount bump.
    fn get_arc(&self, fp: &PipelineFingerprint) -> Option<Arc<Vec<u8>>> {
        self.metrics.lookups.fetch_add(1, Ordering::Relaxed);
        let i = Self::shard_index(fp);
        let mut shard = self.shards[i].lock().unwrap_or_else(|e| e.into_inner());
        let tick = shard.next_tick();
        let Some(entry) = shard.entries.get_mut(fp) else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        entry.last_used = tick;
        self.metrics.hits.fetch_add(1, Ordering::Relaxed);
        Some(Arc::clone(&entry.artifact))
    }

    fn put(&self, fp: PipelineFingerprint, artifact: Vec<u8>) {
        let i = Self::shard_index(&fp);
        let mut shard = self.shards[i].lock().unwrap_or_else(|e| e.into_inner());
        let bytes = artifact.len();
        if self.max_entries_per_shard == 0
            || self.max_bytes_per_shard == 0
            || bytes > self.max_bytes_per_shard
        {
            self.metrics.rejected_puts.fetch_add(1, Ordering::Relaxed);
            if let Some(removed) = shard.entries.remove(&fp) {
                shard.bytes = shard.bytes.saturating_sub(removed.bytes);
                self.metrics.evictions.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .evicted_bytes
                    .fetch_add(removed.bytes as u64, Ordering::Relaxed);
            }
            return;
        }

        if let Some(existing) = shard.entries.remove(&fp) {
            shard.bytes = shard.bytes.saturating_sub(existing.bytes);
        }
        let tick = shard.next_tick();
        shard.bytes = shard.bytes.saturating_add(bytes);
        shard.entries.insert(
            fp,
            InMemoryCacheEntry {
                artifact: Arc::new(artifact),
                bytes,
                last_used: tick,
            },
        );
        self.metrics.puts.fetch_add(1, Ordering::Relaxed);
        let (evictions, evicted_bytes) =
            shard.evict_to_limits(self.max_entries_per_shard, self.max_bytes_per_shard);
        self.metrics
            .evictions
            .fetch_add(evictions, Ordering::Relaxed);
        self.metrics
            .evicted_bytes
            .fetch_add(evicted_bytes, Ordering::Relaxed);
    }

    fn metrics(&self) -> PipelineCacheMetrics {
        self.metrics
            .snapshot(self.cached_bytes() as u64, self.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline_cache::test_helpers::tiny_program;

    #[test]
    fn in_memory_cache_roundtrip() {
        let cache = InMemoryPipelineCache::new();
        let fp = PipelineFingerprint::of(&tiny_program());
        assert!(cache.get(&fp).is_none());
        cache.put(fp, b"target-bytes".to_vec());
        assert_eq!(cache.get(&fp).unwrap(), b"target-bytes".to_vec());
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn in_memory_cache_caps_each_shard() {
        let cache = InMemoryPipelineCache::new();
        for i in 0..(InMemoryPipelineCache::MAX_ENTRIES_PER_SHARD + 17) {
            let mut bytes = [0_u8; 32];
            bytes[1..9].copy_from_slice(&(i as u64).to_le_bytes());
            cache.put(PipelineFingerprint(bytes), vec![i as u8]);
        }
        assert_eq!(cache.len(), InMemoryPipelineCache::MAX_ENTRIES_PER_SHARD);
    }

    #[test]
    fn in_memory_cache_evicts_least_recently_used_entry() {
        let cache = InMemoryPipelineCache::with_limits(2, 1024);
        let a = PipelineFingerprint([0; 32]);
        let mut b_bytes = [0; 32];
        b_bytes[1] = 1;
        let b = PipelineFingerprint(b_bytes);
        let mut c_bytes = [0; 32];
        c_bytes[1] = 2;
        let c = PipelineFingerprint(c_bytes);

        cache.put(a, b"a".to_vec());
        cache.put(b, b"b".to_vec());
        assert_eq!(cache.get(&a).unwrap(), b"a".to_vec());
        cache.put(c, b"c".to_vec());

        assert_eq!(cache.get(&a).unwrap(), b"a".to_vec());
        assert!(cache.get(&b).is_none());
        assert_eq!(cache.get(&c).unwrap(), b"c".to_vec());
    }

    #[test]
    fn in_memory_cache_enforces_byte_budget() {
        let cache = InMemoryPipelineCache::with_limits(8, 10);
        let a = PipelineFingerprint([0; 32]);
        let mut b_bytes = [0; 32];
        b_bytes[1] = 1;
        let b = PipelineFingerprint(b_bytes);
        let mut too_large_bytes = [0; 32];
        too_large_bytes[1] = 2;
        let too_large = PipelineFingerprint(too_large_bytes);

        cache.put(a, vec![1; 6]);
        cache.put(b, vec![2; 6]);
        assert!(cache.get(&a).is_none());
        assert_eq!(cache.get(&b).unwrap(), vec![2; 6]);
        assert_eq!(cache.cached_bytes(), 6);

        cache.put(too_large, vec![3; 11]);
        assert!(cache.get(&too_large).is_none());
        assert_eq!(cache.cached_bytes(), 6);
    }

    #[test]
    fn in_memory_cache_metrics_track_hits_misses_and_evictions() {
        let cache = InMemoryPipelineCache::with_limits(1, 8);
        let a = PipelineFingerprint([0; 32]);
        let mut b_bytes = [0; 32];
        b_bytes[1] = 1;
        let b = PipelineFingerprint(b_bytes);

        assert!(cache.get(&a).is_none());
        cache.put(a, vec![1; 4]);
        assert!(cache.get(&a).is_some());
        cache.put(b, vec![2; 4]);

        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 2);
        assert_eq!(metrics.hits, 1);
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.puts, 2);
        assert_eq!(metrics.evictions, 1);
        assert_eq!(metrics.cached_bytes, 4);
        assert_eq!(metrics.entries, 1);
        assert_eq!(metrics.hit_rate_ppm(), 500_000);
    }
}
