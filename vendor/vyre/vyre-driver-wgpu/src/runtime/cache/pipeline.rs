//! Bounded cache for WGPU pipeline artifacts.

use crate::pipeline::CachedPipelineArtifact;
use dashmap::DashMap;
use rustc_hash::FxHasher;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use vyre_driver::cache_eviction_heat::{entries_to_evict, CacheEntryStats};

/// Bounded cache for WGPU pipeline artifacts using shared driver-tier
/// retention policy. Despite the legacy name, this is not LRU.
pub(crate) struct LruPipelineCache {
    artifacts: DashMap<[u8; 32], PipelineCacheEntry, BuildHasherDefault<FxHasher>>,
    cached_bytes: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    insertions: AtomicU64,
    evictions: AtomicU64,
    max_entries: u32,
    max_bytes: usize,
}

struct PipelineCacheEntry {
    artifact: Arc<CachedPipelineArtifact>,
    gain: AtomicU32,
    last_hit_time_s: AtomicU64,
    cost: usize,
}

impl std::fmt::Debug for LruPipelineCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LruPipelineCache")
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

impl LruPipelineCache {
    /// Create a cache capped at `max_entries`.
    #[cfg(test)]
    pub(crate) fn new(max_entries: u32) -> Self {
        Self::with_limits(max_entries, 256 * 1024 * 1024)
    }

    /// Create a cache capped by entry count and estimated artifact bytes.
    pub(crate) fn with_limits(max_entries: u32, max_bytes: usize) -> Self {
        Self {
            artifacts: DashMap::with_hasher(BuildHasherDefault::<FxHasher>::default()),
            cached_bytes: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            insertions: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
        }
    }

    /// Retrieve an artifact and update its recency/gain.
    pub(crate) fn get(&self, fingerprint: &[u8; 32]) -> Option<Arc<CachedPipelineArtifact>> {
        if let Some(entry) = self.artifacts.get(fingerprint) {
            let artifact = Arc::clone(&entry.artifact);
            entry
                .gain
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |gain| {
                    Some(gain.saturating_add(1))
                })
                .expect("pipeline cache gain update closure always returns Some");
            entry
                .last_hit_time_s
                .store(f64_to_atomic(now_seconds()), Ordering::Relaxed);
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(artifact)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert an artifact, evicting cold entries until capacity is available.
    pub(crate) fn insert(&self, fingerprint: [u8; 32], artifact: Arc<CachedPipelineArtifact>) {
        let cost = artifact.cache_cost_bytes();
        if cost > self.max_bytes {
            self.remove_key(&fingerprint);
            return;
        }

        let previous = self.artifacts.insert(
            fingerprint,
            PipelineCacheEntry {
                artifact,
                gain: AtomicU32::new(1),
                last_hit_time_s: AtomicU64::new(f64_to_atomic(now_seconds())),
                cost,
            },
        );
        match previous {
            Some(old) => {
                if cost >= old.cost {
                    self.cached_bytes
                        .fetch_add(cost - old.cost, Ordering::Relaxed);
                } else {
                    self.cached_bytes
                        .fetch_sub(old.cost - cost, Ordering::Relaxed);
                }
            }
            None => {
                self.cached_bytes.fetch_add(cost, Ordering::Relaxed);
            }
        }
        self.insertions.fetch_add(1, Ordering::Relaxed);

        self.evict_over_capacity();
    }

    fn evict_over_capacity(&self) {
        while self.artifacts.len() > self.max_entries as usize
            || self.cached_bytes.load(Ordering::Relaxed) > self.max_bytes
        {
            let entries = self.eviction_snapshot();
            if entries.is_empty() {
                self.artifacts.clear();
                self.cached_bytes.store(0, Ordering::Relaxed);
                return;
            }

            let mut removed_count = 0u64;
            let evict = self.eviction_keys(&entries);
            for key in evict {
                if let Some((_, removed)) = self.artifacts.remove(&key) {
                    self.cached_bytes.fetch_sub(removed.cost, Ordering::Relaxed);
                    removed_count += 1;
                }
            }
            if removed_count == 0 {
                return;
            }
            self.evictions.fetch_add(removed_count, Ordering::Relaxed);
            vyre_driver::cache_eviction::record_eviction(
                removed_count as f64 / entries.len() as f64,
            );
        }
    }

    fn eviction_snapshot(&self) -> Vec<EvictionEntry> {
        let mut entries = Vec::with_capacity(self.artifacts.len());
        for entry in self.artifacts.iter() {
            entries.push(EvictionEntry {
                key: *entry.key(),
                gain: entry.gain.load(Ordering::Relaxed),
                last_hit_time_s: atomic_to_f64(entry.last_hit_time_s.load(Ordering::Relaxed)),
                cost: entry.cost,
            });
        }
        entries
    }

    fn eviction_keys(&self, entries: &[EvictionEntry]) -> Vec<[u8; 32]> {
        let mut retained_len = entries.len();
        let mut retained_bytes = entries.iter().map(|entry| entry.cost).sum::<usize>();
        let stats: Vec<CacheEntryStats> = entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| CacheEntryStats {
                id: idx as u64,
                hit_count: entry.gain,
                last_hit_time_s: entry.last_hit_time_s,
            })
            .collect();
        let coldest = entries_to_evict(&stats, 0, now_seconds());
        let mut keys = Vec::new();
        for cold_idx in coldest {
            if retained_len <= self.max_entries as usize && retained_bytes <= self.max_bytes {
                break;
            }
            let entry = &entries[cold_idx as usize];
            keys.push(entry.key);
            retained_len = retained_len.saturating_sub(1);
            retained_bytes = retained_bytes.saturating_sub(entry.cost);
        }
        keys
    }

    fn remove_key(&self, fingerprint: &[u8; 32]) {
        if let Some((_, removed)) = self.artifacts.remove(fingerprint) {
            self.cached_bytes.fetch_sub(removed.cost, Ordering::Relaxed);
        }
    }

    /// Remove every cached artifact.
    pub(crate) fn clear(&self) {
        self.artifacts.clear();
        self.cached_bytes.store(0, Ordering::Relaxed);
    }

    /// Invalidate entries impacted by a change in the rule dependency graph.
    ///
    /// This implements the #36 recursion thesis: vyre using its own
    /// `do_calculus` primitive to perform formal causal change-impact
    /// analysis on its own rule graph.
    pub(crate) fn invalidate_impacted(&self, impact_mask: &[u32], keys: &[[u8; 32]]) {
        for (i, &is_impacted) in impact_mask.iter().enumerate() {
            if is_impacted != 0 {
                if let Some(key) = keys.get(i) {
                    self.remove_key(key);
                }
            }
        }
    }

    /// Number of cached artifact keys.
    pub(crate) fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Estimated bytes retained by cached artifacts.
    pub(crate) fn cached_bytes(&self) -> usize {
        self.cached_bytes.load(Ordering::Relaxed)
    }

    /// Entry budget.
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries as usize
    }

    /// Estimated byte budget.
    pub(crate) fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Cache lookup hits.
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Cache lookup misses.
    pub(crate) fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Cache insertions.
    pub(crate) fn insertions(&self) -> u64 {
        self.insertions.load(Ordering::Relaxed)
    }

    /// Capacity-driven evictions.
    pub(crate) fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }
}

struct EvictionEntry {
    key: [u8; 32],
    gain: u32,
    last_hit_time_s: f64,
    cost: usize,
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64())
}

fn f64_to_atomic(value: f64) -> u64 {
    value.to_bits()
}

fn atomic_to_f64(bits: u64) -> f64 {
    f64::from_bits(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn entry(key_byte: u8, gain: u32, last_hit_time_s: f64, cost: usize) -> EvictionEntry {
        EvictionEntry {
            key: key(key_byte),
            gain,
            last_hit_time_s,
            cost,
        }
    }

    #[test]
    fn pipeline_cache_eviction_uses_heat_not_insert_order() {
        let cache = LruPipelineCache::with_limits(2, 1024);
        let entries = [
            entry(1, 1, 100.0, 1),
            entry(2, 100, 100.0, 1),
            entry(3, 50, 100.0, 1),
        ];
        assert_eq!(cache.eviction_keys(&entries), vec![key(1)]);
    }

    #[test]
    fn pipeline_cache_eviction_continues_until_byte_budget_fits() {
        let cache = LruPipelineCache::with_limits(8, 10);
        let entries = [
            entry(1, 1, 100.0, 8),
            entry(2, 2, 100.0, 8),
            entry(3, 100, 100.0, 2),
        ];
        assert_eq!(cache.eviction_keys(&entries), vec![key(1)]);
    }
}
