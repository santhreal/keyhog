use rustc_hash::FxHashMap as HashMap;

use super::lru_index::LruIndex;

const LIVE_CONDITIONAL_CACHE_MAX_ENTRIES: usize = 16_384;
const LIVE_CONDITIONAL_CACHE_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct LiveConditionalCacheKey {
    pub(super) evaluator: u8,
    pub(super) directive_kind: u32,
    pub(super) negated: bool,
    pub(super) row_fingerprint: [u8; 16],
    pub(super) row_len: u32,
    pub(super) macro_fingerprint: [u8; 16],
    pub(super) macro_names_len: u32,
    pub(super) num_macros: u32,
}

pub(super) struct LiveConditionalCache {
    entries: HashMap<LiveConditionalCacheKey, LiveConditionalCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<LiveConditionalCacheKey>,
}

struct LiveConditionalCacheEntry {
    value: bool,
    last_access: u64,
}

impl LiveConditionalCache {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: LIVE_CONDITIONAL_CACHE_MAX_ENTRIES,
            max_bytes: LIVE_CONDITIONAL_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(LIVE_CONDITIONAL_CACHE_MAX_ENTRIES),
        }
    }

    #[cfg(test)]
    pub(super) fn with_limit(max_entries: usize) -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries,
            max_bytes: LIVE_CONDITIONAL_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(max_entries),
        }
    }

    #[cfg(test)]
    pub(super) fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries,
            max_bytes,
            epoch: 0,
            lru: LruIndex::with_capacity(max_entries),
        }
    }

    pub(super) fn lookup(&mut self, key: &LiveConditionalCacheKey) -> Option<bool> {
        let next_epoch = self.next_epoch();
        let entry = self.entries.get_mut(key)?;
        entry.last_access = next_epoch;
        let value = entry.value;
        self.lru.record(key.clone(), next_epoch);
        self.compact_lru_if_needed();
        Some(value)
    }

    pub(super) fn insert(&mut self, key: LiveConditionalCacheKey, value: bool) {
        let entry_bytes = live_conditional_entry_bytes();
        if self.max_entries == 0 || entry_bytes > self.max_bytes {
            self.remove(&key);
            return;
        }
        self.remove(&key);
        while self.entries.len() >= self.max_entries
            || self.bytes.checked_add(entry_bytes).unwrap_or(usize::MAX) > self.max_bytes
        {
            let Some(evict_key) = self.pop_lru_key() else {
                break;
            };
            self.remove(&evict_key);
        }
        let last_access = self.next_epoch();
        self.bytes = self.bytes.checked_add(entry_bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor live conditional cache byte accounting overflowed during insert. Fix: lower live conditional cache limits or shard preprocessing sessions."
            )
        });
        self.entries.insert(
            key.clone(),
            LiveConditionalCacheEntry { value, last_access },
        );
        self.lru.record(key, last_access);
        self.compact_lru_if_needed();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn byte_len(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub(super) fn contains_key(&self, key: &LiveConditionalCacheKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn remove(&mut self, key: &LiveConditionalCacheKey) -> Option<LiveConditionalCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self
            .bytes
            .checked_sub(live_conditional_entry_bytes())
            .unwrap_or_else(|| {
                panic!(
                    "vyre-libs gpu preprocessor live conditional cache byte accounting underflowed during eviction. Fix: repair live conditional cache accounting before relying on memory limits."
                )
            });
        Some(entry)
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor live conditional cache epoch overflowed. Fix: recreate the process-local preprocessor cache before continuing an unbounded translation-unit stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<LiveConditionalCacheKey> {
        self.lru.pop_valid(|key, last_access| {
            self.entries
                .get(key)
                .is_some_and(|entry| entry.last_access == last_access)
        })
    }

    fn compact_lru_if_needed(&mut self) {
        let live = self.entries.len();
        self.lru.compact_if_needed(
            live,
            self.entries
                .iter()
                .map(|(key, entry)| (key.clone(), entry.last_access)),
        );
    }
}

fn live_conditional_entry_bytes() -> usize {
    std::mem::size_of::<LiveConditionalCacheKey>()
        .checked_add(std::mem::size_of::<LiveConditionalCacheEntry>())
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{live_conditional_entry_bytes, LiveConditionalCache, LiveConditionalCacheKey};

    fn key(id: u8) -> LiveConditionalCacheKey {
        LiveConditionalCacheKey {
            evaluator: id,
            directive_kind: id as u32,
            negated: false,
            row_fingerprint: [id; 16],
            row_len: id as u32,
            macro_fingerprint: [id; 16],
            macro_names_len: id as u32,
            num_macros: id as u32,
        }
    }

    #[test]
    fn live_conditional_cache_evicts_least_recently_used_entry() {
        let mut cache = LiveConditionalCache::with_limit(2);
        let a = key(1);
        let b = key(2);
        let c = key(3);
        cache.insert(a.clone(), true);
        cache.insert(b.clone(), false);
        assert_eq!(cache.lookup(&a), Some(true));
        cache.insert(c.clone(), true);
        assert!(cache.contains_key(&a));
        assert!(!cache.contains_key(&b));
        assert!(cache.contains_key(&c));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn live_conditional_cache_evicts_to_byte_budget() {
        let entry_bytes = live_conditional_entry_bytes();
        let mut cache = LiveConditionalCache::with_limits(8, entry_bytes * 2);
        let a = key(1);
        let b = key(2);
        let c = key(3);
        cache.insert(a.clone(), true);
        cache.insert(b.clone(), false);
        assert_eq!(cache.lookup(&a), Some(true));
        cache.insert(c.clone(), true);
        assert!(cache.contains_key(&a));
        assert!(!cache.contains_key(&b));
        assert!(cache.contains_key(&c));
        assert_eq!(cache.len(), 2);
        assert!(cache.byte_len() <= entry_bytes * 2);
    }

    #[test]
    fn live_conditional_cache_lru_index_stays_capacity_scale() {
        let mut cache = LiveConditionalCache::with_limit(4);

        for id in 0..96u8 {
            let cache_key = key(id);
            cache.insert(cache_key.clone(), id % 2 == 0);
            assert!(cache.lookup(&cache_key).is_some());
        }

        assert_eq!(cache.len(), 4);
        assert!(
            cache.lru_index_len() <= cache.len().saturating_mul(4).max(8),
            "Fix: live conditional cache LRU index must compact stale touches to cache-capacity scale"
        );
    }
}
