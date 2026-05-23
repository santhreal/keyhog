use rustc_hash::FxHashMap as HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::super::lru_index::LruIndex;
use super::super::payload_size::directive_payloads_bytes;
use super::super::DirectivePayload;
use super::payload_keys::PayloadsCacheKey;

const PAYLOAD_CACHE_MAX_ENTRIES: usize = 4096;
const PAYLOAD_CACHE_MAX_BYTES: usize = 512 * 1024 * 1024;

pub(in crate::parsing::c::preprocess::gpu_pipeline) struct PayloadCache {
    entries: HashMap<PayloadsCacheKey, PayloadCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<PayloadsCacheKey>,
}

struct PayloadCacheEntry {
    value: Arc<[DirectivePayload]>,
    bytes: usize,
    last_access: u64,
}

impl PayloadCache {
    fn new() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: PAYLOAD_CACHE_MAX_ENTRIES,
            max_bytes: PAYLOAD_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(PAYLOAD_CACHE_MAX_ENTRIES),
        }
    }

    #[cfg(test)]
    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn with_limit(max_entries: usize) -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries,
            max_bytes: PAYLOAD_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(max_entries),
        }
    }

    #[cfg(test)]
    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn with_limits(
        max_entries: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries,
            max_bytes,
            epoch: 0,
            lru: LruIndex::with_capacity(max_entries),
        }
    }

    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn lookup(
        &mut self,
        key: &PayloadsCacheKey,
    ) -> Option<Arc<[DirectivePayload]>> {
        let next_epoch = self.next_epoch();
        let entry = self.entries.get_mut(key)?;
        entry.last_access = next_epoch;
        let value = Arc::clone(&entry.value);
        self.lru.record(key.clone(), next_epoch);
        self.compact_lru_if_needed();
        Some(value)
    }

    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn insert(
        &mut self,
        key: PayloadsCacheKey,
        value: Arc<[DirectivePayload]>,
    ) {
        let entry_bytes = directive_payloads_bytes(&value);
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
                "vyre-libs gpu preprocessor directive payload cache byte accounting overflowed during insert. Fix: lower payload cache limits or shard preprocessing sessions."
            )
        });
        self.entries.insert(
            key.clone(),
            PayloadCacheEntry {
                value,
                bytes: entry_bytes,
                last_access,
            },
        );
        self.lru.record(key, last_access);
        self.compact_lru_if_needed();
    }

    #[cfg(test)]
    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn byte_len(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn contains_key(
        &self,
        key: &PayloadsCacheKey,
    ) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(in crate::parsing::c::preprocess::gpu_pipeline) fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn remove(&mut self, key: &PayloadsCacheKey) -> Option<PayloadCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.checked_sub(entry.bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor directive payload cache byte accounting underflowed during eviction. Fix: repair payload cache accounting before relying on memory limits."
            )
        });
        Some(entry)
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor directive payload cache epoch overflowed. Fix: recreate process-local preprocess cache before continuing an unbounded translation-unit stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<PayloadsCacheKey> {
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

fn payload_cache() -> &'static Mutex<PayloadCache> {
    static CACHE: OnceLock<Mutex<PayloadCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(PayloadCache::new()))
}

pub(crate) fn cached_payloads(
    key: &PayloadsCacheKey,
) -> Result<Option<Arc<[DirectivePayload]>>, String> {
    payload_cache()
        .lock()
        .map_err(|_| "vyre-libs::gpu_pipeline: directive payload cache poisoned".to_string())
        .map(|mut cache| cache.lookup(key))
}

pub(crate) fn insert_payloads(
    key: PayloadsCacheKey,
    payloads: Arc<[DirectivePayload]>,
) -> Result<(), String> {
    let mut cache = payload_cache().lock().map_err(|_| {
        "vyre-libs::gpu_pipeline: directive payload cache poisoned while inserting".to_string()
    })?;
    cache.insert(key, payloads);
    Ok(())
}
