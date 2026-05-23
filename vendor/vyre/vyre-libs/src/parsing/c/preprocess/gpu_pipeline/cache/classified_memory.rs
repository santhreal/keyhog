use rustc_hash::FxHashMap as HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use super::super::classified_size::classified_tokens_bytes;
use super::super::lru_index::LruIndex;
use super::super::ClassifiedTokens;
#[cfg(test)]
use super::disk_common::source_hash128;

const CLASSIFIED_CACHE_MAX_ENTRIES: usize = 4096;
const CLASSIFIED_CACHE_MAX_BYTES: usize = 512 * 1024 * 1024;

pub(crate) const PREPROCESS_CACHE_SEMANTIC_VERSION: &[u8] = b"gpu-preprocess-cache-v14";

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct ClassifiedCacheKey {
    pub(crate) path: PathBuf,
    pub(crate) source_len: usize,
    pub(crate) source_hash: [u8; 16],
}

pub(super) struct ClassifiedTokenCache {
    entries: HashMap<ClassifiedCacheKey, ClassifiedTokenCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<ClassifiedCacheKey>,
}

struct ClassifiedTokenCacheEntry {
    value: Arc<ClassifiedTokens>,
    bytes: usize,
    last_access: u64,
}

impl ClassifiedTokenCache {
    fn new() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: CLASSIFIED_CACHE_MAX_ENTRIES,
            max_bytes: CLASSIFIED_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(CLASSIFIED_CACHE_MAX_ENTRIES),
        }
    }

    #[cfg(test)]
    pub(super) fn with_limit(max_entries: usize) -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries,
            max_bytes: CLASSIFIED_CACHE_MAX_BYTES,
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

    pub(super) fn lookup(&mut self, key: &ClassifiedCacheKey) -> Option<Arc<ClassifiedTokens>> {
        let next_epoch = self.next_epoch();
        let entry = self.entries.get_mut(key)?;
        entry.last_access = next_epoch;
        let value = Arc::clone(&entry.value);
        self.lru.record(key.clone(), next_epoch);
        self.compact_lru_if_needed();
        Some(value)
    }

    pub(super) fn insert(&mut self, key: ClassifiedCacheKey, value: Arc<ClassifiedTokens>) {
        let entry_bytes = classified_tokens_bytes(&value);
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
                "vyre-libs gpu preprocessor classified token cache byte accounting overflowed during insert. Fix: lower classified token cache limits or shard preprocessing sessions."
            )
        });
        self.entries.insert(
            key.clone(),
            ClassifiedTokenCacheEntry {
                value,
                bytes: entry_bytes,
                last_access,
            },
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
    pub(super) fn contains_key(&self, key: &ClassifiedCacheKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn remove(&mut self, key: &ClassifiedCacheKey) -> Option<ClassifiedTokenCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.checked_sub(entry.bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor classified token cache byte accounting underflowed during eviction. Fix: repair classified token cache accounting before relying on memory limits."
            )
        });
        Some(entry)
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor classified token cache epoch overflowed. Fix: recreate process-local preprocess cache before continuing an unbounded translation-unit stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<ClassifiedCacheKey> {
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

fn classified_cache() -> &'static Mutex<ClassifiedTokenCache> {
    static CACHE: OnceLock<Mutex<ClassifiedTokenCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ClassifiedTokenCache::new()))
}

#[cfg(test)]
pub(crate) fn classified_cache_key(path: &std::path::Path, source: &[u8]) -> ClassifiedCacheKey {
    classified_cache_key_from_hash(path, source.len(), source_hash128(source))
}

pub(crate) fn classified_cache_key_from_hash(
    path: &std::path::Path,
    source_len: usize,
    source_hash: [u8; 16],
) -> ClassifiedCacheKey {
    ClassifiedCacheKey {
        path: path.to_path_buf(),
        source_len,
        source_hash,
    }
}

pub(crate) fn cached_classified_tokens(
    key: &ClassifiedCacheKey,
) -> Result<Option<Arc<ClassifiedTokens>>, String> {
    classified_cache()
        .lock()
        .map_err(|_| "vyre-libs::gpu_pipeline: classified token cache poisoned".to_string())
        .map(|mut cache| cache.lookup(key))
}

pub(crate) fn insert_classified_tokens(
    key: ClassifiedCacheKey,
    classified: Arc<ClassifiedTokens>,
) -> Result<(), String> {
    let mut cache = classified_cache().lock().map_err(|_| {
        "vyre-libs::gpu_pipeline: classified token cache poisoned while inserting".to_string()
    })?;
    cache.insert(key, classified);
    Ok(())
}
