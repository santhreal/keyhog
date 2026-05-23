use super::*;
use crate::parsing::c::preprocess::gpu_pipeline::classified_size::classified_tokens_bytes;
use crate::parsing::c::preprocess::gpu_pipeline::lru_index::LruIndex;
use crate::parsing::c::preprocess::gpu_pipeline::token_provenance::model::REPLACEMENT_TOKEN_CACHE_MAX_BYTES;

pub(crate) fn cached_replacement_tokens(
    dispatcher: &dyn GpuDispatcher,
    mac: &MacroDef,
    symbol_id: [u8; 16],
) -> Result<std::sync::Arc<ClassifiedTokens>, String> {
    let key = ReplacementTokenCacheKey {
        symbol_id,
        body_hash: hash_bytes16(&mac.body),
        args_hash: hash_bytes16(&mac.args),
        is_function_like: mac.is_function_like,
    };
    if let Some(classified) = replacement_token_cache()
        .lock()
        .map_err(|error| format!("macro replacement token cache lock poisoned: {error}"))?
        .lookup(&key)
    {
        return Ok(classified);
    }
    let classified = std::sync::Arc::new(gpu_tokenize_without_directive_metadata(
        dispatcher, &mac.body,
    )?);
    let mut cache = replacement_token_cache()
        .lock()
        .map_err(|error| format!("macro replacement token cache lock poisoned: {error}"))?;
    cache.insert(key, classified.clone());
    Ok(classified)
}

struct ReplacementTokenCache {
    entries: HashMap<ReplacementTokenCacheKey, ReplacementTokenCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<ReplacementTokenCacheKey>,
}

struct ReplacementTokenCacheEntry {
    value: std::sync::Arc<ClassifiedTokens>,
    bytes: usize,
    last_access: u64,
}

impl ReplacementTokenCache {
    fn new() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: REPLACEMENT_TOKEN_CACHE_MAX_ENTRIES,
            max_bytes: REPLACEMENT_TOKEN_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(REPLACEMENT_TOKEN_CACHE_MAX_ENTRIES),
        }
    }

    #[cfg(test)]
    fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries,
            max_bytes,
            epoch: 0,
            lru: LruIndex::with_capacity(max_entries),
        }
    }

    fn lookup(
        &mut self,
        key: &ReplacementTokenCacheKey,
    ) -> Option<std::sync::Arc<ClassifiedTokens>> {
        let next_epoch = self.next_epoch();
        let entry = self.entries.get_mut(key)?;
        entry.last_access = next_epoch;
        let value = entry.value.clone();
        self.lru.record(key.clone(), next_epoch);
        self.compact_lru_if_needed();
        Some(value)
    }

    fn insert(&mut self, key: ReplacementTokenCacheKey, value: std::sync::Arc<ClassifiedTokens>) {
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
                "vyre-libs gpu preprocessor replacement token cache byte accounting overflowed during insert. Fix: lower replacement token cache limits or shard macro-expansion sessions."
            )
        });
        self.entries.insert(
            key.clone(),
            ReplacementTokenCacheEntry {
                value,
                bytes: entry_bytes,
                last_access,
            },
        );
        self.lru.record(key, last_access);
        self.compact_lru_if_needed();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn byte_len(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    fn contains_key(&self, key: &ReplacementTokenCacheKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn remove(&mut self, key: &ReplacementTokenCacheKey) -> Option<ReplacementTokenCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.checked_sub(entry.bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor replacement token cache byte accounting underflowed during eviction. Fix: repair replacement token cache accounting before relying on memory limits."
            )
        });
        Some(entry)
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor replacement token cache epoch overflowed. Fix: recreate process-local token provenance cache before continuing an unbounded macro-expansion stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<ReplacementTokenCacheKey> {
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

fn replacement_token_cache() -> &'static Mutex<ReplacementTokenCache> {
    static CACHE: OnceLock<Mutex<ReplacementTokenCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ReplacementTokenCache::new()))
}

pub(crate) fn hash_bytes16(bytes: &[u8]) -> [u8; 16] {
    let digest = blake3::hash(bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn key(id: u8) -> ReplacementTokenCacheKey {
        ReplacementTokenCacheKey {
            symbol_id: [id; 16],
            body_hash: [id.wrapping_add(1); 16],
            args_hash: [id.wrapping_add(2); 16],
            is_function_like: id % 2 == 0,
        }
    }

    fn classified(id: u8, source_len: usize) -> Arc<ClassifiedTokens> {
        Arc::new(ClassifiedTokens {
            tok_types: vec![id as u32],
            tok_starts: vec![0],
            tok_lens: vec![source_len as u32],
            directive_kinds: vec![0],
            directive_count: 0,
            source: Arc::from(vec![id; source_len].into_boxed_slice()),
        })
    }

    #[test]
    fn replacement_token_cache_evicts_to_byte_budget() {
        let mut cache = ReplacementTokenCache::with_limits(8, 96);
        let a = key(1);
        let b = key(2);
        let c = key(3);
        cache.insert(a.clone(), classified(1, 16));
        cache.insert(b.clone(), classified(2, 16));
        assert!(cache.lookup(&a).is_some());
        cache.insert(c.clone(), classified(3, 48));
        assert!(cache.contains_key(&a));
        assert!(!cache.contains_key(&b));
        assert!(cache.contains_key(&c));
        assert!(cache.byte_len() <= 96);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn replacement_token_cache_lru_index_stays_capacity_scale() {
        let mut cache = ReplacementTokenCache::with_limits(4, 1 << 20);

        for id in 0..96u8 {
            let key = key(id);
            cache.insert(key.clone(), classified(id, 8));
            assert!(cache.lookup(&key).is_some());
        }

        assert_eq!(cache.len(), 4);
        assert!(
            cache.lru_index_len() <= cache.len().saturating_mul(4).max(8),
            "Fix: replacement token cache LRU index must compact stale touches to cache-capacity scale"
        );
    }
}
