use super::*;
use crate::parsing::c::preprocess::gpu_pipeline::classified_size::classified_tokens_bytes;
use crate::parsing::c::preprocess::gpu_pipeline::lru_index::LruIndex;

pub(crate) const MACRO_EXPANSION_MIN_REPLACEMENT_SOURCE_BYTES: usize = 256;
pub(crate) const MACRO_EXPANSION_MIN_OUTPUT_TOKENS: usize = 256;
pub(crate) const MACRO_EXPANSION_MIN_OUTPUT_SOURCE_BYTES: usize = 2_048;
pub(crate) const MACRO_RESCAN_DEPTH_LIMIT: usize = 64;

#[derive(Default)]
pub(crate) struct MacroExpansionCache {
    pub(crate) live_macro_lookup: LiveMacroLookup,
    expanded_segments: ExpandedSegmentCache,
    packed_tables: PackedTableCache,
    pub(crate) dispatch_scratch: MacroExpansionDispatchScratch,
    rescan_segment_scratch: Vec<u8>,
    range_chunk_scratch: Vec<u8>,
}

impl MacroExpansionCache {
    pub(crate) fn clear(&mut self) {
        self.live_macro_lookup.clear();
    }

    pub(crate) fn cached_expanded_segment(
        &mut self,
        key: &MacroSegmentCacheKey,
    ) -> Option<&CachedExpandedSegment> {
        self.expanded_segments.lookup(key)
    }

    pub(crate) fn insert_expanded_segment(
        &mut self,
        key: MacroSegmentCacheKey,
        value: CachedExpandedSegment,
    ) {
        self.expanded_segments.insert(key, value);
    }

    pub(crate) fn packed_macro_table_with_dispatch_scratch(
        &mut self,
        macro_hash: [u8; 16],
        macros: &[MacroDef],
    ) -> Result<
        (
            &macro_table::PackedMacroTable,
            &mut MacroExpansionDispatchScratch,
        ),
        String,
    > {
        let packed_tables = &mut self.packed_tables;
        let dispatch_scratch = &mut self.dispatch_scratch;
        let table = packed_tables.lookup_or_insert(macro_hash, macros)?;
        Ok((table, dispatch_scratch))
    }

    pub(crate) fn take_rescan_segment_scratch(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.rescan_segment_scratch)
    }

    pub(crate) fn store_rescan_segment_scratch(&mut self, mut scratch: Vec<u8>) {
        scratch.clear();
        self.rescan_segment_scratch = scratch;
    }

    pub(crate) fn take_range_chunk_scratch(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.range_chunk_scratch)
    }

    pub(crate) fn store_range_chunk_scratch(&mut self, mut scratch: Vec<u8>) {
        scratch.clear();
        self.range_chunk_scratch = scratch;
    }
}

#[derive(Default)]
pub(crate) struct MacroExpansionDispatchScratch {
    pub(crate) input_buffers: Vec<Vec<u8>>,
    pub(crate) runtime_counts: Vec<u8>,
    pub(crate) replacement_words: Vec<u8>,
    pub(crate) outputs: Vec<Vec<u8>>,
}

impl MacroExpansionDispatchScratch {
    pub(crate) fn ensure_input_buffers(&mut self, slots: usize) {
        if self.input_buffers.len() < slots {
            self.input_buffers.resize_with(slots, Vec::new);
        }
    }

    pub(crate) fn input_buffer_mut(&mut self, index: usize) -> &mut Vec<u8> {
        &mut self.input_buffers[index]
    }

    pub(crate) fn write_zero_bytes(&mut self, index: usize, byte_len: usize) {
        let buffer = &mut self.input_buffers[index];
        buffer.clear();
        buffer.resize(byte_len, 0);
    }

    pub(crate) fn write_runtime_counts(
        &mut self,
        token_count: u32,
        source_len: u32,
        replacement_source_len: u32,
    ) {
        self.runtime_counts.clear();
        self.runtime_counts
            .extend_from_slice(&token_count.to_le_bytes());
        self.runtime_counts
            .extend_from_slice(&source_len.to_le_bytes());
        self.runtime_counts
            .extend_from_slice(&replacement_source_len.to_le_bytes());
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) struct MacroSegmentCacheKey {
    pub(crate) source_len: usize,
    pub(crate) source_hash: [u8; 16],
    pub(crate) macro_hash: [u8; 16],
}

#[derive(Clone)]
pub(crate) struct CachedExpandedSegment {
    pub(crate) bytes: Vec<u8>,
    pub(crate) classified: ClassifiedTokens,
}

const MACRO_EXPANDED_SEGMENT_CACHE_MAX_ENTRIES: usize = 8_192;
const MACRO_EXPANDED_SEGMENT_CACHE_MAX_BYTES: usize = 512 * 1024 * 1024;

struct ExpandedSegmentCache {
    entries: HashMap<MacroSegmentCacheKey, ExpandedSegmentCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<MacroSegmentCacheKey>,
}

struct ExpandedSegmentCacheEntry {
    value: CachedExpandedSegment,
    bytes: usize,
    last_access: u64,
}

impl Default for ExpandedSegmentCache {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: MACRO_EXPANDED_SEGMENT_CACHE_MAX_ENTRIES,
            max_bytes: MACRO_EXPANDED_SEGMENT_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(MACRO_EXPANDED_SEGMENT_CACHE_MAX_ENTRIES),
        }
    }
}

impl ExpandedSegmentCache {
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

    fn lookup(&mut self, key: &MacroSegmentCacheKey) -> Option<&CachedExpandedSegment> {
        let next_epoch = self.next_epoch();
        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_access = next_epoch;
        } else {
            return None;
        }
        self.lru.record(key.clone(), next_epoch);
        self.compact_lru_if_needed();
        self.entries.get(key).map(|entry| &entry.value)
    }

    fn insert(&mut self, key: MacroSegmentCacheKey, value: CachedExpandedSegment) {
        let entry_bytes = cached_expanded_segment_bytes(&value);
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
                "vyre-libs gpu preprocessor macro expanded-segment cache byte accounting overflowed during insert. Fix: lower macro expansion cache limits or shard macro-expansion sessions."
            )
        });
        self.entries.insert(
            key.clone(),
            ExpandedSegmentCacheEntry {
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
    fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn remove(&mut self, key: &MacroSegmentCacheKey) -> Option<ExpandedSegmentCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.checked_sub(entry.bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor macro expanded-segment cache byte accounting underflowed during eviction. Fix: repair macro expansion cache accounting before relying on memory limits."
            )
        });
        Some(entry)
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor macro expansion cache epoch overflowed. Fix: recreate macro expansion state before continuing an unbounded translation-unit stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<MacroSegmentCacheKey> {
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

const PACKED_MACRO_TABLE_CACHE_MAX_ENTRIES: usize = 4_096;
const PACKED_MACRO_TABLE_CACHE_MAX_BYTES: usize = 256 * 1024 * 1024;

struct PackedTableCache {
    entries: HashMap<[u8; 16], PackedTableCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<[u8; 16]>,
}

struct PackedTableCacheEntry {
    value: macro_table::PackedMacroTable,
    bytes: usize,
    last_access: u64,
}

impl Default for PackedTableCache {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: PACKED_MACRO_TABLE_CACHE_MAX_ENTRIES,
            max_bytes: PACKED_MACRO_TABLE_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(PACKED_MACRO_TABLE_CACHE_MAX_ENTRIES),
        }
    }
}

impl PackedTableCache {
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

    fn lookup_or_insert(
        &mut self,
        key: [u8; 16],
        macros: &[MacroDef],
    ) -> Result<&macro_table::PackedMacroTable, String> {
        let last_access = self.next_epoch();
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_access = last_access;
            self.lru.record(key, last_access);
            self.compact_lru_if_needed();
        } else {
            let value = macro_table::PackedMacroTable::from_definitions(macros)?;
            let entry_bytes = value.byte_len();
            if self.max_entries == 0 || entry_bytes > self.max_bytes {
                return Err(format!(
                    "vyre-libs::gpu_pipeline: packed macro table cache entry is {entry_bytes} bytes, exceeding the configured {max_bytes} byte cache budget. Fix: shard macro-heavy translation units or raise the packed macro table cache budget.",
                    max_bytes = self.max_bytes
                ));
            }
            while self.entries.len() >= self.max_entries
                || self.bytes.checked_add(entry_bytes).unwrap_or(usize::MAX) > self.max_bytes
            {
                let Some(evict_key) = self.pop_lru_key() else {
                    break;
                };
                self.remove(&evict_key);
            }
            self.bytes = self.bytes.checked_add(entry_bytes).unwrap_or_else(|| {
                panic!(
                    "vyre-libs gpu preprocessor packed macro table cache byte accounting overflowed during insert. Fix: lower packed macro table cache limits or shard macro-expansion sessions."
                )
            });
            self.entries.insert(
                key,
                PackedTableCacheEntry {
                    value,
                    bytes: entry_bytes,
                    last_access,
                },
            );
            self.lru.record(key, last_access);
            self.compact_lru_if_needed();
        }
        self.entries
            .get(&key)
            .map(|entry| &entry.value)
            .ok_or_else(|| {
                "vyre-libs::gpu_pipeline: packed macro table cache insert was lost. Fix: keep macro table cache mutation single-threaded per translation unit.".to_string()
            })
    }

    fn remove(&mut self, key: &[u8; 16]) -> Option<PackedTableCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.checked_sub(entry.bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor packed macro table cache byte accounting underflowed during eviction. Fix: repair packed macro table cache accounting before relying on memory limits."
            )
        });
        Some(entry)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor packed macro table cache epoch overflowed. Fix: recreate macro expansion state before continuing an unbounded translation-unit stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<[u8; 16]> {
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
                .map(|(key, entry)| (*key, entry.last_access)),
        );
    }
}

fn cached_expanded_segment_bytes(segment: &CachedExpandedSegment) -> usize {
    segment
        .bytes
        .len()
        .checked_add(classified_tokens_bytes(&segment.classified))
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment_key(id: u8) -> MacroSegmentCacheKey {
        MacroSegmentCacheKey {
            source_len: id as usize,
            source_hash: [id; 16],
            macro_hash: [id.wrapping_add(1); 16],
        }
    }

    fn segment(id: u8) -> CachedExpandedSegment {
        CachedExpandedSegment {
            bytes: vec![id; 8],
            classified: ClassifiedTokens {
                tok_types: vec![id as u32],
                tok_starts: vec![0],
                tok_lens: vec![8],
                directive_kinds: vec![0],
                directive_count: 0,
                source: std::sync::Arc::from(vec![id; 8].into_boxed_slice()),
            },
        }
    }

    fn macro_def(id: u8) -> MacroDef {
        MacroDef {
            name: format!("M{id}").into_bytes(),
            args: Vec::new(),
            body: b"1".to_vec(),
            is_function_like: false,
        }
    }

    #[test]
    fn expanded_segment_cache_lru_index_stays_capacity_scale() {
        let mut cache = ExpandedSegmentCache::with_limits(4, 1 << 20);

        for id in 0..96u8 {
            let key = segment_key(id);
            cache.insert(key.clone(), segment(id));
            assert!(cache.lookup(&key).is_some());
        }

        assert_eq!(cache.len(), 4);
        assert!(
            cache.lru_index_len() <= cache.len().saturating_mul(4).max(8),
            "Fix: expanded segment cache LRU index must compact stale touches to cache-capacity scale"
        );
    }

    #[test]
    fn packed_table_cache_lru_index_stays_capacity_scale() {
        let mut cache = PackedTableCache::with_limits(4, 1 << 20);

        for id in 0..96u8 {
            let key = [id; 16];
            let macros = [macro_def(id)];
            assert!(cache.lookup_or_insert(key, &macros).is_ok());
            assert!(cache.lookup_or_insert(key, &macros).is_ok());
        }

        assert_eq!(cache.len(), 4);
        assert!(
            cache.lru_index_len() <= cache.len().saturating_mul(4).max(8),
            "Fix: packed macro table cache LRU index must compact stale touches to cache-capacity scale"
        );
    }
}
