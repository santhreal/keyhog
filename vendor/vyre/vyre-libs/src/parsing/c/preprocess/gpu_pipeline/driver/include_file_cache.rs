use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustc_hash::FxHashMap as HashMap;

use crate::parsing::c::preprocess::gpu_pipeline::IncludeByteCacheStats;
use crate::parsing::c::preprocess::gpu_pipeline::IncludeLoader;

type IncludeFileCacheKey = (PathBuf, Vec<u8>, bool, bool);
const DEFAULT_MAX_INCLUDE_CACHE_ENTRIES: usize = 4096;
const DEFAULT_MAX_INCLUDE_CACHE_BYTES: usize = 64 * 1024 * 1024;

pub(super) enum IncludeFileResidency {
    Filesystem,
    RunCache,
}

pub(super) struct IncludeFile {
    pub(super) canonical_path: PathBuf,
    pub(super) bytes: Arc<[u8]>,
    pub(super) residency: IncludeFileResidency,
}

struct IncludeFileCacheEntry {
    canonical_path: PathBuf,
    bytes: Arc<[u8]>,
    retained_bytes: usize,
    last_used: u64,
}

pub(super) struct IncludeFileCache {
    entries: HashMap<IncludeFileCacheKey, IncludeFileCacheEntry>,
    lru: BinaryHeap<Reverse<IncludeFileCacheLruEntry>>,
    clock: u64,
    lru_serial: u64,
    retained_bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    hits: u64,
    misses: u64,
    evictions: u64,
    loaded_bytes: u64,
    reused_bytes: u64,
}

impl Default for IncludeFileCache {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_MAX_INCLUDE_CACHE_ENTRIES,
            DEFAULT_MAX_INCLUDE_CACHE_BYTES,
        )
    }
}

impl IncludeFileCache {
    fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::default(),
            lru: BinaryHeap::new(),
            clock: 0,
            lru_serial: 0,
            retained_bytes: 0,
            max_entries,
            max_bytes,
            hits: 0,
            misses: 0,
            evictions: 0,
            loaded_bytes: 0,
            reused_bytes: 0,
        }
    }

    pub(super) fn resolve(
        &mut self,
        loader: &dyn IncludeLoader,
        from: &Path,
        path: &[u8],
        is_system: bool,
        is_next: bool,
    ) -> Result<Option<IncludeFile>, String> {
        let key = (
            cache_scope_path(from, is_system, is_next),
            path.to_vec(),
            is_system,
            is_next,
        );
        self.clock = self.clock.saturating_add(1);
        if let Some(entry) = self.entries.get_mut(&key) {
            self.hits = self.hits.saturating_add(1);
            self.reused_bytes = self
                .reused_bytes
                .saturating_add(u64::try_from(entry.bytes.len()).unwrap_or(u64::MAX));
            entry.last_used = self.clock;
            let canonical_path = entry.canonical_path.clone();
            let bytes = Arc::clone(&entry.bytes);
            self.record_lru(key, self.clock);
            return Ok(Some(IncludeFile {
                canonical_path,
                bytes,
                residency: IncludeFileResidency::RunCache,
            }));
        }
        self.misses = self.misses.saturating_add(1);
        let Some((canonical_path, bytes)) = loader.load(path, is_system, is_next, from)? else {
            return Ok(None);
        };
        self.loaded_bytes = self
            .loaded_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.insert(key, canonical_path.clone(), Arc::clone(&bytes));
        Ok(Some(IncludeFile {
            canonical_path,
            bytes,
            residency: IncludeFileResidency::Filesystem,
        }))
    }

    pub(super) fn stats(&self) -> IncludeByteCacheStats {
        IncludeByteCacheStats {
            hits: self.hits,
            misses: self.misses,
            entries: self.entries.len(),
            evictions: self.evictions,
            retained_bytes: u64::try_from(self.retained_bytes).unwrap_or(u64::MAX),
            loaded_bytes: self.loaded_bytes,
            reused_bytes: self.reused_bytes,
        }
    }

    fn insert(&mut self, key: IncludeFileCacheKey, canonical_path: PathBuf, bytes: Arc<[u8]>) {
        let retained_bytes = retained_entry_bytes(&key, &canonical_path, bytes.len());
        if self.max_entries == 0 || retained_bytes > self.max_bytes {
            return;
        }
        let last_used = self.clock;
        self.retained_bytes = self.retained_bytes.saturating_add(retained_bytes);
        self.entries.insert(
            key.clone(),
            IncludeFileCacheEntry {
                canonical_path,
                bytes,
                retained_bytes,
                last_used,
            },
        );
        self.record_lru(key, last_used);
        self.evict_to_limits();
    }

    fn evict_to_limits(&mut self) {
        while self.entries.len() > self.max_entries || self.retained_bytes > self.max_bytes {
            let Some(Reverse(candidate)) = self.lru.pop() else {
                break;
            };
            let should_evict = self
                .entries
                .get(&candidate.key)
                .map(|entry| entry.last_used == candidate.last_used)
                .unwrap_or(false);
            if !should_evict {
                continue;
            }
            if let Some(entry) = self.entries.remove(&candidate.key) {
                self.retained_bytes = self.retained_bytes.saturating_sub(entry.retained_bytes);
                self.evictions = self.evictions.saturating_add(1);
            }
        }
    }

    fn record_lru(&mut self, key: IncludeFileCacheKey, last_used: u64) {
        self.lru_serial = self.lru_serial.saturating_add(1);
        self.lru.push(Reverse(IncludeFileCacheLruEntry {
            last_used,
            serial: self.lru_serial,
            key,
        }));
        self.compact_lru_if_needed();
    }

    fn compact_lru_if_needed(&mut self) {
        if self.lru.len() <= self.entries.len().saturating_mul(4).saturating_add(32) {
            return;
        }
        let mut live = BinaryHeap::with_capacity(self.entries.len());
        self.lru_serial = 0;
        for (key, entry) in &self.entries {
            self.lru_serial = self.lru_serial.saturating_add(1);
            live.push(Reverse(IncludeFileCacheLruEntry {
                last_used: entry.last_used,
                serial: self.lru_serial,
                key: key.clone(),
            }));
        }
        self.lru = live;
    }

    #[cfg(test)]
    fn lru_len_for_tests(&self) -> usize {
        self.lru.len()
    }
}

#[derive(Clone, Debug)]
struct IncludeFileCacheLruEntry {
    last_used: u64,
    serial: u64,
    key: IncludeFileCacheKey,
}

impl PartialEq for IncludeFileCacheLruEntry {
    fn eq(&self, other: &Self) -> bool {
        self.last_used == other.last_used && self.serial == other.serial
    }
}

impl Eq for IncludeFileCacheLruEntry {}

impl Ord for IncludeFileCacheLruEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.last_used
            .cmp(&other.last_used)
            .then_with(|| self.serial.cmp(&other.serial))
    }
}

impl PartialOrd for IncludeFileCacheLruEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cache_scope_path(from: &Path, is_system: bool, is_next: bool) -> PathBuf {
    if is_system && !is_next {
        PathBuf::new()
    } else {
        from.to_path_buf()
    }
}

fn retained_entry_bytes(
    key: &IncludeFileCacheKey,
    canonical_path: &Path,
    bytes_len: usize,
) -> usize {
    key.0
        .to_string_lossy()
        .len()
        .saturating_add(key.1.len())
        .saturating_add(canonical_path.to_string_lossy().len())
        .saturating_add(bytes_len)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use super::IncludeFileCache;
    use crate::parsing::c::preprocess::gpu_pipeline::IncludeLoader;

    struct TestLoader {
        files: HashMap<Vec<u8>, Vec<u8>>,
        loads: Cell<usize>,
    }

    impl TestLoader {
        fn new(files: &[(&[u8], &[u8])]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(path, bytes)| (path.to_vec(), bytes.to_vec()))
                    .collect(),
                loads: Cell::new(0),
            }
        }
    }

    impl IncludeLoader for TestLoader {
        fn load(
            &self,
            path: &[u8],
            _is_system: bool,
            _is_next: bool,
            _from: &Path,
        ) -> Result<Option<(PathBuf, Arc<[u8]>)>, String> {
            self.loads.set(self.loads.get() + 1);
            Ok(self.files.get(path).map(|bytes| {
                (
                    PathBuf::from(String::from_utf8_lossy(path).into_owned()),
                    bytes.clone().into(),
                )
            }))
        }
    }

    #[test]
    fn include_file_cache_evicts_to_entry_budget() {
        let loader = TestLoader::new(&[(b"a.h", b"int a;"), (b"b.h", b"int b;")]);
        let mut cache = IncludeFileCache::with_limits(1, usize::MAX);

        assert!(cache
            .resolve(&loader, Path::new("<tu>"), b"a.h", false, false)
            .expect("resolve a")
            .is_some());
        assert!(cache
            .resolve(&loader, Path::new("<tu>"), b"b.h", false, false)
            .expect("resolve b")
            .is_some());

        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.evictions, 1);
        assert!(stats.retained_bytes > 0);
    }

    #[test]
    fn include_file_cache_does_not_retain_oversized_entries() {
        let loader = TestLoader::new(&[(b"huge.h", b"0123456789")]);
        let mut cache = IncludeFileCache::with_limits(8, 4);

        assert!(cache
            .resolve(&loader, Path::new("<tu>"), b"huge.h", false, false)
            .expect("resolve huge")
            .is_some());

        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.retained_bytes, 0);
        assert_eq!(stats.loaded_bytes, 10);
    }

    #[test]
    fn include_file_cache_lru_heap_compacts_hot_hits() {
        let loader = TestLoader::new(&[(b"hot.h", b"int hot;")]);
        let mut cache = IncludeFileCache::with_limits(8, usize::MAX);

        assert!(cache
            .resolve(&loader, Path::new("<tu>"), b"hot.h", false, false)
            .expect("resolve hot")
            .is_some());
        for _ in 0..160 {
            assert!(cache
                .resolve(&loader, Path::new("<tu>"), b"hot.h", false, false)
                .expect("resolve cached hot")
                .is_some());
        }

        assert_eq!(cache.stats().entries, 1);
        assert_eq!(cache.stats().hits, 160);
        assert_eq!(loader.loads.get(), 1);
        assert!(
            cache.lru_len_for_tests() <= cache.stats().entries.saturating_mul(4).saturating_add(32),
            "Fix: include-file cache LRU metadata must compact stale hot-hit records instead of growing with every include."
        );
    }
}
