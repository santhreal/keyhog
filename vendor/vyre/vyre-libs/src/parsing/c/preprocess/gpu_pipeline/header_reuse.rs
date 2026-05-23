//! Parallel header-analysis reuse keyed by path, flags, defines, and target triple.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use rustc_hash::FxHashMap as HashMap;

use super::classified_size::classified_tokens_bytes;
use super::lru_index::LruIndex;
use super::payload_size::directive_payloads_bytes;
use super::{ClassifiedTokens, DirectivePayload, MacroDef};

/// Header-analysis cache key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HeaderReuseKey {
    /// Canonical header path.
    pub path: PathBuf,
    /// Header source hash.
    pub source_hash: [u8; 16],
    /// Live macro-definition hash at the include site.
    pub defines_hash: [u8; 16],
    /// Compiler-flag hash.
    pub flags_hash: [u8; 16],
    /// Target triple.
    pub target_triple: String,
}

/// Header reuse evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderReuseEvent {
    /// Header path.
    pub path: PathBuf,
    /// Target triple in the cache key.
    pub target_triple: String,
    /// Whether cache lookup hit.
    pub hit: bool,
    /// Whether this event stored a freshly computed entry.
    pub stored: bool,
    /// Whether GPU-derived header analysis was reused.
    pub gpu_analysis_reused: bool,
    /// Live defines hash used for invalidation.
    pub defines_hash: [u8; 16],
    /// Compiler flags hash used for invalidation.
    pub flags_hash: [u8; 16],
    /// Header source hash used for invalidation.
    pub source_hash: [u8; 16],
}

/// Cached GPU-derived header analysis.
#[derive(Debug, Clone)]
pub(super) struct HeaderReuseEntry {
    pub classified: Arc<ClassifiedTokens>,
    pub payloads: Arc<[DirectivePayload]>,
}

const HEADER_REUSE_CACHE_MAX_ENTRIES: usize = 8192;
const HEADER_REUSE_CACHE_MAX_BYTES: usize = 512 * 1024 * 1024;

#[cfg(test)]
pub(super) fn header_reuse_key(
    path: &Path,
    source: &[u8],
    defines_hash: [u8; 16],
) -> HeaderReuseKey {
    header_reuse_key_from_hash(path, hash_bytes(source), defines_hash)
}

pub(super) fn header_reuse_key_from_hash(
    path: &Path,
    source_hash: [u8; 16],
    defines_hash: [u8; 16],
) -> HeaderReuseKey {
    HeaderReuseKey {
        path: path.to_path_buf(),
        source_hash,
        defines_hash,
        flags_hash: header_flags_hash(),
        target_triple: header_target_triple().to_string(),
    }
}

pub(super) fn load_header_reuse(key: &HeaderReuseKey) -> Result<Option<HeaderReuseEntry>, String> {
    header_cache()
        .lock()
        .map_err(|_| "vyre-libs::gpu_pipeline: header-analysis reuse cache poisoned".to_string())
        .map(|mut cache| cache.lookup(key))
}

pub(super) fn store_header_reuse(
    key: HeaderReuseKey,
    entry: HeaderReuseEntry,
) -> Result<(), String> {
    let mut cache = header_cache().lock().map_err(|_| {
        "vyre-libs::gpu_pipeline: header-analysis reuse cache poisoned while inserting".to_string()
    })?;
    cache.insert(key, entry);
    Ok(())
}

pub(super) fn reuse_event(key: &HeaderReuseKey, hit: bool, stored: bool) -> HeaderReuseEvent {
    HeaderReuseEvent {
        path: key.path.clone(),
        target_triple: key.target_triple.clone(),
        hit,
        stored,
        gpu_analysis_reused: hit,
        defines_hash: key.defines_hash,
        flags_hash: key.flags_hash,
        source_hash: key.source_hash,
    }
}

struct HeaderReuseCache {
    entries: HashMap<HeaderReuseKey, HeaderReuseCacheEntry>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
    epoch: u64,
    lru: LruIndex<HeaderReuseKey>,
}

struct HeaderReuseCacheEntry {
    value: HeaderReuseEntry,
    bytes: usize,
    last_access: u64,
}

impl HeaderReuseCache {
    fn new() -> Self {
        Self {
            entries: HashMap::default(),
            bytes: 0,
            max_entries: HEADER_REUSE_CACHE_MAX_ENTRIES,
            max_bytes: HEADER_REUSE_CACHE_MAX_BYTES,
            epoch: 0,
            lru: LruIndex::with_capacity(HEADER_REUSE_CACHE_MAX_ENTRIES),
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

    fn lookup(&mut self, key: &HeaderReuseKey) -> Option<HeaderReuseEntry> {
        let next_epoch = self.next_epoch();
        let entry = self.entries.get_mut(key)?;
        entry.last_access = next_epoch;
        let value = entry.value.clone();
        self.lru.record(key.clone(), next_epoch);
        self.compact_lru_if_needed();
        Some(value)
    }

    fn insert(&mut self, key: HeaderReuseKey, value: HeaderReuseEntry) {
        let entry_bytes = header_reuse_entry_bytes(&value);
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
                "vyre-libs gpu preprocessor header reuse cache byte accounting overflowed during insert. Fix: lower header reuse cache limits or shard preprocessing sessions."
            )
        });
        self.entries.insert(
            key.clone(),
            HeaderReuseCacheEntry {
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
    fn contains_key(&self, key: &HeaderReuseKey) -> bool {
        self.entries.contains_key(key)
    }

    #[cfg(test)]
    fn lru_index_len(&self) -> usize {
        self.lru.len()
    }

    fn remove(&mut self, key: &HeaderReuseKey) -> Option<HeaderReuseCacheEntry> {
        let entry = self.entries.remove(key)?;
        self.bytes = self.bytes.checked_sub(entry.bytes).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor header reuse cache byte accounting underflowed during eviction. Fix: repair header reuse cache accounting before relying on memory limits."
            )
        });
        Some(entry)
    }

    fn next_epoch(&mut self) -> u64 {
        self.epoch = self.epoch.checked_add(1).unwrap_or_else(|| {
            panic!(
                "vyre-libs gpu preprocessor header reuse cache epoch overflowed. Fix: recreate process-local header reuse cache before continuing an unbounded include stream."
            )
        });
        self.epoch
    }

    fn pop_lru_key(&mut self) -> Option<HeaderReuseKey> {
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

fn header_reuse_entry_bytes(entry: &HeaderReuseEntry) -> usize {
    classified_tokens_bytes(&entry.classified)
        .checked_add(directive_payloads_bytes(&entry.payloads))
        .unwrap_or(usize::MAX)
}

fn header_cache() -> &'static Mutex<HeaderReuseCache> {
    static CACHE: OnceLock<Mutex<HeaderReuseCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HeaderReuseCache::new()))
}

fn header_flags_hash() -> [u8; 16] {
    static FLAGS_HASH: OnceLock<[u8; 16]> = OnceLock::new();
    *FLAGS_HASH.get_or_init(|| {
        let flags = std::env::var("VYRE_C_HEADER_CACHE_FLAGS").unwrap_or_default();
        hash_bytes(flags.as_bytes())
    })
}

fn header_target_triple() -> &'static str {
    static TARGET_TRIPLE: OnceLock<String> = OnceLock::new();
    TARGET_TRIPLE
        .get_or_init(|| {
            std::env::var("VYRE_TARGET_TRIPLE")
                .unwrap_or_else(|_| "x86_64-unknown-linux-gnu".to_string())
        })
        .as_str()
}

pub(super) fn hash_defines(macros: &[MacroDef]) -> [u8; 16] {
    let mut sorted = macros.iter().collect::<Vec<_>>();
    sorted.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.args.cmp(&b.args))
            .then_with(|| a.body.cmp(&b.body))
            .then_with(|| a.is_function_like.cmp(&b.is_function_like))
    });
    let mut hasher = blake3::Hasher::new();
    for mac in sorted {
        update_len_bytes(&mut hasher, &mac.name);
        update_len_bytes(&mut hasher, &mac.args);
        update_len_bytes(&mut hasher, &mac.body);
        hasher.update(&[u8::from(mac.is_function_like)]);
    }
    finish128(hasher)
}

fn update_len_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_bytes(bytes: &[u8]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    finish128(hasher)
}

fn finish128(hasher: blake3::Hasher) -> [u8; 16] {
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macro_def(name: &[u8], args: &[u8], body: &[u8], is_function_like: bool) -> MacroDef {
        MacroDef {
            name: name.to_vec(),
            args: args.to_vec(),
            body: body.to_vec(),
            is_function_like,
        }
    }

    #[test]
    fn defines_hash_is_order_independent_without_cloning_macro_bodies() {
        let left = vec![
            macro_def(b"B", b"x", b"((x)+1)", true),
            macro_def(b"A", b"", b"1", false),
        ];
        let right = vec![
            macro_def(b"A", b"", b"1", false),
            macro_def(b"B", b"x", b"((x)+1)", true),
        ];
        assert_eq!(hash_defines(&left), hash_defines(&right));
    }

    #[test]
    fn header_reuse_key_matches_prehashed_constructor() {
        let path = Path::new("/tmp/header-reuse-direct.h");
        let source = b"#define DIRECT 1\n";
        let defines_hash = [7; 16];

        assert_eq!(
            header_reuse_key(path, source, defines_hash),
            header_reuse_key_from_hash(path, hash_bytes(source), defines_hash)
        );
    }

    fn key(id: u8) -> HeaderReuseKey {
        HeaderReuseKey {
            path: PathBuf::from(format!("/tmp/header-reuse-{id}.h")),
            source_hash: [id; 16],
            defines_hash: [0; 16],
            flags_hash: [0; 16],
            target_triple: "test-target".to_string(),
        }
    }

    fn entry(id: u8, source_len: usize) -> HeaderReuseEntry {
        HeaderReuseEntry {
            classified: Arc::new(ClassifiedTokens {
                tok_types: vec![id as u32],
                tok_starts: vec![0],
                tok_lens: vec![source_len as u32],
                directive_kinds: vec![0],
                directive_count: 0,
                source: Arc::from(vec![id; source_len].into_boxed_slice()),
            }),
            payloads: Arc::from(vec![DirectivePayload::None].into_boxed_slice()),
        }
    }

    #[test]
    fn header_reuse_cache_rejects_entries_over_byte_budget() {
        let mut cache = HeaderReuseCache::with_limits(8, 16);
        cache.insert(key(1), entry(1, 64));
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.byte_len(), 0);
    }

    #[test]
    fn header_reuse_cache_evicts_lru_to_byte_budget() {
        let a = key(1);
        let b = key(2);
        let c = key(3);
        let a_entry = entry(1, 16);
        let b_entry = entry(2, 16);
        let c_entry = entry(3, 96);
        let budget = header_reuse_entry_bytes(&a_entry)
            .checked_add(header_reuse_entry_bytes(&c_entry))
            .expect("test cache budget must fit usize");
        let mut cache = HeaderReuseCache::with_limits(8, budget);
        cache.insert(a.clone(), a_entry);
        cache.insert(b.clone(), b_entry);
        assert!(cache.lookup(&a).is_some());
        cache.insert(c.clone(), c_entry);
        assert!(cache.contains_key(&a));
        assert!(!cache.contains_key(&b));
        assert!(cache.contains_key(&c));
        assert!(cache.byte_len() <= budget);
    }

    #[test]
    fn header_reuse_cache_lru_index_stays_capacity_scale() {
        let mut cache = HeaderReuseCache::with_limits(4, 1 << 20);

        for id in 0..96u8 {
            let key = key(id);
            cache.insert(key.clone(), entry(id, 8));
            assert!(cache.lookup(&key).is_some());
        }

        assert_eq!(cache.len(), 4);
        assert!(
            cache.lru_index_len() <= cache.len().saturating_mul(4).max(8),
            "Fix: header reuse cache LRU index must compact stale touches to cache-capacity scale"
        );
    }
}
