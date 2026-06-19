//! Incremental scan support via a persisted file-content index.
//!
//! ## What it does
//!
//! On a fresh scan we compute, for every input chunk, a metadata tuple
//! `(mtime_ns, size, BLAKE3(content))` and store it under the file's
//! canonical path. On the next run, files whose `(mtime, size)` match
//! the stored values can be skipped *without re-reading the bytes* -
//! they almost certainly haven't changed (rsync-style trust). When
//! `(mtime, size)` differ but BLAKE3 matches we record the new mtime
//! and still skip - same content, different stat (touched, copied).
//!
//! Tier-B moat innovation #3 from docs/EXECUTION_PLAN.md: "10–100×
//! speedup on CI re-runs" by skipping the 99% of files that didn't change.
//!
//! ## Schema versions
//!
//! - **v1 (legacy)** - `path → BLAKE3 hex` only. Loadable but lacks the
//!   metadata short-circuit; treated as cold-start to avoid mixing schemas.
//! - **v2 (legacy)** - `path → (mtime_ns, size, BLAKE3 hex)` plus a
//!   top-level `spec_hash` derived from the loaded detector set. A
//!   spec-hash mismatch invalidates the entire cache; this is the
//!   correctness fix for "added a detector but unchanged files were
//!   silently skipped, missing the new detection forever." Superseded by
//!   v3 and treated as cold-start (it lacks the racy-clean timestamp).
//! - **v3 (current)** - v2 plus a top-level `written_at_ns` (wall-clock
//!   nanoseconds when the index was last written). On load, any entry
//!   whose file `mtime_ns` falls in the same clock-second as - or after -
//!   `written_at_ns` is dropped (git's "racy index" guard): a
//!   size-preserving edit made in that window leaves `(mtime, size)`
//!   unchanged on coarse-granularity filesystems (FAT/HFS+/some NFS expose
//!   whole-second mtimes), so trusting the stored hash would skip a
//!   freshly injected secret forever. Dropped entries are simply re-read
//!   and re-hashed on the next scan - slower for those few files, never
//!   unsound.
//!
//! ## Serialization
//!
//! JSON, on purpose. The dataset is one row per scanned file (≤ ~1M for
//! any sane repo) and JSON keeps the on-disk format trivial to debug,
//! diff, and version-control if a team wants to.
//!
//! ## Threat model
//!
//! Cached entries do NOT contain credentials. Storing a `(mtime, size,
//! content_hash)` tuple per scanned path leaks that the path *exists*
//! and what its content fingerprint is, which is why `--lockdown`
//! refuses to load or write the cache at all.

use std::collections::{hash_map::DefaultHasher, HashMap};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use parking_lot::RwLock;

// Disk persistence and stale-tmp hygiene are separate filesystem responsibilities;
// the root module owns only the live index and calls those owners through methods.
mod storage;
mod tmp_hygiene;

pub(crate) use storage::default_cache_path;

const SCHEMA_VERSION: u32 = 3;

/// Shard count: spreads concurrent `record` / `unchanged` calls across
/// independent locks so tiny-file storms don't serialize all rayon workers.
const MERKLE_SHARDS: usize = 64;

/// Default upper bound on the number of in-memory cache entries.
///
/// Resident cost per entry is roughly `48 bytes` for the [`CacheEntry`]
/// (`mtime_ns: u64` + `size: u64` + `hash: [u8; 32]`, with padding) plus
/// the heap-allocated [`PathBuf`] key (one allocation, length of the
/// canonical path). On a typical repo a path averages ~80-120 bytes, so
/// budget ~150 bytes/entry end-to-end. At the default cap of 8M entries
/// that bounds the index at roughly 1.2 GB resident - large, but bounded,
/// and survivable on the fleet's 32-128 GB boxes. A giant monorepo can
/// raise or lower this via [`MerkleIndex::with_max_entries`] (Tier-A
/// configurability: compiled default, overridable by the caller).
///
/// When the cap is hit we WARN and stop *adding new paths*; updates to
/// paths already in the index are always allowed so an over-cap scan
/// never corrupts an existing entry. An uncached file is simply re-read
/// and re-scanned next run - slower, never unsound. This preserves the
/// module's core guarantee (a file that ever produced a finding is
/// `forget`-ten, never cached) regardless of the cap.
const MERKLE_DEFAULT_MAX_ENTRIES: usize = 8_000_000;

fn shard_index(path: &Path) -> usize {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    (h.finish() as usize) % MERKLE_SHARDS
}

/// In-memory per-entry record. Mirrors [`EntryV2`] but holds the hash as
/// a fixed-size array - saves the per-lookup hex-decode cost on the
/// `unchanged` hot path.
#[derive(Debug, Clone, Copy)]
struct CacheEntry {
    mtime_ns: u64,
    size: u64,
    hash: [u8; 32],
}

/// In-memory file-hash index loaded from / saved to a JSON cache file.
///
/// Concurrency model: the orchestrator holds an `Arc<MerkleIndex>` and
/// records new entries as chunks arrive from rayon-parallel sources.
/// Paths are sharded across [`MERKLE_SHARDS`] mutex-protected maps so
/// concurrent updates rarely contend.
#[derive(Debug)]
pub struct MerkleIndex {
    shards: Vec<RwLock<HashMap<PathBuf, CacheEntry>>>,
    /// Upper bound on the number of retained entries across all shards.
    /// Defaults to [`MERKLE_DEFAULT_MAX_ENTRIES`]. Once reached, only
    /// updates to existing paths are accepted; new paths are dropped
    /// (with a one-shot WARN) so a giant monorepo can't silently grow
    /// the index without bound.
    max_entries: usize,
    /// Set once the cap is first hit so we WARN at most once per index
    /// rather than once per dropped entry (which would be a log storm
    /// on a multi-million-file overflow).
    cap_warned: std::sync::atomic::AtomicBool,
    /// Approximate live entry count, maintained on the insert hot path so
    /// the cap check is O(1) instead of summing all 64 shard lengths per
    /// insert (that scan would dominate a multi-million-file scan). It is
    /// incremented only on a NEW-path insert and never decremented (the
    /// `forget` path is for found-secret invalidation, not bulk eviction),
    /// so it is a monotonic upper bound on live entries - exactly the
    /// conservative side for a "stop growing" budget. Exact counts use
    /// [`Self::len`].
    approx_count: std::sync::atomic::AtomicUsize,
}

impl MerkleIndex {
    /// Construct a fresh, empty [`MerkleIndex`] with no cached entries and
    /// the default entry cap ([`MERKLE_DEFAULT_MAX_ENTRIES`]).
    fn empty() -> Self {
        Self::with_max_entries(MERKLE_DEFAULT_MAX_ENTRIES)
    }

    /// Construct a fresh, empty [`MerkleIndex`] with an explicit entry cap.
    /// A cap of `0` is treated as "unbounded" for callers that genuinely
    /// want the old behavior, but the documented resident cost still
    /// applies (~150 bytes/entry).
    pub(crate) fn with_max_entries(max_entries: usize) -> Self {
        Self {
            shards: (0..MERKLE_SHARDS)
                .map(|_| RwLock::new(HashMap::new()))
                .collect(),
            max_entries,
            cap_warned: std::sync::atomic::AtomicBool::new(false),
            approx_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The configured maximum number of retained entries (`0` = unbounded).
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Hash the given content with BLAKE3 (32-byte output).
    pub(crate) fn hash_content(content: &[u8]) -> [u8; 32] {
        *blake3::hash(content).as_bytes()
    }

    /// Record one observed chunk and return `true` when it matched the
    /// previously indexed content hash. This is the production incremental
    /// scan contract: callers provide the path, stat metadata, and bytes they
    /// already read; the index owns hashing, skip classification, and update.
    pub fn record_chunk_and_check_unchanged(
        &self,
        path: PathBuf,
        mtime_ns: u64,
        size: u64,
        content: &[u8],
    ) -> bool {
        let content_hash = Self::hash_content(content);
        let unchanged = self.unchanged(&path, &content_hash);
        self.record_with_metadata(path, mtime_ns, size, content_hash);
        unchanged
    }

    /// Returns `true` when `path` was previously indexed with the SAME
    /// content hash. Kept for callers that already have the hash in hand
    /// (e.g. the orchestrator's chunk-level skip path).
    pub(crate) fn unchanged(&self, path: &Path, content_hash: &[u8; 32]) -> bool {
        let i = shard_index(path);
        self.shards[i]
            .read()
            .get(path)
            .is_some_and(|prev| &prev.hash == content_hash)
    }

    /// Returns `true` when `(path, mtime_ns, size)` exactly matches a
    /// stored entry. This is the **fast-path skip** - it avoids reading
    /// the file at all, which is the dominant cost on cold-cache disk.
    /// A `false` return means "either we've never seen this path, or
    /// metadata differs - caller must read + hash to decide."
    pub fn metadata_unchanged(&self, path: &Path, mtime_ns: u64, size: u64) -> bool {
        let i = shard_index(path);
        self.shards[i]
            .read()
            .get(path)
            .is_some_and(|prev| prev.mtime_ns == mtime_ns && prev.size == size)
    }

    /// Returns the stored `(mtime_ns, size, content_hash)` for `path`,
    /// or `None` if the index hasn't seen it. Used by paranoid-mode
    /// verifiers that want to confirm content didn't change even when
    /// metadata happens to match.
    pub(crate) fn lookup(&self, path: &Path) -> Option<(u64, u64, [u8; 32])> {
        let i = shard_index(path);
        self.shards[i]
            .read()
            .get(path)
            .map(|e| (e.mtime_ns, e.size, e.hash))
    }

    /// Record a file's content hash. Back-compat shim that drops to a
    /// zero-metadata entry - calls into [`Self::record_with_metadata`]
    /// with `mtime_ns = 0` and `size = 0` so existing callers keep
    /// working but won't benefit from the metadata fast-path.
    pub(crate) fn record(&self, path: PathBuf, content_hash: [u8; 32]) {
        self.record_with_metadata(path, 0, 0, content_hash);
    }

    /// Record a file's metadata + content hash. Overwrites any prior
    /// entry at the same path. The path-shard mutex is held for the
    /// duration of the insert only; concurrent recordings against
    /// different shards never contend.
    pub(crate) fn record_with_metadata(
        &self,
        path: PathBuf,
        mtime_ns: u64,
        size: u64,
        content_hash: [u8; 32],
    ) {
        self.try_insert(
            path,
            CacheEntry {
                mtime_ns,
                size,
                hash: content_hash,
            },
        );
    }

    /// Insert or update one entry, honoring [`Self::max_entries`].
    ///
    /// Returns `true` if the entry is now present (inserted or updated),
    /// `false` if it was a NEW path dropped because the cap is reached.
    /// Updates to an already-present path always succeed (they don't grow
    /// the working set) so an over-cap scan never corrupts existing state.
    /// The first drop emits a single WARN; subsequent drops are silent to
    /// avoid a log storm on a multi-million-file overflow.
    fn try_insert(&self, path: PathBuf, entry: CacheEntry) -> bool {
        let i = shard_index(&path);
        {
            // Fast path: updating a path we already track is a
            // replacement, not growth - always allowed, no cap check.
            // Scope the write guard so it is released before we read
            // sibling shards for the cap check below (parking_lot
            // RwLock is non-reentrant; re-locking shard `i` would
            // deadlock).
            let mut shard = self.shards[i].write();
            if shard.contains_key(&path) {
                shard.insert(path, entry);
                return true;
            }
        }
        // `max_entries == 0` means unbounded (opt-in legacy behavior).
        // The cap is a soft budget checked against `approx_count` (O(1),
        // no shard scan). Concurrent new-path inserts across shards can
        // overshoot by at most the number of in-flight `record` calls -
        // bounded and harmless (a few entries over budget, never
        // unbounded growth).
        use std::sync::atomic::Ordering;
        if self.max_entries != 0 && self.approx_count.load(Ordering::Relaxed) >= self.max_entries {
            if !self.cap_warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    cap = self.max_entries,
                    "merkle index entry cap reached; new paths will not be \
                     cached this run (they are re-scanned next run). Raise \
                     the cap for very large trees if the rescan cost matters."
                );
            }
            return false;
        }
        // Re-acquire the shard write lock for the actual insert. A racing
        // writer may have inserted this same new path in the gap; only
        // bump the approximate count when WE created a new key, so the
        // counter doesn't drift above true growth on update races.
        let is_new = self.shards[i].write().insert(path, entry).is_none();
        if is_new {
            self.approx_count.fetch_add(1, Ordering::Relaxed);
        }
        true
    }

    /// Remove `path` from the index so the next scan treats it as new and
    /// re-reads + re-scans it.
    ///
    /// This is how incremental mode keeps its core safety guarantee: a file
    /// that produced ANY finding is never cached, so a secret in an otherwise
    /// unchanged file still surfaces on every later run instead of being
    /// silently skipped (the failure this module's own header warns about).
    /// Clean files - the 99% - stay cached, so the 10-100x speedup is
    /// unaffected, and because we store the ABSENCE of an entry rather than the
    /// finding, no secret value ever touches the on-disk index.
    pub fn forget(&self, path: &Path) {
        let i = shard_index(path);
        self.shards[i].write().remove(path);
    }

    /// Number of indexed entries.
    pub(crate) fn len(&self) -> usize {
        self.shards.iter().map(|s| s.read().len()).sum()
    }

    /// Returns true if no cached entries are present across any shard.
    pub(crate) fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.read().is_empty())
    }
}

impl Default for MerkleIndex {
    fn default() -> Self {
        Self::empty()
    }
}
