//! Durable load/save schema for the merkle index cache.
//!
//! The parent module owns the live sharded index. This module owns only the JSON
//! disk representation, spec-hash validation, cap-preserving merges, and atomic
//! persistence.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    tmp_hygiene::{sweep_stale_tmp_files, MERKLE_TMP_PREFIX},
    CacheEntry, CacheFileFingerprint, CacheKey, MerkleIndex, MerkleLoadReport, MerkleLoadStatus,
    SCHEMA_VERSION,
};
use crate::hex_encode;
use crate::merkle_spec_hash::hex_to_array;
use crate::state_file::{self, MERKLE_INDEX_CACHE_FILE_BYTES};

/// On-disk per-entry record (v4). The `mtime_ns` + `size` pair is the fast-path
/// key: a successful match short-circuits the BLAKE3 read entirely. `hash`
/// remains as a paranoid-mode verifier and as the authoritative content
/// fingerprint when mtime alone changed. `last_seen_order` makes over-cap
/// eviction deterministic without changing the schema version for older v4
/// caches that do not carry it yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntryV4 {
    /// Source path. Stored inside the entry because v4 allows multiple rows for
    /// one path at different chunk offsets.
    path: String,
    /// Absolute byte offset of this chunk within `path`.
    #[serde(default)]
    chunk_offset: u64,
    /// `mtime` in nanoseconds since UNIX epoch. Stored as `u64` so we don't lose
    /// ext4/NTFS sub-second precision; older filesystems just round-trip their
    /// rounded value.
    mtime_ns: u64,
    /// File size in bytes from `fs::metadata`.
    size: u64,
    /// Monotonic recency marker. Older v4 caches default to `0` and are evicted
    /// before entries written by binaries that persist this field.
    #[serde(default)]
    last_seen_order: u64,
    /// BLAKE3 hex digest of the chunk content.
    hash: String,
}

/// Top-level on-disk schema.
#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    /// Schema version. Bumped on incompatible changes.
    version: u32,
    /// Hex BLAKE3 of the canonical detector-spec digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spec_hash: Option<String>,
    /// Wall-clock time (nanoseconds since the UNIX epoch) when this index was
    /// last written. Reference point for the racy-clean guard on load: an entry
    /// whose file `mtime_ns` is in the same clock-second as - or after - this
    /// value may have been modified after we recorded its hash, so it is dropped
    /// and re-checked rather than trusted. A `0` value (clock read failed at
    /// save time) floors every entry to racy, which fails safe: the next scan
    /// re-reads and re-hashes everything rather than trusting a stale entry.
    #[serde(default)]
    written_at_ns: u64,
    /// One persisted chunk row per `(path, chunk_offset)`.
    entries: Vec<EntryV4>,
}

/// Nanoseconds per second; used to floor a timestamp to its whole second for
/// the racy-clean comparison.
const NS_PER_SEC: u64 = 1_000_000_000;

/// Floor a UNIX-epoch nanosecond timestamp to its whole second. The racy-clean
/// guard compares a file's `mtime_ns` against the FLOORED index-write time so
/// coarse-granularity filesystems are handled correctly: a file written in the
/// same wall-second as the index has a truncated `mtime_ns` numerically *below*
/// the fine-grained `written_at_ns`, yet must still be treated as racy.
fn second_floor(ns: u64) -> u64 {
    (ns / NS_PER_SEC) * NS_PER_SEC
}

/// Current wall-clock time in nanoseconds since the UNIX epoch. A clock set
/// before the epoch (or an arithmetic overflow past ~year 2554) collapses to a
/// value that marks every later load racy, which fails safe: the next scan
/// re-reads and re-hashes everything rather than trusting a stale entry.
fn now_unix_ns() -> u64 {
    let Ok(duration) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
        return 0;
    };
    let Ok(ns) = u64::try_from(duration.as_nanos()) else {
        return 0;
    };
    ns
}

fn cache_file_fingerprint(path: &Path) -> std::io::Result<Option<CacheFileFingerprint>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(CacheFileFingerprint {
        modified: metadata.modified()?,
        len: metadata.len(),
    }))
}

impl MerkleIndex {
    /// Load the index from `path` without spec-hash gating. Returns an empty
    /// index when the file doesn't exist or cannot be trusted.
    pub(crate) fn load(path: &Path) -> Self {
        Self::load_report(path).into_index()
    }

    pub(crate) fn load_with_max_entries(path: &Path, max_entries: usize) -> Self {
        Self::load_report_with_max_entries(path, max_entries).into_index()
    }

    /// Load the index from `path` and report whether it cold-started.
    pub(crate) fn load_report(path: &Path) -> MerkleLoadReport {
        Self::load_report_with_max_entries(path, super::MERKLE_DEFAULT_MAX_ENTRIES)
    }

    pub(crate) fn load_report_with_max_entries(
        path: &Path,
        max_entries: usize,
    ) -> MerkleLoadReport {
        sweep_stale_tmp_files(path);
        let (index, status) = Self::load_with_spec_inner(path, None, max_entries);
        MerkleLoadReport { index, status }
    }

    /// Load the index, gated on a matching detector-spec hash. This prevents an
    /// added detector from leaving unchanged files skipped forever.
    pub(crate) fn load_with_spec(path: &Path, expected_spec_hash: &[u8; 32]) -> Self {
        Self::load_with_spec_report(path, expected_spec_hash).into_index()
    }

    pub(crate) fn load_with_spec_and_max_entries(
        path: &Path,
        expected_spec_hash: &[u8; 32],
        max_entries: usize,
    ) -> Self {
        Self::load_with_spec_report_and_max_entries(path, expected_spec_hash, max_entries)
            .into_index()
    }

    /// Load the spec-gated index and report whether the cache was trusted.
    pub fn load_with_spec_report(path: &Path, expected_spec_hash: &[u8; 32]) -> MerkleLoadReport {
        Self::load_with_spec_report_and_max_entries(
            path,
            expected_spec_hash,
            super::MERKLE_DEFAULT_MAX_ENTRIES,
        )
    }

    fn load_with_spec_report_and_max_entries(
        path: &Path,
        expected_spec_hash: &[u8; 32],
        max_entries: usize,
    ) -> MerkleLoadReport {
        sweep_stale_tmp_files(path);
        let (index, status) =
            Self::load_with_spec_inner(path, Some(expected_spec_hash), max_entries);
        MerkleLoadReport { index, status }
    }

    fn load_with_spec_inner(
        path: &Path,
        expected_spec_hash: Option<&[u8; 32]>,
        max_entries: usize,
    ) -> (Self, MerkleLoadStatus) {
        let bytes =
            match state_file::read_capped(path, MERKLE_INDEX_CACHE_FILE_BYTES, "merkle index") {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return (
                        Self::with_max_entries(max_entries),
                        MerkleLoadStatus::Missing {
                            path: path.to_path_buf(),
                        },
                    );
                }
                Err(error) => {
                    let error = error.to_string();
                    tracing::warn!(
                        cache = %path.display(),
                        %error,
                        "merkle index file read failed; treating as cold start"
                    );
                    return (
                        Self::with_max_entries(max_entries),
                        MerkleLoadStatus::ReadFailed {
                            path: path.to_path_buf(),
                            error,
                        },
                    );
                }
            };
        let on_disk: OnDisk = match serde_json::from_slice(&bytes) {
            Ok(on_disk) => on_disk,
            Err(error) => {
                let error = error.to_string();
                tracing::warn!(
                    cache = %path.display(),
                    %error,
                    "merkle index parse failed; treating as cold start"
                );
                return (
                    Self::with_max_entries(max_entries),
                    MerkleLoadStatus::ParseFailed {
                        path: path.to_path_buf(),
                        error,
                    },
                );
            }
        };
        if on_disk.version != SCHEMA_VERSION {
            tracing::warn!(
                cache = %path.display(),
                version = on_disk.version,
                expected = SCHEMA_VERSION,
                "merkle index schema mismatch; treating as cold start"
            );
            return (
                Self::with_max_entries(max_entries),
                MerkleLoadStatus::SchemaMismatch {
                    path: path.to_path_buf(),
                    version: on_disk.version,
                    expected: SCHEMA_VERSION,
                },
            );
        }
        if let Some(expected) = expected_spec_hash {
            let stored_match = on_disk
                .spec_hash
                .as_deref()
                .and_then(hex_to_array)
                .is_some_and(|stored| &stored == expected);
            if !stored_match {
                tracing::info!(
                    cache = %path.display(),
                    "detector spec changed since last scan; cache invalidated"
                );
                return (
                    Self::with_max_entries(max_entries),
                    MerkleLoadStatus::SpecChanged {
                        path: path.to_path_buf(),
                    },
                );
            }
        }

        let idx = Self::with_max_entries(max_entries);
        // Racy-clean guard (git's "racy index" problem): an entry whose file
        // mtime falls in the same clock-second as - or after - the moment we
        // last wrote this index cannot be trusted by (mtime, size) alone. A
        // size-preserving edit in that window leaves the stat unchanged on
        // coarse-granularity filesystems, so skipping the file would miss a
        // freshly injected secret forever. Drop those entries so the next scan
        // re-reads and content-hashes them. `written_at_ns == 0` (clock read
        // failed at save time) floors to 0, marking every entry racy => full,
        // correct cold re-scan that self-heals on the next save.
        let racy_floor = second_floor(on_disk.written_at_ns);
        let mut racy_dropped = 0usize;
        for entry in on_disk.entries {
            let Some(hash) = hex_to_array(&entry.hash) else {
                let invalid_hash = entry.hash;
                tracing::warn!(
                    cache = %path.display(),
                    entry_path = %entry.path,
                    hash = %invalid_hash,
                    "merkle index entry hash is invalid; treating as cold start"
                );
                return (
                    Self::with_max_entries(max_entries),
                    MerkleLoadStatus::InvalidEntryHash {
                        path: path.to_path_buf(),
                        entry_path: entry.path,
                        hash: invalid_hash,
                    },
                );
            };
            let key = CacheKey::chunk(PathBuf::from(entry.path), entry.chunk_offset);
            let entry = CacheEntry {
                mtime_ns: entry.mtime_ns,
                size: entry.size,
                last_seen_order: entry.last_seen_order,
                hash,
            };
            if entry.mtime_ns >= racy_floor {
                racy_dropped += 1;
                continue;
            }
            idx.observe_loaded_access_order(entry.last_seen_order);
            if !idx.try_insert(key, entry) {
                break;
            }
        }
        if racy_dropped > 0 {
            tracing::info!(
                cache = %path.display(),
                racy_dropped,
                "merkle index: entries modified in the same second as (or after) \
                 the last index write were dropped (racy-clean guard) and will be \
                 re-read + re-scanned this run"
            );
        }
        tracing::info!(
            cache = %path.display(),
            count = idx.len(),
            "merkle index loaded"
        );
        idx.remember_cache_file_fingerprint(path);
        let entries = idx.len();
        (
            idx,
            MerkleLoadStatus::Loaded {
                path: path.to_path_buf(),
                entries,
            },
        )
    }

    /// Persist the index without binding it to a detector-spec hash.
    pub(crate) fn save(&self, path: &Path) -> std::io::Result<()> {
        self.save_inner(path, None)
    }

    /// Persist the index with a detector-spec hash so future loads can detect
    /// detector drift and invalidate cleanly.
    pub fn save_with_spec(&self, path: &Path, spec_hash: &[u8; 32]) -> std::io::Result<()> {
        self.save_inner(path, Some(spec_hash))
    }

    fn save_inner(&self, path: &Path, spec_hash: Option<&[u8; 32]>) -> std::io::Result<()> {
        let _save_lock = state_file::StateFileWriteLock::acquire(path)?;
        let mut merged = self.load_merge_base(path, spec_hash);
        let in_memory_paths = self.overlay_in_memory_entries(&mut merged);
        self.enforce_persisted_cap(&mut merged, &in_memory_paths);

        let on_disk = OnDisk {
            version: SCHEMA_VERSION,
            spec_hash: spec_hash.map(hex_encode),
            written_at_ns: now_unix_ns(),
            entries: encode_entries(&merged),
        };
        let serialized = serde_json::to_vec_pretty(&on_disk)
            .map_err(|error| std::io::Error::other(format!("merkle index encode: {error}")))?;
        persist_atomically(path, &serialized)?;
        self.remember_cache_file_fingerprint(path);
        Ok(())
    }

    fn load_merge_base(
        &self,
        path: &Path,
        spec_hash: Option<&[u8; 32]>,
    ) -> HashMap<CacheKey, CacheEntry> {
        if !self.cache_file_changed_since_load_or_save(path) {
            return HashMap::new();
        }
        // Preserve existing disk entries only when they match the spec gate we
        // are about to write. Corrupt or mismatched disk state has already been
        // surfaced by load and must not block writing a fresh cache.
        let on_disk_now = match spec_hash {
            Some(hash) => Self::load_with_spec_and_max_entries(path, hash, self.max_entries),
            None => Self::load_with_max_entries(path, self.max_entries),
        };
        flatten_shards(&on_disk_now)
    }

    fn cache_file_changed_since_load_or_save(&self, path: &Path) -> bool {
        let current = match cache_file_fingerprint(path) {
            Ok(fingerprint) => fingerprint,
            Err(_) => return true, // LAW10: fail-closed fingerprint failure; dirty=true forces reload/rewrite instead of trusting stale cache state.
        };
        current != *self.cache_file_fingerprint.read()
    }

    fn remember_cache_file_fingerprint(&self, path: &Path) {
        if let Ok(fingerprint) = cache_file_fingerprint(path) {
            // LAW10: fail-closed — a failed post-write fingerprint leaves the cache untrusted; the loader rejects a missing fingerprint instead of trusting stale entries.
            *self.cache_file_fingerprint.write() = fingerprint;
        }
    }

    fn overlay_in_memory_entries(
        &self,
        merged: &mut HashMap<CacheKey, CacheEntry>,
    ) -> HashSet<CacheKey> {
        let mut in_memory_paths = HashSet::<CacheKey>::new();
        for shard in &self.shards {
            for (key, entry) in shard.read().iter() {
                merged.insert(key.clone(), *entry);
                in_memory_paths.insert(key.clone());
            }
        }
        in_memory_paths
    }

    fn enforce_persisted_cap(
        &self,
        merged: &mut HashMap<CacheKey, CacheEntry>,
        in_memory_paths: &HashSet<CacheKey>,
    ) {
        if self.max_entries == 0 || merged.len() <= self.max_entries {
            return;
        }

        let over_cap = merged.len().saturating_sub(self.max_entries);
        for key in oldest_eviction_keys(merged, Some(in_memory_paths), over_cap) {
            merged.remove(&key);
        }
        if merged.len() <= self.max_entries {
            return;
        }

        let over_cap = merged.len().saturating_sub(self.max_entries);
        for key in oldest_eviction_keys(merged, None, over_cap) {
            merged.remove(&key);
        }
    }
}

fn oldest_eviction_keys(
    merged: &HashMap<CacheKey, CacheEntry>,
    protected: Option<&HashSet<CacheKey>>,
    remove_count: usize,
) -> Vec<CacheKey> {
    let mut candidates = merged
        .iter()
        .filter(|(key, _)| match protected {
            Some(protected) => !protected.contains(key),
            None => true,
        })
        .collect::<Vec<_>>();
    // Eviction needs only the `remove_count` OLDEST entries, not a fully ordered
    // set. Fully sorting is O(N log N) over the whole cache (up to millions of
    // entries) to keep a handful; `select_nth_unstable_by` partitions the oldest
    // `take` into the prefix in O(N), and only that small prefix is then sorted
    // for a deterministic eviction order.
    let cmp = |a: &(&CacheKey, &CacheEntry), b: &(&CacheKey, &CacheEntry)| {
        a.1.last_seen_order
            .cmp(&b.1.last_seen_order)
            .then_with(|| a.0.path.cmp(&b.0.path))
            .then_with(|| a.0.chunk_offset.cmp(&b.0.chunk_offset))
    };
    let take = remove_count.min(candidates.len());
    if take == 0 {
        return Vec::new();
    }
    if take < candidates.len() {
        candidates.select_nth_unstable_by(take - 1, cmp);
        candidates.truncate(take);
    }
    candidates.sort_by(cmp);
    candidates.into_iter().map(|(key, _)| key.clone()).collect()
}

/// Default Merkle index location: `$XDG_CACHE_HOME/keyhog/merkle.idx` or
/// `~/.cache/keyhog/merkle.idx` on Linux, `~/Library/Caches/keyhog/...` on
/// macOS.
pub fn merkle_default_cache_path() -> Option<PathBuf> {
    crate::keyhog_cache_root().map(|dir| dir.join("merkle.idx"))
}

pub use merkle_default_cache_path as default_cache_path;

fn encode_entries(entries: &HashMap<CacheKey, CacheEntry>) -> Vec<EntryV4> {
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by(|(left_key, _), (right_key, _)| {
        left_key
            .path
            .cmp(&right_key.path)
            .then_with(|| left_key.chunk_offset.cmp(&right_key.chunk_offset))
    });
    ordered
        .into_iter()
        .map(|(key, entry)| EntryV4 {
            path: key.path.display().to_string(),
            chunk_offset: key.chunk_offset,
            mtime_ns: entry.mtime_ns,
            size: entry.size,
            last_seen_order: entry.last_seen_order,
            hash: hex_encode(&entry.hash),
        })
        .collect()
}

fn flatten_shards(index: &MerkleIndex) -> HashMap<CacheKey, CacheEntry> {
    let mut entries = HashMap::new();
    for shard in &index.shards {
        entries.extend(
            shard
                .read()
                .iter()
                .map(|(key, entry)| (key.clone(), *entry)),
        );
    }
    entries
}

fn persist_atomically(path: &Path, serialized: &[u8]) -> std::io::Result<()> {
    state_file::write_atomically(path, MERKLE_TMP_PREFIX, serialized)
}
