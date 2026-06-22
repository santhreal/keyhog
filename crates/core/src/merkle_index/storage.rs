//! Durable load/save schema for the merkle index cache.
//!
//! The parent module owns the live sharded index. This module owns only the JSON
//! disk representation, spec-hash validation, cap-preserving merges, and atomic
//! persistence.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    tmp_hygiene::sweep_stale_tmp_files, CacheEntry, CacheKey, MerkleIndex, MerkleLoadReport,
    MerkleLoadStatus, SCHEMA_VERSION,
};
use crate::hex_encode;
use crate::merkle_spec_hash::hex_to_array;

/// On-disk per-entry record (v4). The `mtime_ns` + `size` pair is the
/// fast-path key: a successful match short-circuits the BLAKE3 read entirely.
/// `hash` remains as a paranoid-mode verifier and as the authoritative content
/// fingerprint when mtime alone changed.
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

impl MerkleIndex {
    /// Load the index from `path` without spec-hash gating. Returns an empty
    /// index when the file doesn't exist or cannot be trusted.
    pub(crate) fn load(path: &Path) -> Self {
        Self::load_report(path).into_index()
    }

    /// Load the index from `path` and report whether it cold-started.
    pub(crate) fn load_report(path: &Path) -> MerkleLoadReport {
        sweep_stale_tmp_files(path);
        let (index, status) = Self::load_with_spec_inner(path, None);
        MerkleLoadReport { index, status }
    }

    /// Load the index, gated on a matching detector-spec hash. This prevents an
    /// added detector from leaving unchanged files skipped forever.
    pub(crate) fn load_with_spec(path: &Path, expected_spec_hash: &[u8; 32]) -> Self {
        Self::load_with_spec_report(path, expected_spec_hash).into_index()
    }

    /// Load the spec-gated index and report whether the cache was trusted.
    pub fn load_with_spec_report(path: &Path, expected_spec_hash: &[u8; 32]) -> MerkleLoadReport {
        sweep_stale_tmp_files(path);
        let (index, status) = Self::load_with_spec_inner(path, Some(expected_spec_hash));
        MerkleLoadReport { index, status }
    }

    fn load_with_spec_inner(
        path: &Path,
        expected_spec_hash: Option<&[u8; 32]>,
    ) -> (Self, MerkleLoadStatus) {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (
                    Self::empty(),
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
                    Self::empty(),
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
                    Self::empty(),
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
                Self::empty(),
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
                    Self::empty(),
                    MerkleLoadStatus::SpecChanged {
                        path: path.to_path_buf(),
                    },
                );
            }
        }

        let idx = Self::empty();
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
                    Self::empty(),
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
                hash,
            };
            if entry.mtime_ns >= racy_floor {
                racy_dropped += 1;
                continue;
            }
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
        persist_atomically(path, &serialized)
    }

    fn load_merge_base(
        &self,
        path: &Path,
        spec_hash: Option<&[u8; 32]>,
    ) -> HashMap<CacheKey, CacheEntry> {
        // Preserve existing disk entries only when they match the spec gate we
        // are about to write. Corrupt or mismatched disk state has already been
        // surfaced by load and must not block writing a fresh cache.
        let on_disk_now = match spec_hash {
            Some(hash) => Self::load_with_spec(path, hash),
            None => Self::load(path),
        };
        flatten_shards(&on_disk_now)
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

        let mut to_remove = Vec::<CacheKey>::new();
        for key in merged.keys() {
            if merged.len().saturating_sub(to_remove.len()) <= self.max_entries {
                break;
            }
            if !in_memory_paths.contains(key) {
                to_remove.push(key.clone());
            }
        }
        for key in to_remove {
            merged.remove(&key);
        }
        if merged.len() <= self.max_entries {
            return;
        }

        let mut to_remove = Vec::<CacheKey>::new();
        for key in merged.keys() {
            if merged.len().saturating_sub(to_remove.len()) <= self.max_entries {
                break;
            }
            to_remove.push(key.clone());
        }
        for key in to_remove {
            merged.remove(&key);
        }
    }
}

/// Default index location: `$XDG_CACHE_HOME/keyhog/merkle.idx` or
/// `~/.cache/keyhog/merkle.idx` on Linux, `~/Library/Caches/keyhog/...` on
/// macOS.
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("keyhog").join("merkle.idx"))
}

fn encode_entries(entries: &HashMap<CacheKey, CacheEntry>) -> Vec<EntryV4> {
    entries
        .iter()
        .map(|(key, entry)| EntryV4 {
            path: key.path.display().to_string(),
            chunk_offset: key.chunk_offset,
            mtime_ns: entry.mtime_ns,
            size: entry.size,
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
    // `Path::parent()` is `None` only for a root/empty path, where the CWD (".")
    // is the correct directory to create the temp file in.
    let parent = path.parent().unwrap_or_else(|| Path::new(".")); // LAW10: deterministic default, not a swallowed failure
    std::fs::create_dir_all(parent)?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut tmp, serialized)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|error| error.error)?;
    Ok(())
}
