//! Durable load/save schema for the merkle index cache.
//!
//! The parent module owns the live sharded index. This module owns only the JSON
//! disk representation, spec-hash validation, cap-preserving merges, and atomic
//! persistence.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{tmp_hygiene::sweep_stale_tmp_files, CacheEntry, MerkleIndex, SCHEMA_VERSION};
use crate::hex_encode;
use crate::merkle_spec_hash::hex_to_array;

/// On-disk per-entry record (v2). The `mtime_ns` + `size` pair is the
/// fast-path key: a successful match short-circuits the BLAKE3 read entirely.
/// `hash` remains as a paranoid-mode verifier and as the authoritative content
/// fingerprint when mtime alone changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EntryV2 {
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
    /// `path -> entry`. Stored as hex strings so a human can diff cache files.
    entries: HashMap<String, EntryV2>,
}

impl MerkleIndex {
    /// Load the index from `path` without spec-hash gating. Returns an empty
    /// index when the file doesn't exist or cannot be trusted.
    pub(crate) fn load(path: &Path) -> Self {
        sweep_stale_tmp_files(path);
        Self::load_with_spec_inner(path, None)
    }

    /// Load the index, gated on a matching detector-spec hash. This prevents an
    /// added detector from leaving unchanged files skipped forever.
    pub fn load_with_spec(path: &Path, expected_spec_hash: &[u8; 32]) -> Self {
        sweep_stale_tmp_files(path);
        Self::load_with_spec_inner(path, Some(expected_spec_hash))
    }

    fn load_with_spec_inner(path: &Path, expected_spec_hash: Option<&[u8; 32]>) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Self::empty(),
            Err(error) => {
                tracing::warn!(
                    cache = %path.display(),
                    %error,
                    "merkle index file read failed; treating as cold start"
                );
                return Self::empty();
            }
        };
        let on_disk: OnDisk = match serde_json::from_slice(&bytes) {
            Ok(on_disk) => on_disk,
            Err(error) => {
                tracing::warn!(
                    cache = %path.display(),
                    %error,
                    "merkle index parse failed; treating as cold start"
                );
                return Self::empty();
            }
        };
        if on_disk.version != SCHEMA_VERSION {
            tracing::warn!(
                cache = %path.display(),
                version = on_disk.version,
                expected = SCHEMA_VERSION,
                "merkle index schema mismatch; treating as cold start"
            );
            return Self::empty();
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
                return Self::empty();
            }
        }

        let idx = Self::empty();
        for (path, entry) in decode_entries(on_disk.entries) {
            if !idx.try_insert(path, entry) {
                break;
            }
        }
        tracing::info!(
            cache = %path.display(),
            count = idx.len(),
            "merkle index loaded"
        );
        idx
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
    ) -> HashMap<PathBuf, CacheEntry> {
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
        merged: &mut HashMap<PathBuf, CacheEntry>,
    ) -> HashSet<PathBuf> {
        let mut in_memory_paths = HashSet::<PathBuf>::new();
        for shard in &self.shards {
            for (path, entry) in shard.read().iter() {
                merged.insert(path.clone(), *entry);
                in_memory_paths.insert(path.clone());
            }
        }
        in_memory_paths
    }

    fn enforce_persisted_cap(
        &self,
        merged: &mut HashMap<PathBuf, CacheEntry>,
        in_memory_paths: &HashSet<PathBuf>,
    ) {
        if self.max_entries == 0 || merged.len() <= self.max_entries {
            return;
        }

        let mut kept = HashMap::<PathBuf, CacheEntry>::with_capacity(self.max_entries);
        for path in in_memory_paths {
            if kept.len() >= self.max_entries {
                break;
            }
            if let Some(entry) = merged.get(path) {
                kept.insert(path.clone(), *entry);
            }
        }
        for (path, entry) in merged.iter() {
            if kept.len() >= self.max_entries {
                break;
            }
            kept.entry(path.clone()).or_insert(*entry);
        }
        *merged = kept;
    }
}

/// Default index location: `$XDG_CACHE_HOME/keyhog/merkle.idx` or
/// `~/.cache/keyhog/merkle.idx` on Linux, `~/Library/Caches/keyhog/...` on
/// macOS.
pub(crate) fn default_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("keyhog").join("merkle.idx"))
}

fn decode_entries(
    entries: HashMap<String, EntryV2>,
) -> impl Iterator<Item = (PathBuf, CacheEntry)> {
    entries.into_iter().filter_map(|(path, entry)| {
        hex_to_array(&entry.hash).map(|hash| {
            (
                PathBuf::from(path),
                CacheEntry {
                    mtime_ns: entry.mtime_ns,
                    size: entry.size,
                    hash,
                },
            )
        })
    })
}

fn encode_entries(entries: &HashMap<PathBuf, CacheEntry>) -> HashMap<String, EntryV2> {
    entries
        .iter()
        .map(|(path, entry)| {
            (
                path.display().to_string(),
                EntryV2 {
                    mtime_ns: entry.mtime_ns,
                    size: entry.size,
                    hash: hex_encode(&entry.hash),
                },
            )
        })
        .collect()
}

fn flatten_shards(index: &MerkleIndex) -> HashMap<PathBuf, CacheEntry> {
    let mut entries = HashMap::new();
    for shard in &index.shards {
        entries.extend(
            shard
                .read()
                .iter()
                .map(|(path, entry)| (path.clone(), *entry)),
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
