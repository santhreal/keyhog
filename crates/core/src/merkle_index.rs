//! Incremental scan support via a persisted file-content index.
//!
//! On a fresh scan we compute the BLAKE3 hash of every input chunk and store
//! the `path → hash` mapping. On the next run, files whose hash matches the
//! stored value can be skipped — they cannot have leaked any new secret.
//!
//! Tier-B moat innovation #3 from audits/legendary-2026-04-26: "10-100×
//! speedup on CI re-runs" by skipping the 99% of files that didn't change.
//!
//! The index is a flat `HashMap<PathBuf, [u8; 32]>` serialized as JSON for
//! human-inspectability. We deliberately don't use a sqlite/sled-style
//! database — the dataset is one row per scanned file (≤ ~1M for any sane
//! repo) and JSON keeps the on-disk format trivial to debug, diff, and
//! version-control if a team wants to.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// On-disk format. The version field gates breaking schema changes; any
/// future `record` that needs new fields must bump this and add a migrator.
#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    /// Schema version. Bumped on incompatible changes.
    version: u32,
    /// `path → hex BLAKE3 hash`. Stored as hex strings (not raw bytes) so a
    /// human can `git diff` the file and see which entries changed.
    entries: HashMap<String, String>,
}

const SCHEMA_VERSION: u32 = 1;

/// In-memory file-hash index loaded from / saved to a JSON cache file.
///
/// Concurrency model: the orchestrator holds an `Arc<MerkleIndex>` and
/// records new entries as chunks arrive from rayon-parallel sources. Both
/// `lookup` and `record` are O(1) hashmap ops behind a `parking_lot::Mutex`
/// shard. We don't use `DashMap` here because the contention surface is low
/// (one record per file) and the simpler primitive is easier to reason
/// about for a persisted on-disk artifact.
#[derive(Debug)]
pub struct MerkleIndex {
    inner: Mutex<HashMap<PathBuf, [u8; 32]>>,
}

impl MerkleIndex {
    pub fn empty() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Load the index from `path`. Returns an empty index when the file
    /// doesn't exist (first run) or fails to parse (treat as cold start —
    /// safer than poisoning the cache from a corrupted artifact).
    pub fn load(path: &Path) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return Self::empty(),
        };
        let on_disk: OnDisk = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    cache = %path.display(),
                    error = %e,
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
        let entries: HashMap<PathBuf, [u8; 32]> = on_disk
            .entries
            .into_iter()
            .filter_map(|(p, h)| hex_to_array(&h).map(|a| (PathBuf::from(p), a)))
            .collect();
        tracing::info!(
            cache = %path.display(),
            count = entries.len(),
            "merkle index loaded"
        );
        Self {
            inner: Mutex::new(entries),
        }
    }

    /// Persist the index to `path`, atomically (write to a tmp file in the
    /// same dir, then rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let entries: HashMap<String, String> = self
            .inner
            .lock()
            .iter()
            .map(|(p, h)| (p.display().to_string(), hex_encode(h)))
            .collect();
        let on_disk = OnDisk {
            version: SCHEMA_VERSION,
            entries,
        };
        let serialized = serde_json::to_vec_pretty(&on_disk)
            .map_err(|e| std::io::Error::other(format!("merkle index encode: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, &serialized)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Hash the given content with BLAKE3 (32-byte output).
    pub fn hash_content(content: &[u8]) -> [u8; 32] {
        *blake3::hash(content).as_bytes()
    }

    /// Returns `true` when `path` was previously indexed with the SAME
    /// content hash and the orchestrator should skip rescanning it. The
    /// intention: callers compute the hash of the in-memory chunk and ask
    /// "have I seen this exact byte sequence at this exact path before?"
    pub fn unchanged(&self, path: &Path, content_hash: &[u8; 32]) -> bool {
        self.inner
            .lock()
            .get(path)
            .is_some_and(|prev| prev == content_hash)
    }

    /// Record a file's hash. Overwrites a previous entry at the same path.
    pub fn record(&self, path: PathBuf, content_hash: [u8; 32]) {
        self.inner.lock().insert(path, content_hash);
    }

    /// Number of indexed entries.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl Default for MerkleIndex {
    fn default() -> Self {
        Self::empty()
    }
}

/// Default index location: `$XDG_CACHE_HOME/keyhog/merkle.idx` or
/// `~/.cache/keyhog/merkle.idx` on Linux, `~/Library/Caches/keyhog/...`
/// on macOS.
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("keyhog").join("merkle.idx"))
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_unchanged_roundtrip() {
        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/example.env");
        let h = MerkleIndex::hash_content(b"DB_PASS=secret123");
        idx.record(p.clone(), h);
        assert!(idx.unchanged(&p, &h));

        let h2 = MerkleIndex::hash_content(b"DB_PASS=changed");
        assert!(!idx.unchanged(&p, &h2));
    }

    #[test]
    fn unknown_path_is_changed() {
        let idx = MerkleIndex::empty();
        let h = MerkleIndex::hash_content(b"x");
        assert!(!idx.unchanged(&PathBuf::from("/never/seen"), &h));
    }

    #[test]
    fn save_and_load_preserves_entries() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");

        let idx = MerkleIndex::empty();
        let p = PathBuf::from("/tmp/secrets.env");
        let h = MerkleIndex::hash_content(b"hello world");
        idx.record(p.clone(), h);
        idx.save(&cache_path).expect("save");

        let loaded = MerkleIndex::load(&cache_path);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.unchanged(&p, &h));
    }

    #[test]
    fn corrupted_cache_treated_as_cold_start() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        std::fs::write(&cache_path, b"this is not json").unwrap();
        let loaded = MerkleIndex::load(&cache_path);
        assert!(loaded.is_empty());
    }

    #[test]
    fn missing_cache_returns_empty() {
        let loaded = MerkleIndex::load(Path::new("/definitely/does/not/exist.idx"));
        assert!(loaded.is_empty());
    }

    #[test]
    fn schema_version_mismatch_treated_as_cold_start() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("merkle.idx");
        // Forge a JSON with a future schema version.
        let bad = serde_json::json!({
            "version": 99,
            "entries": { "/foo": "00".repeat(32) }
        });
        std::fs::write(&cache_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let loaded = MerkleIndex::load(&cache_path);
        assert!(loaded.is_empty());
    }
}
