//! Exact staged Git manifest for the guard commit transaction.
//!
//! This module produces an ordered manifest of every staged blob, derived
//! from the Git index (not the working tree). The manifest carries:
//!
//! - repository identity and Git hash algorithm
//! - index fingerprint (for race detection)
//! - path bytes without lossy Unicode conversion
//! - file mode
//! - staged object ID
//! - exact object size
//! - deletion/submodule/symlink classification
//! - any source coverage gap
//!
//! The manifest is the commit-time authorization input. Working-tree bytes
//! are never substituted for staged object bytes.

use keyhog_core::guard_state::GitHashAlgorithm;
use keyhog_core::SourceError;
use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexFingerprintCacheEntry {
    pub(crate) index_path: PathBuf,
    pub(crate) mtime: SystemTime,
    pub(crate) file_size: u64,
    pub(crate) trailing_checksum: [u8; 20],
    pub(crate) fingerprint: String,
}

pub(crate) const MAX_INDEX_FINGERPRINT_CACHE_REPOSITORIES: usize = 64;

static INDEX_FINGERPRINT_CACHE: Mutex<Option<LruCache<PathBuf, IndexFingerprintCacheEntry>>> =
    Mutex::new(None);

pub(crate) fn record_index_fingerprint_cache(
    repo_root: PathBuf,
    entry: IndexFingerprintCacheEntry,
) {
    let mut guard = INDEX_FINGERPRINT_CACHE.lock();
    let cache = guard.get_or_insert_with(|| {
        let cap = NonZeroUsize::new(MAX_INDEX_FINGERPRINT_CACHE_REPOSITORIES)
            .expect("MAX_INDEX_FINGERPRINT_CACHE_REPOSITORIES must be non-zero");
        LruCache::new(cap)
    });
    cache.put(repo_root, entry);
}

pub(crate) fn fast_check_index_fingerprint(
    repo_path: &Path,
    expected_fingerprint: &str,
) -> Option<bool> {
    let repo_root = super::canonical_repo_root(repo_path).ok()?;
    let mut guard = INDEX_FINGERPRINT_CACHE.lock();
    let cache = guard.as_mut()?;
    let entry = cache.get(&repo_root)?;
    let meta = std::fs::metadata(&entry.index_path).ok()?;
    let mtime = meta.modified().ok()?;
    if mtime != entry.mtime || meta.len() != entry.file_size {
        return None;
    }
    let checksum = super::read_index_tail_checksum(&entry.index_path)?;
    if checksum != entry.trailing_checksum {
        return None;
    }
    Some(entry.fingerprint == expected_fingerprint)
}
/// File mode classification for a staged index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StagedEntryKind {
    /// Regular file (blob).
    File,
    /// Symlink.
    Symlink,
    /// Submodule (gitlink).
    Submodule,
    /// Deleted entry (no payload to scan).
    Deletion,
}

/// One entry in the ordered staged manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedManifestEntry {
    /// Path bytes as reported by Git, without lossy Unicode conversion.
    pub path_bytes: Vec<u8>,
    /// File mode classification.
    pub kind: StagedEntryKind,
    /// Staged blob object ID (hex). Empty for deletions.
    pub object_oid: String,
    /// Exact object size in bytes. Zero for deletions.
    pub object_size: u64,
    /// Raw file mode from the index (e.g. `100644`, `100755`, `120000`).
    pub raw_mode: u32,
}

/// The complete ordered staged manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedManifest {
    /// Git hash algorithm used by the repository.
    pub hash_algorithm: GitHashAlgorithm,
    /// Index fingerprint: a digest over the ordered set of staged entries,
    /// used to detect concurrent index mutation during a guard transaction.
    pub index_fingerprint: String,
    /// Ordered entries.
    pub entries: Vec<StagedManifestEntry>,
    /// Total bytes across all non-deletion entries.
    pub total_bytes: u64,
    /// Total number of non-deletion entries in the manifest.
    pub total_objects: u64,
    /// Coverage gaps: non-secret descriptions of entries where the
    /// object could not be read or sized.
    pub coverage_gaps: Vec<String>,
}

impl StagedManifest {
    /// Acquire the staged manifest from a repository path.
    ///
    /// This runs `git diff --cached --raw -z --no-renames --no-abbrev` to get
    /// the exact staged object IDs and paths, then computes an index
    /// fingerprint over the ordered entry set.
    pub fn acquire(repo_path: &Path) -> Result<Self, SourceError> {
        super::staged_manifest_acquire(repo_path)
    }

    /// Recompute the index fingerprint from the current entries. Used to
    /// detect whether the index changed between the scan start and the
    /// receipt validation.
    pub fn recompute_fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"keyhog-staged-manifest\0");
        hasher.update(match self.hash_algorithm {
            GitHashAlgorithm::Sha1 => b"sha1\0",
            GitHashAlgorithm::Sha256 => b"sha256\0",
        });
        for entry in &self.entries {
            hasher.update(&entry.path_bytes);
            hasher.update(&[0]);
            hasher.update(entry.object_oid.as_bytes());
            hasher.update(&[0]);
            hasher.update(&entry.object_size.to_le_bytes());
            hasher.update(&[0]);
            hasher.update(&entry.raw_mode.to_le_bytes());
            hasher.update(&[0]);
        }
        hex::encode(hasher.finalize().as_bytes())
    }

    /// Whether the Git index still matches the fingerprint captured at
    /// acquisition time. Re-reads the staged manifest from the repository
    /// and compares the fresh fingerprint against the stored one. This
    /// detects concurrent index mutations between the start of a guard
    /// transaction and receipt validation.
    pub fn fingerprint_matches(&self, repo_path: &std::path::Path) -> bool {
        if let Some(matches) = fast_check_index_fingerprint(repo_path, &self.index_fingerprint) {
            return matches;
        }
        match super::staged_manifest_acquire(repo_path) {
            Ok(fresh) => fresh.index_fingerprint == self.index_fingerprint,
            Err(_) => false,
        }
    }
}

/// Re-acquire the staged manifest and check whether the index
/// fingerprint matches the expected value. Returns false if the
/// manifest cannot be acquired or the fingerprint differs. This is
/// the race-detection check the guard commit protocol runs at
/// `GuardCommitFinish` to ensure the staged content has not changed
/// since the transaction began.
pub fn verify_staged_fingerprint(repo_path: &std::path::Path, expected_fingerprint: &str) -> bool {
    if let Some(matches) = fast_check_index_fingerprint(repo_path, expected_fingerprint) {
        return matches;
    }
    match super::staged_manifest_acquire(repo_path) {
        Ok(fresh) => fresh.index_fingerprint == expected_fingerprint,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cache_entry(index_path: PathBuf, fingerprint: &str) -> IndexFingerprintCacheEntry {
        IndexFingerprintCacheEntry {
            index_path,
            mtime: SystemTime::UNIX_EPOCH,
            file_size: 100,
            trailing_checksum: [0x42; 20],
            fingerprint: fingerprint.to_string(),
        }
    }

    #[test]
    fn index_fingerprint_cache_caps_at_64_and_evicts_lru() {
        // WHY: in multi-tenant or long-running daemons monitoring many repositories,
        // unbounded cache growth creates silent memory leaks. Capping to 64 repositories
        // with LRU eviction bounds resident memory while preserving fast race-check hits
        // for active repositories.
        let mut guard = INDEX_FINGERPRINT_CACHE.lock();
        let cap = NonZeroUsize::new(MAX_INDEX_FINGERPRINT_CACHE_REPOSITORIES).unwrap();
        let mut cache = LruCache::new(cap);

        for i in 0..64 {
            let repo = PathBuf::from(format!("/repos/repo_{i}"));
            let entry = sample_cache_entry(repo.join(".git/index"), &format!("fp_{i}"));
            cache.put(repo, entry);
        }
        assert_eq!(cache.len(), 64);

        // Access repo_0 to promote it to most-recently used.
        let _ = cache.get(&PathBuf::from("/repos/repo_0"));

        // Insert 65th entry. Since repo_0 was accessed, repo_1 is now the oldest (LRU).
        let repo_64 = PathBuf::from("/repos/repo_64");
        cache.put(
            repo_64.clone(),
            sample_cache_entry(repo_64.join(".git/index"), "fp_64"),
        );
        assert_eq!(cache.len(), 64);

        // repo_1 must have been evicted; repo_0 must still be present.
        assert!(
            cache.peek(&PathBuf::from("/repos/repo_1")).is_none(),
            "repo_1 should have been evicted"
        );
        assert!(
            cache.peek(&PathBuf::from("/repos/repo_0")).is_some(),
            "repo_0 should still be cached"
        );
        assert!(
            cache.peek(&PathBuf::from("/repos/repo_64")).is_some(),
            "repo_64 should be cached"
        );

        // Restore the global cache to avoid test pollution.
        *guard = Some(cache);
    }

    #[test]
    fn fast_check_index_fingerprint_validates_mtime_and_checksum() {
        // WHY: fast-path index verification avoids re-running git plumbing on every commit
        // finish when the index on disk is untouched. Any modification to mtime, size, or
        // checksum must invalidate the fast-check so race detection falls back to safe re-scan.
        let temp = tempfile::tempdir().unwrap();
        let index_path = temp.path().join("index");
        let mut data = vec![0u8; 80];
        let checksum = [0x77u8; 20];
        data.extend_from_slice(&checksum);
        std::fs::write(&index_path, &data).unwrap();

        let meta = std::fs::metadata(&index_path).unwrap();
        let entry = IndexFingerprintCacheEntry {
            index_path: index_path.clone(),
            mtime: meta.modified().unwrap(),
            file_size: meta.len(),
            trailing_checksum: checksum,
            fingerprint: "expected_fp_abc".to_string(),
        };

        record_index_fingerprint_cache(temp.path().to_path_buf(), entry);

        // Matching fingerprint returns Some(true)
        assert_eq!(
            fast_check_index_fingerprint(temp.path(), "expected_fp_abc"),
            Some(true)
        );

        // Differing fingerprint returns Some(false)
        assert_eq!(
            fast_check_index_fingerprint(temp.path(), "different_fp"),
            Some(false)
        );

        // Modify index file bytes (invalidating checksum/size)
        std::fs::write(&index_path, b"modified").unwrap();
        assert_eq!(
            fast_check_index_fingerprint(temp.path(), "expected_fp_abc"),
            None
        );
    }
}
