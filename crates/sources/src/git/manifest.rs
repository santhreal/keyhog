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
use std::path::Path;

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
        match super::staged_manifest_acquire(repo_path) {
            Ok(fresh) => fresh.index_fingerprint == self.index_fingerprint,
            Err(_) => false,
        }
    }
}
