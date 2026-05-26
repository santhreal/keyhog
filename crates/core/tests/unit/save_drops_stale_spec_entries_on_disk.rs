//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::compute_spec_hash;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    MerkleIndex::hash_content(s)
}
#[test]
fn save_drops_stale_spec_entries_on_disk() {
    // If the on-disk file was written with a DIFFERENT detector
    // spec, those entries are stale (a future load_with_spec
    // would invalidate them anyway). The save path uses
    // load_with_spec internally, so spec-mismatched disk entries
    // are NOT merged in — only the current process's in-memory
    // entries get written.
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    let idx_old = MerkleIndex::empty();
    idx_old.record_with_metadata(PathBuf::from("/from-old-spec"), 1, 1, sample_hash(b"x"));
    idx_old.save_with_spec(&cache_path, &[1u8; 32]).unwrap();

    let idx_new = MerkleIndex::empty();
    idx_new.record_with_metadata(PathBuf::from("/from-new-spec"), 2, 2, sample_hash(b"y"));
    idx_new.save_with_spec(&cache_path, &[2u8; 32]).unwrap();

    // After saving with the new spec, only the new-spec entry
    // is present. The old-spec entry was dropped at save time.
    let loaded = MerkleIndex::load_with_spec(&cache_path, &[2u8; 32]);
    assert_eq!(loaded.len(), 1);
    assert!(loaded.metadata_unchanged(Path::new("/from-new-spec"), 2, 2));
}
