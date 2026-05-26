//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::compute_spec_hash;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    MerkleIndex::hash_content(s)
}
#[test]
fn load_with_mismatched_spec_invalidates_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let idx = MerkleIndex::empty();
    idx.record_with_metadata(PathBuf::from("/tmp/x"), 7, 1, sample_hash(b"x"));
    idx.save_with_spec(&cache_path, &[42u8; 32]).unwrap();
    // Different spec hash → empty cache.
    let loaded = MerkleIndex::load_with_spec(&cache_path, &[7u8; 32]);
    assert!(loaded.is_empty());
}
