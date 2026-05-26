//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::compute_spec_hash;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    MerkleIndex::hash_content(s)
}
#[test]
fn save_with_spec_then_load_with_matching_spec_keeps_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let idx = MerkleIndex::empty();
    let p = PathBuf::from("/tmp/x");
    let h = sample_hash(b"x");
    idx.record_with_metadata(p.clone(), 7, 1, h);
    let spec = [42u8; 32];
    idx.save_with_spec(&cache_path, &spec).unwrap();
    let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
    assert_eq!(loaded.len(), 1);
    assert!(loaded.metadata_unchanged(&p, 7, 1));
}
