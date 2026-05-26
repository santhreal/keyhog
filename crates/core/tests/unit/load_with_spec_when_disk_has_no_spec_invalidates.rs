//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::compute_spec_hash;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    MerkleIndex::hash_content(s)
}
#[test]
fn load_with_spec_when_disk_has_no_spec_invalidates() {
    // Old save() (no spec) must NOT satisfy a load_with_spec gate —
    // missing means "we don't know which detector set wrote this,"
    // so treat as cold-start under the strict path.
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let idx = MerkleIndex::empty();
    idx.record_with_metadata(PathBuf::from("/tmp/x"), 1, 1, sample_hash(b"x"));
    idx.save(&cache_path).unwrap();
    let loaded = MerkleIndex::load_with_spec(&cache_path, &[1u8; 32]);
    assert!(loaded.is_empty());
}
