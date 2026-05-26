//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::compute_spec_hash;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{CompanionSpec, DetectorSpec, PatternSpec, Severity};
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    MerkleIndex::hash_content(s)
}
#[test]
fn schema_version_mismatch_treated_as_cold_start() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let bad = serde_json::json!({
        "version": 99,
        "entries": { "/foo": { "mtime_ns": 0, "size": 0, "hash": "00".repeat(32) } }
    });
    std::fs::write(&cache_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let loaded = MerkleIndex::load(&cache_path);
    assert!(loaded.is_empty());
}
