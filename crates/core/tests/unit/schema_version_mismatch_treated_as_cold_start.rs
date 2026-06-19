//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::{MerkleIndex, MerkleLoadStatus};

#[test]
fn schema_version_mismatch_treated_as_cold_start() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let bad = serde_json::json!({
        "version": 99,
        "entries": { "/foo": { "mtime_ns": 0, "size": 0, "hash": "00".repeat(32) } }
    });
    std::fs::write(&cache_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let report = MerkleIndex::load_report(&cache_path);
    assert!(matches!(
        report.status(),
        MerkleLoadStatus::SchemaMismatch {
            path,
            version: 99,
            expected: 3,
        } if path == &cache_path
    ));
    let loaded = report.into_index();
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &loaded
    ));
}
