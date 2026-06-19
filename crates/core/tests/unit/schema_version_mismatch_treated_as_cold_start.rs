//! Migrated from `src/merkle_index.rs` inline tests.
#[test]
fn schema_version_mismatch_treated_as_cold_start() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let bad = serde_json::json!({
        "version": 99,
        "entries": { "/foo": { "mtime_ns": 0, "size": 0, "hash": "00".repeat(32) } }
    });
    std::fs::write(&cache_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    let loaded =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &loaded
    ));
}
