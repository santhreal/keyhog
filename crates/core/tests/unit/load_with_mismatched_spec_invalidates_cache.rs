//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::PathBuf;
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn load_with_mismatched_spec_invalidates_cache() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        PathBuf::from("/tmp/x"),
        7,
        1,
        sample_hash(b"x"),
    );
    idx.save_with_spec(&cache_path, &[42u8; 32]).unwrap();
    // Different spec hash → empty cache.
    let loaded = keyhog_core::testing::CoreTestApi::merkle_load_with_spec(
        &keyhog_core::testing::TestApi,
        &cache_path,
        &[7u8; 32],
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &loaded
    ));
}
