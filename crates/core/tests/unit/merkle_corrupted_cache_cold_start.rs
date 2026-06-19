//! Corrupted merkle cache must cold-start as empty index.

use keyhog_core::MerkleIndex;

#[test]
fn merkle_corrupted_cache_treated_as_cold_start() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("merkle.idx");
    std::fs::write(&cache_path, b"this is not json").expect("write garbage");
    let loaded = keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(&keyhog_core::testing::TestApi, &loaded));
}
