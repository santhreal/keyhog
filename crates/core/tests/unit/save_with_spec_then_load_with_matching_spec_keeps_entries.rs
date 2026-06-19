//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::MerkleIndex;
use std::path::PathBuf;
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn save_with_spec_then_load_with_matching_spec_keeps_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    let p = PathBuf::from("/tmp/x");
    let h = sample_hash(b"x");
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        p.clone(),
        7,
        1,
        h,
    );
    let spec = [42u8; 32];
    idx.save_with_spec(&cache_path, &spec).unwrap();
    let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        1
    );
    assert!(loaded.metadata_unchanged(&p, 7, 1));
}
