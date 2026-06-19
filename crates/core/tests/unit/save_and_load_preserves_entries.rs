//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::PathBuf;
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn save_and_load_preserves_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    let p = PathBuf::from("/tmp/secrets.env");
    let h = sample_hash(b"hello world");
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        p.clone(),
        12345,
        11,
        h,
    );
    keyhog_core::testing::CoreTestApi::merkle_save(
        &keyhog_core::testing::TestApi,
        &idx,
        &cache_path,
    )
    .expect("save");

    let loaded =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        1
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_unchanged(
        &keyhog_core::testing::TestApi,
        &loaded,
        &p,
        &h
    ));
    assert!(loaded.metadata_unchanged(&p, 12345, 11));
}
