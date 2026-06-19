//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::PathBuf;
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn load_with_spec_when_disk_has_no_spec_invalidates() {
    // Old save() (no spec) must NOT satisfy a load_with_spec gate -
    // missing means "we don't know which detector set wrote this,"
    // so treat as cold-start under the strict path.
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        PathBuf::from("/tmp/x"),
        1,
        1,
        sample_hash(b"x"),
    );
    keyhog_core::testing::CoreTestApi::merkle_save(
        &keyhog_core::testing::TestApi,
        &idx,
        &cache_path,
    )
    .unwrap();
    let loaded = keyhog_core::testing::CoreTestApi::merkle_load_with_spec(
        &keyhog_core::testing::TestApi,
        &cache_path,
        &[1u8; 32],
    );
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &loaded
    ));
}
