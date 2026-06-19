//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn save_drops_stale_spec_entries_on_disk() {
    // If the on-disk file was written with a DIFFERENT detector
    // spec, those entries are stale (a future load_with_spec
    // would invalidate them anyway). The save path uses
    // load_with_spec internally, so spec-mismatched disk entries
    // are NOT merged in - only the current process's in-memory
    // entries get written.
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    let idx_old = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx_old,
        PathBuf::from("/from-old-spec"),
        1,
        1,
        sample_hash(b"x"),
    );
    idx_old.save_with_spec(&cache_path, &[1u8; 32]).unwrap();

    let idx_new = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx_new,
        PathBuf::from("/from-new-spec"),
        2,
        2,
        sample_hash(b"y"),
    );
    idx_new.save_with_spec(&cache_path, &[2u8; 32]).unwrap();

    // After saving with the new spec, only the new-spec entry
    // is present. The old-spec entry was dropped at save time.
    let loaded = keyhog_core::testing::CoreTestApi::merkle_load_with_spec(
        &keyhog_core::testing::TestApi,
        &cache_path,
        &[2u8; 32],
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        1
    );
    assert!(loaded.metadata_unchanged(Path::new("/from-new-spec"), 2, 2));
}
