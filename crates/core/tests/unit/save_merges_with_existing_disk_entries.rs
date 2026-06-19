//! Migrated from `src/merkle_index.rs` inline tests.
use keyhog_core::MerkleIndex;
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn save_merges_with_existing_disk_entries() {
    // Simulates two concurrent `keyhog scan --incremental`
    // processes scanning different subsets. The save path now
    // does read-modify-write so process B's save doesn't blow
    // away process A's entries when their target path sets
    // don't overlap.
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let spec = [42u8; 32];

    // Process A scans path /a/file and saves.
    let idx_a = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx_a,
        PathBuf::from("/a/file"),
        100,
        10,
        sample_hash(b"a contents"),
    );
    idx_a.save_with_spec(&cache_path, &spec).unwrap();

    // Process B (separate handle, fresh memory) scans /b/file and
    // saves. Without read-modify-write, /a/file's entry would be
    // gone after this save.
    let idx_b = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx_b,
        PathBuf::from("/b/file"),
        200,
        20,
        sample_hash(b"b contents"),
    );
    idx_b.save_with_spec(&cache_path, &spec).unwrap();

    // Reload with the same spec. BOTH /a/file AND /b/file must
    // be present - process A's entry survived process B's save.
    let loaded = MerkleIndex::load_with_spec(&cache_path, &spec);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        2
    );
    assert!(loaded.metadata_unchanged(Path::new("/a/file"), 100, 10));
    assert!(loaded.metadata_unchanged(Path::new("/b/file"), 200, 20));
}
