//! KH-GAP-015: legacy save() cache must not satisfy load_with_spec gate.

use keyhog_core::MerkleIndex;
use std::path::PathBuf;

#[test]
fn merkle_load_with_spec_rejects_legacy_save_without_spec() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("merkle.idx");
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        PathBuf::from("/tmp/x"),
        1,
        1,
        keyhog_core::testing::CoreTestApi::merkle_hash_content(
            &keyhog_core::testing::TestApi,
            b"x",
        ),
    );
    keyhog_core::testing::CoreTestApi::merkle_save(
        &keyhog_core::testing::TestApi,
        &idx,
        &cache_path,
    )
    .expect("save legacy");
    let loaded = MerkleIndex::load_with_spec(&cache_path, &[1u8; 32]);
    assert!(
        keyhog_core::testing::CoreTestApi::merkle_is_empty(&keyhog_core::testing::TestApi, &loaded),
        "legacy save must not satisfy spec-gated load"
    );
}
