//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::Path;
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn unknown_path_is_changed() {
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    let h = sample_hash(b"x");
    assert!(!keyhog_core::testing::CoreTestApi::merkle_unchanged(
        &keyhog_core::testing::TestApi,
        &idx,
        Path::new("/never/seen"),
        &h
    ));
}
