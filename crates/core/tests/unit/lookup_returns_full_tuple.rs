//! Migrated from `src/merkle_index.rs` inline tests.
use std::path::{Path, PathBuf};
fn sample_hash(s: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, s)
}
#[test]
fn lookup_returns_full_tuple() {
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    let p = PathBuf::from("/tmp/file");
    let h = sample_hash(b"abc");
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        p.clone(),
        42,
        99,
        h,
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(&keyhog_core::testing::TestApi, &idx, &p),
        Some((42, 99, h))
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(
            &keyhog_core::testing::TestApi,
            &idx,
            Path::new("/missing")
        ),
        None
    );
}
