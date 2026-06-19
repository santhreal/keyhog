//! Metadata fast-path matches only on exact mtime+size pair.

use keyhog_core::MerkleIndex;
use std::path::{Path, PathBuf};

#[test]
fn merkle_metadata_unchanged_matches_only_on_exact_pair() {
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi);
    let p = PathBuf::from("/tmp/file");
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        p.clone(),
        1_700_000_000_000_000_000,
        4096,
        keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, b"x"),
    );
    assert!(idx.metadata_unchanged(&p, 1_700_000_000_000_000_000, 4096));
    assert!(!idx.metadata_unchanged(&p, 1_700_000_000_000_000_001, 4096));
    assert!(!idx.metadata_unchanged(&p, 1_700_000_000_000_000_000, 4097));
    assert!(!idx.metadata_unchanged(Path::new("/never/seen"), 0, 0));
}
