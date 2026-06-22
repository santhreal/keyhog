//! Merkle index records content hash and detects changes.

use std::path::PathBuf;

#[test]
fn merkle_record_and_unchanged_roundtrip() {
    let idx = keyhog_core::testing::CoreTestApi::merkle_empty(&keyhog_core::testing::TestApi, );
    let p = PathBuf::from("/tmp/example.env");
    let h = keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, b"DB_PASS=secret123");
    keyhog_core::testing::CoreTestApi::merkle_record(&keyhog_core::testing::TestApi, &idx, p.clone(), h);
    assert!(keyhog_core::testing::CoreTestApi::merkle_unchanged(&keyhog_core::testing::TestApi, &idx, &p, &h));
    let h2 = keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, b"DB_PASS=changed");
    assert!(!keyhog_core::testing::CoreTestApi::merkle_unchanged(&keyhog_core::testing::TestApi, &idx, &p, &h2));
}
