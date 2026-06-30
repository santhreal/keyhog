//! Merkle insert hot path uses one map entry probe.

use std::path::PathBuf;

fn sample_hash(bytes: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, bytes)
}

#[test]
fn merkle_try_insert_uses_map_entry_once() {
    let source = keyhog_core::testing::read_crate_source("src/merkle_index.rs");
    let try_insert = source
        .split("fn try_insert(")
        .nth(1)
        .expect("try_insert exists")
        .split("/// Remove `path`")
        .next()
        .expect("try_insert body boundary");

    assert!(try_insert.contains("shard.entry(key)"));
    assert!(try_insert.contains("Entry::Occupied"));
    assert!(try_insert.contains("Entry::Vacant"));
    assert!(!try_insert.contains(".get_mut(&path)"));
    assert!(!try_insert.contains(".write().insert(path, entry)"));
}

#[test]
fn merkle_over_cap_updates_existing_path() {
    let idx = keyhog_core::testing::CoreTestApi::merkle_with_max_entries(
        &keyhog_core::testing::TestApi,
        1,
    );
    let path = PathBuf::from("/tmp/full-cap");
    let first = sample_hash(b"first");
    let second = sample_hash(b"second");
    let blocked = PathBuf::from("/tmp/blocked-new-path");

    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        path.clone(),
        1,
        5,
        first,
    );
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        blocked.clone(),
        2,
        7,
        sample_hash(b"blocked"),
    );
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &idx,
        path.clone(),
        3,
        6,
        second,
    );

    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(
            &keyhog_core::testing::TestApi,
            &idx,
            &path
        ),
        Some((3, 6, second))
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_lookup(
            &keyhog_core::testing::TestApi,
            &idx,
            &blocked
        ),
        None,
        "new over-cap path must still be dropped"
    );
}
