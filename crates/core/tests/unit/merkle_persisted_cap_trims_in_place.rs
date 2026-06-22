//! Merkle persisted-cap enforcement trims the merge map in place.

use std::path::{Path, PathBuf};

fn sample_hash(bytes: &[u8]) -> [u8; 32] {
    keyhog_core::testing::CoreTestApi::merkle_hash_content(&keyhog_core::testing::TestApi, bytes)
}

#[test]
fn save_cap_prefers_current_in_memory_entries() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let spec = [7u8; 32];

    let disk = keyhog_core::testing::CoreTestApi::merkle_with_max_entries(
        &keyhog_core::testing::TestApi,
        0,
    );
    for idx in 0..3 {
        keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
            &keyhog_core::testing::TestApi,
            &disk,
            PathBuf::from(format!("/disk/{idx}")),
            idx,
            10,
            sample_hash(format!("disk-{idx}").as_bytes()),
        );
    }
    disk.save_with_spec(&cache_path, &spec).unwrap();

    let current = keyhog_core::testing::CoreTestApi::merkle_with_max_entries(
        &keyhog_core::testing::TestApi,
        2,
    );
    keyhog_core::testing::CoreTestApi::merkle_record_with_metadata(
        &keyhog_core::testing::TestApi,
        &current,
        PathBuf::from("/current"),
        99,
        11,
        sample_hash(b"current"),
    );
    current.save_with_spec(&cache_path, &spec).unwrap();

    let loaded = keyhog_core::testing::CoreTestApi::merkle_load_with_spec(
        &keyhog_core::testing::TestApi,
        &cache_path,
        &spec,
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        2
    );
    assert!(
        loaded.metadata_unchanged(Path::new("/current"), 99, 11),
        "fresh in-memory entry must survive persisted cap trimming"
    );
}

#[test]
fn persisted_cap_enforcement_does_not_replace_the_merged_map() {
    let source =
        std::fs::read_to_string("src/merkle_index/storage.rs").expect("read merkle storage source");
    let cap_fn = source
        .split("fn enforce_persisted_cap(")
        .nth(1)
        .expect("enforce_persisted_cap exists")
        .split("/// Default index location")
        .next()
        .expect("cap function boundary");

    assert!(cap_fn.contains("merged.remove(&key)"));
    assert!(!cap_fn.contains("HashMap::<PathBuf, CacheEntry>::with_capacity"));
    assert!(!cap_fn.contains("*merged = kept"));
}
