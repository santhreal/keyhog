//! Merkle load/save preserves configured caps and serializes save merges.

use std::path::PathBuf;

use keyhog_core::testing::{CoreTestApi, TestApi};

fn sample_hash(bytes: &[u8]) -> [u8; 32] {
    TestApi.merkle_hash_content(bytes)
}

#[test]
fn missing_cache_load_preserves_configured_cap() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("missing-merkle.idx");

    let loaded = TestApi.merkle_load_with_max_entries(&cache_path, 17);

    assert!(TestApi.merkle_is_empty(&loaded));
    assert_eq!(TestApi.merkle_max_entries(&loaded), 17);
}

#[test]
fn persisted_cache_load_enforces_configured_cap() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    let disk = TestApi.merkle_with_max_entries(0);
    for idx in 0..3 {
        TestApi.merkle_record_with_metadata(
            &disk,
            PathBuf::from(format!("/repo/{idx}.txt")),
            idx,
            1,
            sample_hash(format!("content-{idx}").as_bytes()),
        );
    }
    TestApi.merkle_save(&disk, &cache_path).unwrap();

    let loaded = TestApi.merkle_load_with_max_entries(&cache_path, 2);

    assert_eq!(TestApi.merkle_max_entries(&loaded), 2);
    assert_eq!(TestApi.merkle_len(&loaded), 2);
}

#[test]
fn save_lock_and_cap_source_contract() {
    let storage_source =
        std::fs::read_to_string("src/merkle_index/storage.rs").expect("read merkle storage");

    assert!(storage_source.contains("use fs2::FileExt;"));
    assert!(storage_source.contains("struct CacheWriteLock"));
    assert!(storage_source.contains(".lock_exclusive()?"));
    assert!(storage_source.contains("fn cache_lock_path("));
    assert!(storage_source.contains("load_with_max_entries(path, self.max_entries)"));
    assert!(storage_source.contains("load_with_spec_and_max_entries(path, hash, self.max_entries)"));

    let save_inner = storage_source
        .split("fn save_inner(")
        .nth(1)
        .expect("save_inner exists")
        .split("fn load_merge_base(")
        .next()
        .expect("save_inner boundary");
    let lock_pos = save_inner
        .find("let _save_lock = CacheWriteLock::acquire(path)?;")
        .expect("save lock acquisition");
    let merge_pos = save_inner
        .find("let mut merged = self.load_merge_base(path, spec_hash);")
        .expect("load/merge after lock");
    assert!(
        lock_pos < merge_pos,
        "save must acquire the sidecar lock before reading merge base"
    );
}
