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
fn persisted_cache_entries_are_sorted_by_cache_key() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let index = TestApi.merkle_with_max_entries(0);
    for (path, offset) in [
        ("/repo/z.txt", 8),
        ("/repo/a.txt", 16),
        ("/repo/a.txt", 0),
        ("/repo/m.txt", 4),
    ] {
        TestApi.merkle_record_chunk_at_offset_and_check_unchanged(
            &index,
            PathBuf::from(path),
            offset,
            offset + 1,
            1,
            format!("{path}:{offset}").as_bytes(),
        );
    }

    TestApi.merkle_save(&index, &cache_path).unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
    let persisted = saved["entries"]
        .as_array()
        .expect("cache entries are serialized as an array")
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().expect("entry path").to_owned(),
                entry["chunk_offset"].as_u64().expect("entry chunk_offset"),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        persisted,
        vec![
            ("/repo/a.txt".to_owned(), 0),
            ("/repo/a.txt".to_owned(), 16),
            ("/repo/m.txt".to_owned(), 4),
            ("/repo/z.txt".to_owned(), 8),
        ],
        "persisted Merkle cache order must not depend on randomized hash-map iteration"
    );
}

#[test]
fn save_lock_and_cap_source_contract() {
    let storage_source = keyhog_core::testing::read_crate_source("src/merkle_index/storage.rs");
    let state_source = keyhog_core::testing::read_crate_source("src/state_file.rs");

    assert!(state_source.contains("use fs2::FileExt;"));
    assert!(state_source.contains("pub struct StateFileWriteLock"));
    assert!(state_source.contains("file.lock_exclusive()?"));
    assert!(state_source.contains("pub fn state_file_lock_path("));
    assert!(storage_source.contains("fn cache_file_fingerprint("));
    assert!(storage_source.contains("cache_file_changed_since_load_or_save(path)"));
    assert!(storage_source.contains("remember_cache_file_fingerprint(path)"));
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
        .find("let _save_lock = state_file::StateFileWriteLock::acquire(path)?;")
        .expect("save lock acquisition");
    let merge_pos = save_inner
        .find("let mut merged = self.load_merge_base(path, spec_hash);")
        .expect("load/merge after lock");
    assert!(
        lock_pos < merge_pos,
        "save must acquire the sidecar lock before reading merge base"
    );
    let merge_base = storage_source
        .split("fn load_merge_base(")
        .nth(1)
        .expect("load_merge_base exists")
        .split("fn overlay_in_memory_entries(")
        .next()
        .expect("load_merge_base boundary");
    assert!(
        merge_base.contains("if !self.cache_file_changed_since_load_or_save(path)")
            && merge_base.contains("return HashMap::new();"),
        "load_merge_base should skip disk read/parse when the cache file fingerprint is unchanged"
    );
    assert!(
        storage_source.contains("ordered.sort_by(|(left_key, _), (right_key, _)|")
            && storage_source
                .contains(".then_with(|| left_key.chunk_offset.cmp(&right_key.chunk_offset))")
            && storage_source.contains("path: key.path.display().to_string()"),
        "save must serialize Merkle entries deterministically by cache key"
    );
}
