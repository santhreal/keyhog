//! Chunked Merkle entries are keyed by path plus chunk offset.

use std::path::{Path, PathBuf};

use keyhog_core::testing::{CoreTestApi, TestApi};

fn record_chunk(
    index: &keyhog_core::MerkleIndex,
    path: PathBuf,
    offset: u64,
    content: &[u8],
) -> bool {
    TestApi.merkle_record_chunk_at_offset_and_check_unchanged(index, path, offset, 7, 2048, content)
}

#[test]
fn same_path_chunks_do_not_overwrite_each_other() {
    let index = TestApi.merkle_empty();
    let path = PathBuf::from("/repo/large.bin");

    assert!(!record_chunk(&index, path.clone(), 0, b"first chunk"));
    assert!(!record_chunk(&index, path.clone(), 1024, b"second chunk"));
    assert_eq!(TestApi.merkle_len(&index), 2);

    assert!(record_chunk(&index, path.clone(), 0, b"first chunk"));
    assert!(record_chunk(&index, path.clone(), 1024, b"second chunk"));

    assert!(!record_chunk(
        &index,
        path.clone(),
        1024,
        b"changed second chunk"
    ));
    assert!(record_chunk(&index, path, 0, b"first chunk"));
}

#[test]
fn forget_removes_every_chunk_for_the_file() {
    let index = TestApi.merkle_empty();
    let path = PathBuf::from("/repo/found-secret.bin");

    assert!(!record_chunk(&index, path.clone(), 0, b"prefix"));
    assert!(!record_chunk(&index, path.clone(), 4096, b"suffix"));
    assert_eq!(TestApi.merkle_len(&index), 2);

    index.forget(Path::new("/repo/found-secret.bin"));

    assert_eq!(TestApi.merkle_len(&index), 0);
    assert!(!record_chunk(&index, path.clone(), 0, b"prefix"));
    assert!(!record_chunk(&index, path, 4096, b"suffix"));
}

#[test]
fn save_and_load_preserves_multiple_offsets_for_one_path() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");
    let path = PathBuf::from("/repo/persisted-large.bin");

    let index = TestApi.merkle_empty();
    assert!(!record_chunk(&index, path.clone(), 0, b"alpha"));
    assert!(!record_chunk(&index, path.clone(), 8192, b"omega"));
    TestApi.merkle_save(&index, &cache_path).unwrap();

    let loaded = TestApi.merkle_load(&cache_path);
    assert_eq!(TestApi.merkle_len(&loaded), 2);
    assert!(record_chunk(&loaded, path.clone(), 0, b"alpha"));
    assert!(record_chunk(&loaded, path, 8192, b"omega"));
}

#[test]
fn merkle_chunk_offset_source_contract_is_on_production_path() {
    let root_source = keyhog_core::testing::read_crate_source("src/merkle_index.rs");
    assert!(root_source.contains("const SCHEMA_VERSION: u32 = 4"));
    assert!(root_source.contains("struct CacheKey"));
    assert!(root_source.contains("struct CacheKeyRef<'a>"));
    assert!(root_source.contains("chunk_offset: u64"));
    assert!(root_source.contains("record_chunk_at_offset_and_check_unchanged"));
    assert!(root_source.contains("record_borrowed_key_at_offset_with_metadata"));
    assert!(!root_source.contains("HashMap<PathBuf, CacheEntry>"));
    let borrowed_recording = root_source
        .split("fn record_borrowed_key_at_offset_with_metadata(")
        .nth(1)
        .expect("borrowed recording helper exists")
        .split("/// Insert or update one entry")
        .next()
        .expect("borrowed recording helper body");
    assert!(borrowed_recording.contains("shard.get_mut(&lookup)"));
    assert!(
        !borrowed_recording.contains("let key = CacheKey::chunk(path.to_path_buf(), chunk_offset)"),
        "borrowed chunk recording must not allocate the owned key before checking existing entries"
    );

    let storage_source = keyhog_core::testing::read_crate_source("src/merkle_index/storage.rs");
    assert!(storage_source.contains("entries: Vec<EntryV4>"));
    assert!(storage_source.contains("chunk_offset"));
    assert!(storage_source.contains("CacheKey::chunk"));

    let dispatch_source =
        keyhog_core::testing::read_crate_source("../cli/src/orchestrator/dispatch.rs");
    assert!(dispatch_source.contains("record_chunk_path_at_offset_and_check_unchanged"));
    assert!(dispatch_source.contains("c.metadata.base_offset as u64"));
    assert!(!dispatch_source.contains("PathBuf::from(path_str)"));

    let fused_source =
        keyhog_core::testing::read_crate_source("../cli/src/orchestrator/dispatch/fused.rs");
    assert!(fused_source.contains("record_chunk_path_at_offset_and_check_unchanged"));
    assert!(fused_source.contains("c.metadata.base_offset as u64"));
    assert!(!fused_source.contains("PathBuf::from(path_str)"));
}
