use keyhog_core::MerkleLoadStatus;

#[test]
fn merkle_invalid_entry_hash_cold_starts_with_status() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache_path = dir.path().join("merkle.idx");
    let bad = serde_json::json!({
        "version": 3,
        "written_at_ns": 1,
        "entries": {
            "/tmp/keyhog-bad-entry": {
                "mtime_ns": 0,
                "size": 10,
                "hash": "not-a-blake3-hex"
            }
        }
    });
    std::fs::write(
        &cache_path,
        serde_json::to_vec(&bad).expect("serialize bad cache"),
    )
    .expect("write bad cache");

    let report = keyhog_core::testing::CoreTestApi::merkle_load_report(
        &keyhog_core::testing::TestApi,
        &cache_path,
    );
    assert!(matches!(
        report.status(),
        MerkleLoadStatus::InvalidEntryHash {
            path,
            entry_path,
            hash,
        } if path == &cache_path
            && entry_path == "/tmp/keyhog-bad-entry"
            && hash == "not-a-blake3-hex"
    ));
    let loaded = report.into_index();
    assert!(keyhog_core::testing::CoreTestApi::merkle_is_empty(
        &keyhog_core::testing::TestApi,
        &loaded
    ));
}
