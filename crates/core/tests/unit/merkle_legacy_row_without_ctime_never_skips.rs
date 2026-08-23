//! Regression: a persisted cache row without an inode change time is never
//! trusted by the read-free fast-path skip.
//!
//! WHY: the skip's identity is `(mtime, ctime, size)`. Rows written before
//! `ctime_ns` existed (schema v4) deserialize with `ctime_ns == 0`, and rows
//! from platforms without a change time store `0` as well. `0` can never match
//! a live stat, so such entries are re-read and re-hashed on the next scan and
//! then persisted with a real ctime. This keeps a stale v4 cache (or a
//! ctime-less platform) from resurrecting the adversarial-kind-1 recall hole:
//! a same-size tamper whose mtime was forged back must never be skipped.

use std::path::Path;

#[test]
fn legacy_row_without_ctime_is_loaded_but_never_skips() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    // A v4-shaped row: no `ctime_ns` key at all. Deserializes to 0.
    let on_disk = serde_json::json!({
        "version": 5,
        "written_at_ns": 1_000u64 * 1_000_000_000,
        "entries": [
            {
                "path": "/legacy.env",
                "chunk_offset": 0,
                "mtime_ns": 999u64 * 1_000_000_000,
                "size": 20,
                "hash": "ab".repeat(32)
            }
        ]
    });
    std::fs::write(&cache_path, serde_json::to_vec(&on_disk).unwrap()).unwrap();

    let loaded =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        1,
        "the legacy row itself still loads"
    );

    // Exact (mtime, size) match with ctime 0: the skip must refuse.
    assert!(
        !loaded.metadata_unchanged(Path::new("/legacy.env"), 999u64 * 1_000_000_000, 0, 20),
        "a row without a change time is never trusted by the read-free skip"
    );

    // A row WITH a matching nonzero ctime is trusted.
    let fresh = keyhog_core::MerkleIndex::default();
    assert!(!fresh.record_chunk_at_offset_and_check_unchanged(
        std::path::PathBuf::from("/fresh.env"),
        0,
        999u64 * 1_000_000_000,
        999u64 * 1_000_000_000 + 5,
        20,
        b"KEY=value",
    ));
    assert!(fresh.metadata_unchanged(
        Path::new("/fresh.env"),
        999u64 * 1_000_000_000,
        999u64 * 1_000_000_000 + 5,
        20,
    ));
}
