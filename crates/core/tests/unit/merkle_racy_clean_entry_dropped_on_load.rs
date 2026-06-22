//! Regression: the racy-clean guard drops cache entries whose file mtime
//! lands in the same clock-second as (or after) the index write, while keeping
//! entries from a strictly earlier second.
//!
//! This is git's "racy index" defense applied to the incremental scan cache.
//! On a coarse-mtime filesystem (FAT/HFS+/some NFS report whole-second mtimes)
//! a size-preserving edit made in the same second the index was written leaves
//! `(mtime, size)` unchanged, so trusting the stored content hash would skip a
//! freshly injected secret forever - a silent recall loss in `--incremental`
//! mode. The guard forces those entries to be re-read and re-hashed instead.

use std::path::Path;

const NS_PER_SEC: u64 = 1_000_000_000;

#[test]
fn racy_entry_dropped_safe_entry_kept_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    // The index was written at 1000.000000000s. Entries whose file mtime is in
    // that same second cannot be trusted by (mtime, size) alone; an entry from
    // a strictly earlier second can.
    let written_at_ns = 1000 * NS_PER_SEC;
    let racy_after = 1000 * NS_PER_SEC + 400_000_000; // 1000.4s - same second, later
    let racy_boundary = 1000 * NS_PER_SEC; // exactly 1000.0s - the coarse-FS whole-second case
    let safe_mtime = 999 * NS_PER_SEC + 900_000_000; // 999.9s - strictly earlier second

    let on_disk = serde_json::json!({
        "version": 4,
        "written_at_ns": written_at_ns,
        "entries": [
            {
                "path": "/racy-after",
                "chunk_offset": 0,
                "mtime_ns": racy_after,
                "size": 10,
                "hash": "ab".repeat(32)
            },
            {
                "path": "/racy-boundary",
                "chunk_offset": 0,
                "mtime_ns": racy_boundary,
                "size": 11,
                "hash": "ef".repeat(32)
            },
            {
                "path": "/safe",
                "chunk_offset": 0,
                "mtime_ns": safe_mtime,
                "size": 20,
                "hash": "cd".repeat(32)
            }
        ]
    });
    std::fs::write(&cache_path, serde_json::to_vec(&on_disk).unwrap()).unwrap();

    let loaded =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);

    // Both racy entries are gone -> the next scan re-reads + re-hashes them.
    assert!(
        !loaded.metadata_unchanged(Path::new("/racy-after"), racy_after, 10),
        "entry modified later in the index-write second must be dropped"
    );
    assert!(
        !loaded.metadata_unchanged(Path::new("/racy-boundary"), racy_boundary, 11),
        "entry whose whole-second mtime equals the index-write second must be dropped \
         (the canonical coarse-filesystem case)"
    );
    // The entry from a strictly earlier second survives -> the speedup is intact.
    assert!(
        loaded.metadata_unchanged(Path::new("/safe"), safe_mtime, 20),
        "entry from a strictly earlier second must be kept for the fast-path skip"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::merkle_len(&keyhog_core::testing::TestApi, &loaded),
        1,
        "exactly the one safe entry survives the racy-clean load filter"
    );
}

#[test]
fn zero_written_at_marks_every_entry_racy() {
    // A cache written with `written_at_ns == 0` (clock read failed at save
    // time) must fail safe: the floor is 0, so every entry is racy and the
    // whole index cold-starts rather than trusting a stale hash.
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("merkle.idx");

    let on_disk = serde_json::json!({
        "version": 4,
        "written_at_ns": 0,
        "entries": [
            {
                "path": "/any",
                "chunk_offset": 0,
                "mtime_ns": 5,
                "size": 1,
                "hash": "12".repeat(32)
            }
        ]
    });
    std::fs::write(&cache_path, serde_json::to_vec(&on_disk).unwrap()).unwrap();

    let loaded =
        keyhog_core::testing::CoreTestApi::merkle_load(&keyhog_core::testing::TestApi, &cache_path);
    assert!(
        keyhog_core::testing::CoreTestApi::merkle_is_empty(&keyhog_core::testing::TestApi, &loaded),
        "written_at_ns == 0 must mark every entry racy (fail safe to full re-scan)"
    );
}
