#![cfg(unix)]

use std::os::unix::io::AsRawFd;

use keyhog_core::Source;
use keyhog_sources::skip_counts;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::FilesystemSource;

fn lock_exclusive(path: &std::path::Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("open lock target");
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "exclusive lock acquired for test fixture");
    file
}

#[test]
fn locked_files_are_counted_and_not_reopened_unlocked() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().expect("tempdir");

    let plain = dir.path().join("locked.txt");
    std::fs::write(&plain, "SECRET=ghp_lockedPlainShouldNotRead1234567890\n").expect("write plain");
    let _plain_lock = lock_exclusive(&plain);
    assert!(
        TestApi.read_file_mmap(&plain).is_none(),
        "whole-file mmap path must skip a locked file instead of buffered-reading it unlocked"
    );

    let compressed = dir.path().join("locked.gz");
    std::fs::write(
        &compressed,
        b"not really compressed; this test covers the pre-decompress byte reader",
    )
    .expect("write compressed input");
    let _compressed_lock = lock_exclusive(&compressed);
    assert!(
        TestApi
            .read_file_for_compressed_input(&compressed, 1024 * 1024)
            .is_none(),
        "compressed byte reader must skip a locked file instead of buffered-reading it unlocked"
    );

    let large = dir.path().join("locked-large.txt");
    std::fs::write(&large, "A".repeat(8192)).expect("write large");
    let _large_lock = lock_exclusive(&large);
    assert_eq!(
        TestApi.read_file_windowed_mmap_len(&large, 1024, 32),
        Some(0),
        "windowed mmap path must consume the locked-file skip and prevent caller fallback"
    );

    assert_eq!(
        skip_counts().unreadable,
        3,
        "each locked read owner must surface an unreadable skip"
    );
}

#[test]
fn filesystem_source_does_not_reopen_locked_small_file_unlocked() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().expect("tempdir");
    let locked = dir.path().join("locked-small.txt");
    let secret = "SECRET=ghp_lockedSmallShouldNotRead1234567890\n";
    std::fs::write(&locked, secret).expect("write locked fixture");
    let _lock = lock_exclusive(&locked);

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let mut chunks = Vec::new();
    let mut errors = Vec::new();
    for row in rows {
        match row {
            Ok(chunk) => chunks.push(chunk),
            Err(error) => errors.push(error),
        }
    }

    assert!(
        chunks
            .iter()
            .all(|chunk| !chunk.data.as_ref().contains(secret)),
        "locked file bytes must not be scanned through an unlocked fallback"
    );
    assert_eq!(
        errors.len(),
        1,
        "locked small file must emit one visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("primary read path refused") && error.contains("file was not scanned"),
        "locked small file SourceError must describe unscanned coverage, got {error}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "locked small file must count exactly one unreadable skip"
    );
}
