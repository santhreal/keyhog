#![cfg(unix)]

use std::os::unix::io::AsRawFd;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

use crate::support::split_chunk_results;

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
fn locked_compressed_file_emits_source_error() {
    let _guard = TestApi.skip_counter_guard();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("locked.gz");
    std::fs::write(&path, b"compressed input bytes").expect("write compressed input");
    let _lock = lock_exclusive(&path);

    TestApi.reset_skip_counters();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks.is_empty(),
        "locked compressed file must not be reopened and scanned unlocked"
    );
    assert_eq!(
        errors.len(),
        1,
        "locked compressed file must emit one machine-visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("failed to scan compressed file")
            && error.contains("locked.gz")
            && error.contains("compressed file was not scanned"),
        "compressed read failure error must identify the unscanned path, got {error:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "locked compressed file must also count as unreadable coverage"
    );
}
