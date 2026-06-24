//! RAR archives that cannot be read must emit a source error and increment skip
//! counters.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[cfg(unix)]
fn lock_exclusive(path: &std::path::Path) -> std::fs::File {
    use std::os::unix::io::AsRawFd;

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
fn corrupt_rar_counts_as_unreadable() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.rar"), b"not a rar archive").expect("write corrupt RAR");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "corrupt RAR should emit one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("corrupt RAR must be an error row");
    assert!(
        err.to_string().contains("cannot open archive")
            && err.to_string().contains("archive was not scanned"),
        "error should name the unscanned RAR archive, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt RAR coverage gap must be counted as unreadable"
    );
}

#[cfg(unix)]
#[test]
fn locked_rar_emits_source_error() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    let archive_path = dir.path().join("locked.rar");
    std::fs::write(&archive_path, b"locked bytes should not be parsed").expect("write rar");
    let _lock = lock_exclusive(&archive_path);

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "locked RAR input must emit one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("locked RAR input must be an error row");
    assert!(
        err.to_string().contains("failed to scan RAR archive")
            && err.to_string().contains("locked.rar")
            && err.to_string().contains("compressed input")
            && err.to_string().contains("archive was not scanned"),
        "error should name the locked RAR coverage gap, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "locked RAR coverage gap must be counted as unreadable"
    );
}
