//! Special-file safety for the read entry points above `open_file_safe`.

use super::super::support::{make_fifo, symlink_to, within_timeout, write_regular};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::path::Path;

const CAP: u64 = 1 << 20;

// ── read_file_buffered ──────────────────────────────────────────────

/// Regression: preserves the externally observable `buffered_refuses_fifo_returns_none_without_hanging` behavior after the inline suite split.
#[test]
fn buffered_refuses_fifo_returns_none_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || TestApi.read_file_buffered_text(&fifo, 0));
    assert!(result.is_none(), "buffered read must skip a FIFO");
}

/// Regression: preserves the externally observable `buffered_refuses_symlink_returns_none` behavior after the inline suite split.
#[test]
fn buffered_refuses_symlink_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_regular(dir.path(), "real.txt", b"secret = abc123def456");
    let link = symlink_to(dir.path(), "link.txt", &target);
    assert!(
        TestApi.read_file_buffered_text(&link, 0).is_none(),
        "buffered read must refuse a symlink"
    );
}

/// Regression: preserves the externally observable `buffered_refuses_directory_returns_none` behavior after the inline suite split.
#[test]
fn buffered_refuses_directory_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(TestApi.read_file_buffered_text(dir.path(), 0).is_none());
}

/// Regression: preserves the externally observable `buffered_refuses_dev_null_returns_none` behavior after the inline suite split.
#[test]
fn buffered_refuses_dev_null_returns_none() {
    assert!(TestApi
        .read_file_buffered_text(Path::new("/dev/null"), 0)
        .is_none());
}

/// Regression: preserves the externally observable `buffered_regular_file_returns_exact_text` behavior after the inline suite split.
#[test]
fn buffered_regular_file_returns_exact_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"token = ghp_example");
    assert_eq!(
        TestApi.read_file_buffered_text(&path, 0).as_deref(),
        Some("token = ghp_example")
    );
}

// ── read_file_for_compressed_input (7z / rar / gz / xz / pdf path) ───

/// Regression: preserves the externally observable `compressed_input_refuses_fifo_none_without_hanging` behavior after the inline suite split.
#[test]
fn compressed_input_refuses_fifo_none_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "a.gz");
    let result = within_timeout(move || TestApi.read_file_for_compressed_input(&fifo, CAP));
    assert!(result.is_none(), "compressed-input read must skip a FIFO");
}

/// Regression: preserves the externally observable `compressed_input_refuses_symlink_to_fifo_none_without_hanging` behavior after the inline suite split.
#[test]
fn compressed_input_refuses_symlink_to_fifo_none_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let link = symlink_to(dir.path(), "a.gz", &fifo);
    let result = within_timeout(move || TestApi.read_file_for_compressed_input(&link, CAP));
    assert!(result.is_none());
}

/// Regression: preserves the externally observable `compressed_input_refuses_symlink_none` behavior after the inline suite split.
#[test]
fn compressed_input_refuses_symlink_none() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_regular(dir.path(), "real.gz", b"\x1f\x8b\x08\x00");
    let link = symlink_to(dir.path(), "a.gz", &target);
    assert!(
        TestApi.read_file_for_compressed_input(&link, CAP).is_none(),
        "must refuse a symlinked archive"
    );
}

/// Regression: preserves the externally observable `compressed_input_refuses_directory_none` behavior after the inline suite split.
#[test]
fn compressed_input_refuses_directory_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(TestApi
        .read_file_for_compressed_input(dir.path(), CAP)
        .is_none());
}

/// Regression: preserves the externally observable `compressed_input_refuses_dev_null_none` behavior after the inline suite split.
#[test]
fn compressed_input_refuses_dev_null_none() {
    assert!(TestApi
        .read_file_for_compressed_input(Path::new("/dev/null"), CAP)
        .is_none());
}

/// Regression: preserves the externally observable `compressed_input_regular_file_returns_bytes` behavior after the inline suite split.
#[test]
fn compressed_input_regular_file_returns_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "a.bin", b"PK\x03\x04payload");
    let bytes = TestApi
        .read_file_for_compressed_input(&path, CAP)
        .expect("regular file must read");
    assert_eq!(bytes, b"PK\x03\x04payload");
}

// ── read_file_windowed_mmap (windowed scan path) ────────────────────

// The windowed-mmap path expresses a refusal as `Some(0)`: zero windows
// scanned, rather than `None`: per its contract that is an already-counted
// unreadable skip that must NOT invite the caller to reopen and stream the
// file (a bare `None` means "mmap unavailable, try the non-mmap path"). Either
// way the special file is opened through `open_file_safe`, refused, and never
// read; the assertion is that ZERO windows reach the scanner.

/// Regression: preserves the externally observable `windowed_refuses_fifo_zero_windows_without_hanging` behavior after the inline suite split.
#[test]
fn windowed_refuses_fifo_zero_windows_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || TestApi.read_file_windowed_mmap_len(&fifo, 1024, 32));
    assert_eq!(
        result,
        Some(0),
        "a FIFO must yield zero windows, never hang"
    );
}

/// Regression: preserves the externally observable `windowed_refuses_symlink_zero_windows` behavior after the inline suite split.
#[test]
fn windowed_refuses_symlink_zero_windows() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_regular(dir.path(), "real.txt", b"x".repeat(4096).as_slice());
    let link = symlink_to(dir.path(), "link.txt", &target);
    assert_eq!(
        TestApi.read_file_windowed_mmap_len(&link, 1024, 32),
        Some(0),
        "a symlink must yield zero windows"
    );
}

/// Regression: preserves the externally observable `windowed_refuses_dev_null_zero_windows` behavior after the inline suite split.
#[test]
fn windowed_refuses_dev_null_zero_windows() {
    assert_eq!(
        TestApi.read_file_windowed_mmap_len(Path::new("/dev/null"), 1024, 32),
        Some(0)
    );
}

/// Regression: preserves the externally observable `windowed_regular_file_returns_windows` behavior after the inline suite split.
#[test]
fn windowed_regular_file_returns_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(
        dir.path(),
        "big.txt",
        b"password = hunter2longvalue\n".repeat(64).as_slice(),
    );
    let n = TestApi
        .read_file_windowed_mmap_len(&path, 1024, 32)
        .expect("regular file must mmap");
    assert!(
        n > 0,
        "a non-empty regular file must produce at least one window"
    );
}

// ── read_file_mmap_for_test ─────────────────────────────────────────

/// Regression: preserves the externally observable `mmap_refuses_fifo_none_without_hanging` behavior after the inline suite split.
#[test]
fn mmap_refuses_fifo_none_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || TestApi.read_file_mmap(&fifo));
    assert!(result.is_none(), "mmap read must skip a FIFO");
}

/// Regression: preserves the externally observable `mmap_regular_text_file_returns_exact_text` behavior after the inline suite split.
#[test]
fn mmap_regular_text_file_returns_exact_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"AKIAIOSFODNN7EXAMPLE\n");
    assert_eq!(
        TestApi.read_file_mmap(&path).as_deref(),
        Some("AKIAIOSFODNN7EXAMPLE\n")
    );
}

// ── read_file_safe_capped ───────────────────────────────────────────

/// Regression: preserves the externally observable `safe_capped_refuses_fifo_err_without_hanging` behavior after the inline suite split.
#[test]
fn safe_capped_refuses_fifo_err_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || TestApi.read_file_safe_capped(&fifo, CAP).is_err());
    assert!(result, "capped read must error on a FIFO");
}

/// Regression: preserves the externally observable `safe_capped_refuses_symlink_err` behavior after the inline suite split.
#[test]
fn safe_capped_refuses_symlink_err() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_regular(dir.path(), "real.txt", b"hello");
    let link = symlink_to(dir.path(), "link.txt", &target);
    assert!(
        TestApi.read_file_safe_capped(&link, CAP).is_err(),
        "capped read must refuse a symlink"
    );
}

/// Regression: preserves the externally observable `safe_capped_refuses_dev_null_err` behavior after the inline suite split.
#[test]
fn safe_capped_refuses_dev_null_err() {
    assert!(TestApi
        .read_file_safe_capped(Path::new("/dev/null"), CAP)
        .is_err());
}

/// Regression: preserves the externally observable `safe_capped_regular_file_returns_exact_bytes` behavior after the inline suite split.
#[test]
fn safe_capped_regular_file_returns_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"AKIAIOSFODNN7EXAMPLE");
    let bytes = TestApi.read_file_safe_capped(&path, 32).unwrap();
    assert_eq!(bytes, b"AKIAIOSFODNN7EXAMPLE");
}
