//! Special-file safety at the single read-open boundary (`open_file_safe`).

use super::super::support::{make_fifo, within_timeout, write_regular};
use keyhog_sources::testing::TestApi;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// ── FIFO: refused, and never blocks ─────────────────────────────────

/// Regression: preserves the externally observable `open_file_safe_refuses_fifo_without_hanging` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let err = within_timeout(move || TestApi.open_file_safe(&fifo)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// Regression: preserves the externally observable `open_file_safe_fifo_error_names_non_regular` behavior after the inline suite split.
#[test]
fn open_file_safe_fifo_error_names_non_regular() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let err = within_timeout(move || TestApi.open_file_safe(&fifo)).unwrap_err();
    assert!(
        err.to_string().contains("non-regular"),
        "error must name the cause, got: {err}"
    );
}

/// Regression: preserves the externally observable `read_file_safe_refuses_fifo_without_hanging` behavior after the inline suite split.
#[test]
fn read_file_safe_refuses_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || TestApi.read_file_safe_capped(&fifo, 0));
    assert!(result.is_err(), "read_file_safe must refuse a FIFO");
}

/// Regression: preserves the externally observable `read_file_prefix_safe_refuses_fifo_without_hanging` behavior after the inline suite split.
#[test]
fn read_file_prefix_safe_refuses_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || {
        let mut buf = [0u8; 64];
        TestApi.read_file_prefix_safe(&fifo, &mut buf)
    });
    assert!(result.is_err(), "read_file_prefix_safe must refuse a FIFO");
}

/// Regression: preserves the externally observable `read_file_mmap_returns_none_for_fifo_without_hanging` behavior after the inline suite split.
#[test]
fn read_file_mmap_returns_none_for_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let result = within_timeout(move || TestApi.read_file_mmap(&fifo));
    assert!(result.is_none(), "read_file_mmap must skip (None) a FIFO");
}

/// Regression: preserves the externally observable `fifo_refused_by_type_even_with_writer_present` behavior after the inline suite split.
#[test]
fn fifo_refused_by_type_even_with_writer_present() {
    // A keep-alive O_RDWR fd means a blocking open WOULD succeed, proving the
    // refusal is by file TYPE (is_file == false), not merely the no-writer
    // hang the O_NONBLOCK flag covers.
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: open(2) the FIFO read-write non-blocking; closed below.
    let keepalive = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
    assert!(keepalive >= 0, "keep-alive open failed");
    let probe = fifo.clone();
    let err = within_timeout(move || TestApi.open_file_safe(&probe)).unwrap_err();
    // SAFETY: closing the descriptor opened just above.
    unsafe { libc::close(keepalive) };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

// ── Devices: refused (no streaming /dev/zero, no /dev/null read) ─────

/// Regression: preserves the externally observable `open_file_safe_refuses_dev_null` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_dev_null() {
    let err = TestApi.open_file_safe(Path::new("/dev/null")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// Regression: preserves the externally observable `open_file_safe_refuses_dev_zero_so_it_cannot_stream` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_dev_zero_so_it_cannot_stream() {
    // /dev/zero would otherwise stream up to the read cap of zero bytes; the
    // boundary refusal means we never enter the read at all.
    let err = TestApi.open_file_safe(Path::new("/dev/zero")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

/// Regression: preserves the externally observable `read_file_safe_refuses_dev_null` behavior after the inline suite split.
#[test]
fn read_file_safe_refuses_dev_null() {
    assert!(TestApi
        .read_file_safe_capped(Path::new("/dev/null"), 0)
        .is_err());
}

// ── Unix domain socket: refused ─────────────────────────────────────

/// Regression: preserves the externally observable `open_file_safe_refuses_unix_socket` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_unix_socket() {
    // A socket is refused at the `open(2)` syscall itself (ENXIO, surfaced as
    // an `Uncategorized` kind) BEFORE the metadata guard runs, a FIFO/device
    // instead opens then trips the `is_file()` guard (`InvalidInput`). Either
    // way the contract is the same: a non-regular file never reaches a read.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    assert!(
        TestApi.open_file_safe(&sock).is_err(),
        "a unix-domain socket must be refused"
    );
}

/// Regression: preserves the externally observable `read_file_safe_refuses_unix_socket` behavior after the inline suite split.
#[test]
fn read_file_safe_refuses_unix_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    assert!(TestApi.read_file_safe_capped(&sock, 0).is_err());
}

// ── Directory: refused by the is_file() guard (never a content read) ─

/// Regression: preserves the externally observable `open_file_safe_refuses_directory` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_directory() {
    let dir = tempfile::tempdir().unwrap();
    let err = TestApi.open_file_safe(dir.path()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

// ── Symlinks: O_NOFOLLOW refusal preserved (regular + FIFO targets) ──

/// Regression: preserves the externally observable `open_file_safe_refuses_symlink_to_regular_file` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_symlink_to_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = write_regular(dir.path(), "real.txt", b"secret = abc123def456");
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        TestApi.open_file_safe(&link).is_err(),
        "O_NOFOLLOW must refuse a symlinked regular file"
    );
}

/// Regression: preserves the externally observable `open_file_safe_refuses_symlink_to_fifo_without_hanging` behavior after the inline suite split.
#[test]
fn open_file_safe_refuses_symlink_to_fifo_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = make_fifo(dir.path(), "pipe");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&fifo, &link).unwrap();
    let result = within_timeout(move || TestApi.open_file_safe(&link));
    assert!(result.is_err(), "a symlink to a FIFO must be refused");
}

// ── Regular files: the guard does NOT regress ordinary reads ─────────

/// Regression: preserves the externally observable `open_file_safe_accepts_regular_file` behavior after the inline suite split.
#[test]
fn open_file_safe_accepts_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"hello");
    let mut file = TestApi
        .open_file_safe(&path)
        .expect("regular file must open");
    let mut s = String::new();
    file.read_to_string(&mut s).unwrap();
    assert_eq!(s, "hello");
}

/// The metadata returned by safe-open belongs to the validated descriptor, not
/// to a path that can be replaced after open.
#[test]
fn open_file_safe_metadata_is_bound_to_opened_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "opened.txt", b"first");
    let moved_path = dir.path().join("moved.txt");
    let (mut file, metadata) = TestApi
        .open_file_safe_with_metadata(&path)
        .expect("regular file and metadata must open");

    std::fs::rename(&path, &moved_path).unwrap();
    std::fs::write(&path, b"replacement-is-longer").unwrap();

    assert_eq!(metadata.len(), 5);
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "first");
}

/// The advisory-flock DoS / torn-write guard is enforced by `open_file_safe`
/// (`LOCK_SH | LOCK_NB` fails closed when another owner holds the file
/// exclusively). That is the SINGLE owner of the guard: the per-read-path
/// re-flocks are redundant, because a `LOCK_SH` already held by
/// `open_file_safe` blocks any new `LOCK_EX`, so a re-request can catch
/// nothing new. Pin the behavior at the owner AND through `read_file_mmap`
/// so removing the redundant re-flock can never silently drop the skip.
#[cfg(unix)]
/// Regression: preserves the externally observable `externally_exclusive_locked_file_is_refused_by_open_and_mmap` behavior after the inline suite split.
#[test]
fn externally_exclusive_locked_file_is_refused_by_open_and_mmap() {
    use std::os::unix::io::AsRawFd;
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "locked.txt", b"aws_secret = hunter2longvalue");
    // A SEPARATE open file description holds an exclusive advisory lock
    // exactly how a second process (or a torn writer) would. flock treats
    // distinct OFDs independently, so this conflicts even in-process.
    let holder = std::fs::File::open(&path).unwrap();
    assert_eq!(
        unsafe { libc::flock(holder.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0,
        "test setup must acquire the exclusive lock"
    );

    // Owner refuses to open (fail closed, not a torn-write scan).
    assert!(
        TestApi.open_file_safe(&path).is_err(),
        "open_file_safe must refuse a file another owner holds exclusively locked"
    );
    // The mmap read path opens via `open_file_safe`, so it must skip too
    // this directly guards the removal of raw.rs's redundant re-flock.
    assert!(
        TestApi.read_file_mmap(&path).is_none(),
        "read_file_mmap must skip an exclusively-locked file via open_file_safe's lock"
    );

    // Releasing the exclusive lock lets both succeed again.
    drop(holder);
    assert!(
        TestApi.open_file_safe(&path).is_ok(),
        "file opens once the exclusive lock is released"
    );
    assert!(
        TestApi.read_file_mmap(&path).is_some(),
        "mmap read succeeds once the exclusive lock is released"
    );
}

/// Regression: preserves the externally observable `open_file_safe_regular_file_reads_back_contents` behavior after the inline suite split.
#[test]
fn open_file_safe_regular_file_reads_back_contents() {
    // Proves O_NONBLOCK did not break a normal regular-file read.
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"token = ghp_example");
    let mut file = TestApi.open_file_safe(&path).unwrap();
    let mut s = String::new();
    file.read_to_string(&mut s).unwrap();
    assert_eq!(s, "token = ghp_example");
}

/// Regression: preserves the externally observable `read_file_safe_regular_file_returns_exact_bytes` behavior after the inline suite split.
#[test]
fn read_file_safe_regular_file_returns_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"AKIAIOSFODNN7EXAMPLE");
    let bytes = TestApi.read_file_safe_capped(&path, 20).unwrap();
    assert_eq!(bytes, b"AKIAIOSFODNN7EXAMPLE");
}

/// Regression: preserves the externally observable `read_file_prefix_safe_regular_file_returns_prefix` behavior after the inline suite split.
#[test]
fn read_file_prefix_safe_regular_file_returns_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"0123456789abcdef");
    let mut buf = [0u8; 8];
    let n = TestApi.read_file_prefix_safe(&path, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"01234567");
}

/// Regression: preserves the externally observable `read_file_mmap_regular_file_returns_exact_text` behavior after the inline suite split.
#[test]
fn read_file_mmap_regular_file_returns_exact_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "ok.txt", b"password = hunter2longvalue");
    assert_eq!(
        TestApi.read_file_mmap(&path).as_deref(),
        Some("password = hunter2longvalue")
    );
}

/// Regression: preserves the externally observable `open_file_safe_accepts_empty_regular_file` behavior after the inline suite split.
#[test]
fn open_file_safe_accepts_empty_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "empty.txt", b"");
    let mut file = TestApi
        .open_file_safe(&path)
        .expect("empty regular file must open");
    let mut s = String::new();
    file.read_to_string(&mut s).unwrap();
    assert_eq!(s, "");
}

/// Regression: preserves the externally observable `read_file_safe_empty_regular_file_is_empty` behavior after the inline suite split.
#[test]
fn read_file_safe_empty_regular_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_regular(dir.path(), "empty.txt", b"");
    let bytes = TestApi.read_file_safe_capped(&path, 0).unwrap();
    assert!(bytes.is_empty());
}
