//! Shared fixtures for filesystem read boundary tests (Unix-only).

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Run `f` on a worker thread and REQUIRE it to finish within 10s. A bare
/// blocking `open(O_RDONLY)` of a writer-less FIFO never returns, so this is the
/// regression guard proving a read entry point returns instead of hanging.
pub fn within_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if tx.send(f()).is_err() {
            eprintln!("special-file watchdog receiver closed before the worker completed");
        }
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("a read entry point must NOT block on a special file (missing O_NONBLOCK?)")
}

/// Create a FIFO (named pipe) at `dir/name` and return its path.
pub fn make_fifo(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: mkfifo(2) with an owner-only mode on a fresh temp path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
    path
}

/// Create a symlink at `dir/link` pointing at `target` and return the link path.
pub fn symlink_to(dir: &Path, link: &str, target: &Path) -> PathBuf {
    let path = dir.join(link);
    std::os::unix::fs::symlink(target, &path).unwrap();
    path
}

/// Write a regular file at `dir/name` with `bytes` and return its path.
pub fn write_regular(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}
