//! Shared fixtures for the special-file safety tests.
//!
//! The filesystem read boundary (`open_file_safe`) and every entry point above
//! it must refuse non-regular files (FIFO, socket, device, symlink) WITHOUT
//! blocking — a plain `open(O_RDONLY)` of a writer-less FIFO hangs forever.
//! Several test modules under `crate::filesystem` assert that contract (the read
//! primitive in `read::tests`, the ZIP archive opens in `extract::archive`), so
//! the FIFO fabrication + no-hang watchdog live here ONCE instead of being copied
//! into each (no-duplication).

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Run `f` on a worker thread and REQUIRE it to finish within 10s. A bare
/// blocking `open(O_RDONLY)` of a writer-less FIFO never returns, so this is the
/// regression guard proving a read entry point returns instead of hanging.
pub(crate) fn within_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("a read entry point must NOT block on a special file (missing O_NONBLOCK?)")
}

/// Create a FIFO (named pipe) at `dir/name` and return its path.
pub(crate) fn make_fifo(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: mkfifo(2) with an owner-only mode on a fresh temp path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
    path
}

/// Create a symlink at `dir/link` pointing at `target` and return the link path.
pub(crate) fn symlink_to(dir: &Path, link: &str, target: &Path) -> PathBuf {
    let path = dir.join(link);
    std::os::unix::fs::symlink(target, &path).unwrap();
    path
}

/// Write a regular file at `dir/name` with `bytes` and return its path.
pub(crate) fn write_regular(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}
