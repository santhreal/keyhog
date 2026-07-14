//! Public single-file safe-read entry point for non-walker callers (e.g.
//! `keyhog watch`) so they read a file through the SAME guarded path the scan
//! walker uses instead of a raw `std::fs::read`, which follows symlinks out of
//! the scanned tree, blocks forever on a FIFO, and OOMs on a large or
//! TOCTOU-grown file. Sharing the walker's read keeps recall/behavior parity
//! (Law 10) and avoids re-inventing a weaker read (no-duplication).

use std::path::Path;

/// Read `path`'s raw bytes through the walker's guarded read: an
/// `O_NOFOLLOW` + `O_NONBLOCK` open followed by a post-open regular-file
/// `fstat` that refuses a FIFO / socket / device with
/// [`std::io::ErrorKind::InvalidInput`] (a FIFO opened blocking would otherwise
/// hang the caller forever), bounded by a byte cap.
///
/// `max_bytes` is the caller's size budget; `0` means "no caller budget, only
/// the walker's hard 2 GiB TOCTOU sanity ceiling", a file exceeding the
/// effective cap returns [`std::io::ErrorKind::InvalidData`] rather than being
/// read into unbounded memory. A file that vanished between a caller's event
/// and this read surfaces as [`std::io::ErrorKind::NotFound`].
pub fn read_file_safe_bytes(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    crate::filesystem::read_file_safe(path, max_bytes)
}

#[cfg(all(test, unix))]
#[path = "../tests/unit/safe_read.rs"]
mod tests;
