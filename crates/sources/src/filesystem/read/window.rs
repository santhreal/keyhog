//! Overlapping-window slicer for files too large to scan in a single
//! pass. The mmap variant ([`read_file_windowed_mmap`]) is used by the
//! filesystem source; the pure helper ([`slice_into_windows`]) is the
//! unit-testable boundary arithmetic the mmap path delegates to.

use keyhog_core::SourceError;
use memmap2::MmapOptions;
use std::path::Path;

use super::raw::open_file_safe;
use super::MMAP_TOCTOU_SANITY_CAP_BYTES;

/// One scanning window over a large file: an absolute byte offset into
/// the original file plus the lossy-UTF-8 view of those bytes. The
/// orchestrator's match locations are translated through `offset` so
/// findings reference the right place in the source even though we
/// scanned a slice.
pub(in crate::filesystem) struct FileWindow {
    pub offset: usize,
    /// Number of newlines in `bytes[0..offset]` - the count of lines that
    /// fully precede this window's first byte. Added to a match's
    /// window-local line number so findings report the absolute file
    /// line, not the per-window one (the line analog of `offset`).
    pub base_line: usize,
    pub text: String,
}

/// Memory-map `path` and slice it into overlapping `window_size`-byte
/// windows with `overlap` bytes shared between consecutive windows. The
/// previous flow allocated a 64 MiB heap working buffer per big file
/// and re-read the overlap region through `seek+read`; mmap slices
/// the same region zero-copy at the kernel level and lets `madvise`
/// drive aggressive read-ahead.
///
/// Returns `None` when:
///   * the file cannot be opened safely (symlink guard, permission),
///   * the mmap call itself fails (typically a 0-byte file or a
///     filesystem that refuses mmap - falls through to the caller's
///     non-mmap windowed path).
///
/// Returns `Some(Vec::new())` when an advisory shared lock cannot be taken on
/// Unix: that is an already-counted unreadable skip, not permission for the
/// caller to reopen and stream the same locked file without a lock.
pub(in crate::filesystem) fn read_file_windowed_mmap(
    path: &Path,
    window_size: usize,
    overlap: usize,
) -> Option<Vec<FileWindow>> {
    let mut windows = Vec::new();
    let mut terminal_error = false;
    for_each_file_windowed_mmap(path, window_size, overlap, |row| match row {
        Ok(window) => {
            windows.push(window);
            true
        }
        Err(_error) => {
            terminal_error = true;
            true
        }
    })?;
    if terminal_error {
        return Some(Vec::new());
    }
    Some(windows)
}

/// Memory-map `path` and emit overlapping windows one at a time.
///
/// This is the production path. It keeps only the current decoded window live
/// instead of retaining every `String` in a `Vec<FileWindow>` before the scanner
/// sees the first chunk. The collecting sibling above remains for tests and
/// count-only facades.
pub(in crate::filesystem) fn for_each_file_windowed_mmap(
    path: &Path,
    window_size: usize,
    overlap: usize,
    mut emit: impl FnMut(Result<FileWindow, SourceError>) -> bool,
) -> Option<()> {
    debug_assert!(window_size > overlap, "window must exceed overlap");
    let file = match open_file_safe(path) {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot open large file for windowed mmap; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            let _continue_scan = emit(Err(windowed_mmap_error(
                path,
                format!("cannot open large file for windowed mmap ({error})"),
            )));
            return Some(());
        }
    };

    // Post-open re-stat: defeat the walker-stat-then-grow race. See
    // read_file_mmap for the full rationale + MMAP_TOCTOU_SANITY_CAP_BYTES
    // ceiling justification. Kimi sources-audit MEDIUM finding on the
    // windowed-mmap path. The walker decides which files reach this
    // function based on its own size budget; this cap is a defense
    // against the file growing AFTER the walker's stat completed.
    if let Ok(meta) = file.metadata() {
        // LAW10: failed post-open metadata probe skips only mmap TOCTOU optimization; caller falls back to bounded reads.
        if meta.len() > MMAP_TOCTOU_SANITY_CAP_BYTES {
            tracing::warn!(
                path = %path.display(),
                live_size = meta.len(),
                cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
                "refusing to windowed-mmap file: live size exceeds sanity cap (likely TOCTOU growth)"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            let _continue_scan = emit(Err(windowed_mmap_error(
                path,
                format!(
                    "live size {} exceeded the {}-byte windowed mmap sanity cap",
                    meta.len(),
                    MMAP_TOCTOU_SANITY_CAP_BYTES
                ),
            )));
            return Some(());
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory lock FFI call. A failure means
        // someone else holds an exclusive lock; do not reopen and scan the
        // file unlocked through the caller's buffered fallback.
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            tracing::warn!(
                path = %path.display(),
                "large file is locked by another process; skipping to avoid scanning a torn write"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            let _continue_scan = emit(Err(windowed_mmap_error(
                path,
                "large file is locked by another process",
            )));
            return Some(());
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the
    // mapping call, and we drop the mmap before this function returns
    // (the windows we hand back are owned `String` copies).
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot windowed-mmap file; falling back to buffered read"
            );
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                // SAFETY: `file` is still a valid open `File`;
                // `LOCK_UN` releases the advisory shared lock taken
                // above before bailing out of the windowed-mmap path.
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
            return None;
        }
    };

    #[cfg(unix)]
    {
        // SAFETY: madvise on a valid mmap range; ignored if the kernel
        // doesn't honor the hint. SEQUENTIAL doubles readahead and
        // disables LRU protection on already-read pages - we walk
        // front-to-back and never revisit, so eviction is correct.
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut libc::c_void,
                mmap.len(),
                libc::MADV_SEQUENTIAL,
            );
        }
    }

    for_each_window(&mmap, window_size, overlap, |window| emit(Ok(window)));

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: Simple advisory unlock FFI call.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    Some(())
}

fn windowed_mmap_error(path: &Path, reason: impl std::fmt::Display) -> SourceError {
    SourceError::Other(format!(
        "failed to scan large file '{}': {reason}; file was not scanned",
        path.display()
    ))
}

/// Count newlines in `slice` via `memchr` (SIMD-accelerated). Used to
/// advance each window's absolute `base_line` by exactly the lines in its
/// non-overlapping stride region, so the whole file is scanned for `\n`
/// once across all windows rather than re-counted per window.
#[inline]
fn bytecount_newlines(slice: &[u8]) -> usize {
    memchr::memchr_iter(b'\n', slice).count()
}

/// Pure helper: split `bytes` into `window_size`-byte windows that
/// share `overlap` bytes with the next window. Each window is decoded
/// lossily as UTF-8 and tagged with its starting byte offset in
/// `bytes`. Extracted so we can unit-test the boundary arithmetic
/// without conjuring 64 MiB+ files on the test runner.
///
/// Invariants:
///   * window N starts at offset `N * (window_size - overlap)`,
///   * the last window may be shorter than `window_size`,
///   * for `bytes.len() <= window_size` the function returns exactly
///     one window covering the whole input,
///   * for `bytes.is_empty()` the function returns an empty `Vec`,
///   * consecutive windows always share exactly `overlap` bytes (the
///     reason: a secret straddling the cut would otherwise be missed).
pub(in crate::filesystem) fn slice_into_windows(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
) -> Vec<FileWindow> {
    let mut out = Vec::with_capacity(
        bytes
            .len()
            .div_ceil(window_size.saturating_sub(overlap).max(1)),
    );
    for_each_window(bytes, window_size, overlap, |window| {
        out.push(window);
        true
    });
    out
}

fn for_each_window(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
    mut emit: impl FnMut(FileWindow) -> bool,
) -> bool {
    assert!(window_size > overlap, "window must exceed overlap");
    if bytes.is_empty() {
        return true;
    }
    let stride = window_size - overlap;
    let total = bytes.len();
    let mut offset = 0usize;
    // Running count of newlines in `bytes[0..offset]`. Advanced by the
    // newlines in each non-overlapping stride region exactly once, so the
    // whole slice is scanned for `\n` a single time across all windows
    // (no per-window re-count). This is the window's absolute base line.
    let mut base_line = 0usize;
    while offset < total {
        let end = (offset + window_size).min(total);
        let slice = &bytes[offset..end];
        // `from_utf8_lossy` returns Cow::Borrowed when the slice is
        // valid UTF-8; we still own the result via `into_owned` because
        // SensitiveString needs ownership. The lossy fallback is what
        // makes us robust to partial multi-byte sequences at window
        // boundaries (an emoji split across two windows survives via
        // `U+FFFD` rather than failing the decode).
        let text = String::from_utf8_lossy(slice).into_owned();
        if !emit(FileWindow {
            offset,
            base_line,
            text,
        }) {
            return false;
        }
        // Stop once we've reached the tail; stride-from-here would
        // start past EOF.
        if end >= total {
            return true;
        }
        let next = offset + stride;
        base_line += bytecount_newlines(&bytes[offset..next]);
        offset = next;
    }
    true
}
