//! Overlapping-window slicer for files too large to scan in a single
//! pass. The mmap variant ([`read_file_windowed_mmap`]) is used by the
//! filesystem source; the pure helper ([`slice_into_windows`]) is the
//! unit-testable boundary arithmetic the mmap path delegates to.

use keyhog_core::SourceError;
use memmap2::MmapOptions;
use std::fs::File;
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

pub(in crate::filesystem) enum WindowedMmapOutcome {
    Consumed,
    Fallback(File),
}

/// Host page size, queried once. `MADV_DONTNEED` only acts on whole pages, so
/// the release prefix below has to be rounded with the real value rather than
/// an assumed 4 KiB (a 16 KiB-page host would reject every misaligned call).
#[cfg(unix)]
fn page_size() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CACHED: AtomicUsize = AtomicUsize::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    // SAFETY: `sysconf` is thread-safe and takes no pointers.
    let probed = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(probed).unwrap_or(0).max(1);
    CACHED.store(size, Ordering::Relaxed);
    size
}

/// Releases the pages of a windowed mapping the slicer has already walked past.
///
/// The slicer moves strictly front-to-back and never revisits a byte below the
/// current window's start, but the pages it has read stay resident for the
/// lifetime of the mapping, so peak RSS grew with the *file* size: scanning one
/// 300 MiB file kept all 300 MiB of mapped pages live on top of the decoded
/// window text. `MADV_DONTNEED` drops the resident copy of a read-only private
/// file mapping; the bytes remain readable (a later access re-faults them from
/// the file), so this can only change residency, never what gets scanned.
///
/// `released_upto` tracks the high-water mark so each page is advised exactly
/// once, keeping this O(file) rather than O(windows x file).
#[cfg(unix)]
struct MappedPrefixReleaser {
    base: *mut libc::c_void,
    released_upto: usize,
}

#[cfg(unix)]
impl MappedPrefixReleaser {
    fn new(mmap: &memmap2::Mmap) -> Self {
        Self {
            base: mmap.as_ptr() as *mut libc::c_void,
            released_upto: 0,
        }
    }

    /// `dead_below` is the offset of the next window's first byte: everything
    /// under it is finished with.
    fn release_below(&mut self, dead_below: usize) {
        let page = page_size();
        // Round DOWN: the partial page containing `dead_below` still holds
        // bytes the next window reads.
        let aligned = dead_below - (dead_below % page);
        if aligned <= self.released_upto {
            return;
        }
        let len = aligned - self.released_upto;
        // SAFETY: `released_upto` starts at 0 and only ever advances to a
        // page-aligned offset, so `base + released_upto` is a page-aligned
        // address inside the live mapping owned by the caller, and
        // `released_upto + len == aligned` stays within it. Advisory only: a
        // failure leaves the pages resident, which is merely the old behaviour.
        unsafe {
            libc::madvise(self.base.add(self.released_upto), len, libc::MADV_DONTNEED);
        }
        self.released_upto = aligned;
    }
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
/// Unix or the post-open metadata probe fails: that is an already-counted
/// unreadable skip, not permission for the caller to reopen and stream the
/// same locked/unproven file without the hard mmap sanity-cap proof.
pub(in crate::filesystem) fn read_file_windowed_mmap(
    path: &Path,
    window_size: usize,
    overlap: usize,
) -> Option<Vec<FileWindow>> {
    let mut windows = Vec::new();
    let mut terminal_error = false;
    match for_each_file_windowed_mmap(path, window_size, overlap, |row| match row {
        Ok(window) => {
            windows.push(window);
            true
        }
        Err(_error) => {
            terminal_error = true;
            true
        }
    }) {
        WindowedMmapOutcome::Consumed => {}
        WindowedMmapOutcome::Fallback(_) => return None,
    }
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
) -> WindowedMmapOutcome {
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
            return WindowedMmapOutcome::Consumed;
        }
    };

    // Post-open re-stat: defeat the walker-stat-then-grow race. See
    // read_file_mmap for the full rationale + MMAP_TOCTOU_SANITY_CAP_BYTES
    // ceiling justification. Kimi sources-audit MEDIUM finding on the
    // windowed-mmap path. The walker decides which files reach this
    // function based on its own size budget; this cap is a defense
    // against the file growing AFTER the walker's stat completed.
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot stat opened large file for windowed mmap sanity cap; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            let _continue_scan = emit(Err(windowed_mmap_error(
                path,
                format!("cannot stat opened large file for windowed mmap ({error})"),
            )));
            return WindowedMmapOutcome::Consumed;
        }
    };
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
        return WindowedMmapOutcome::Consumed;
    }
    // No re-flock: `open_file_safe` already holds the advisory LOCK_SH on this
    // fd (a shared lock we hold blocks any new LOCK_EX), so this was a redundant
    // syscall with a dead "locked by another process" branch. The lock persists
    // until the deliberate LOCK_UN after the windowed mmap below. ONE owner of
    // the flock guard: `open_file_safe` (contract pinned by
    // `externally_exclusive_locked_file_is_refused_by_open_and_mmap`).

    // SAFETY: the mapping is read-only, the `File` lives through the
    // mapping call, and we drop the mmap before this function returns
    // (the windows we hand back are owned `String` copies). Do not pass the
    // earlier stat length into mmap: a shrink between stat and map can make an
    // explicit length extend past live EOF. Map the current kernel length, then
    // enforce the hard cap before touching bytes.
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot windowed-mmap file; falling back to buffered read"
            );
            return WindowedMmapOutcome::Fallback(file);
        }
    };
    let mapped_len = match u64::try_from(mmap.len()) {
        Ok(len) => len,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                mapped_len = mmap.len(),
                %error,
                "cannot represent mapped length for windowed mmap sanity cap; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            let _continue_scan = emit(Err(windowed_mmap_error(
                path,
                "mapped length is not representable for windowed mmap",
            )));
            return WindowedMmapOutcome::Consumed;
        }
    };
    if mapped_len > MMAP_TOCTOU_SANITY_CAP_BYTES {
        tracing::warn!(
            path = %path.display(),
            live_size = mapped_len,
            cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
            "refusing windowed mmap: mapped length exceeds sanity cap"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        let _continue_scan = emit(Err(windowed_mmap_error(
            path,
            format!(
                "mapped length {} exceeds the {}-byte windowed mmap sanity cap; file was not scanned",
                mapped_len,
                MMAP_TOCTOU_SANITY_CAP_BYTES
            ),
        )));
        return WindowedMmapOutcome::Consumed;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let allocated_bytes = meta.blocks().saturating_mul(512);
        let advice = if allocated_bytes < meta.len() {
            // Sparse holes need no storage read-ahead. Sequential advice can
            // fault hundreds of MiB of zero-backed pages ahead of the one live
            // scanner window, multiplying RSS without reducing I/O.
            libc::MADV_RANDOM
        } else {
            // Dense files are consumed front-to-back once; sequential readahead
            // remains the throughput path and released prefixes lose LRU
            // protection immediately below.
            libc::MADV_SEQUENTIAL
        };
        // SAFETY: advisory call over the complete live read-only mapping.
        unsafe {
            libc::madvise(mmap.as_ptr() as *mut libc::c_void, mmap.len(), advice);
        }
    }

    // Release each window's pages as the slicer leaves them behind, so a
    // multi-hundred-MiB file costs one window of residency instead of its whole
    // length. On non-unix the closure is a no-op and behaviour is unchanged.
    #[cfg(unix)]
    let mut releaser = MappedPrefixReleaser::new(&mmap);
    for_each_window(
        &mmap,
        window_size,
        overlap,
        |window| emit(Ok(window)),
        |dead_below| {
            #[cfg(unix)]
            releaser.release_below(dead_below);
            #[cfg(not(unix))]
            let _ = dead_below;
        },
    );

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: Simple advisory unlock FFI call.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    WindowedMmapOutcome::Consumed
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
    for_each_window(
        bytes,
        window_size,
        overlap,
        |window| {
            out.push(window);
            true
        },
        // Pure in-memory slicing owns no mapping to release.
        |_dead_below| {},
    );
    out
}

/// `on_advance(dead_below)` fires each time the cursor moves forward, naming the
/// offset below which no later window can read. The mmap path uses it to hand
/// those pages back so residency tracks the window, not the file; the pure
/// slicer ignores it.
fn for_each_window(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
    mut emit: impl FnMut(FileWindow) -> bool,
    mut on_advance: impl FnMut(usize),
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
        // `offset` is the next window's first byte, so nothing below it will be
        // read again: this window's non-overlapping stride is now dead. The
        // overlap region stays mapped precisely because the next window reads it.
        on_advance(offset);
    }
    true
}
