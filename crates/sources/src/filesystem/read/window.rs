//! Overlapping-window slicer for files too large to scan in a single
//! pass. The mmap variant ([`read_file_windowed_mmap`]) is used by the
//! filesystem source; the pure helper ([`slice_into_windows`]) is the
//! unit-testable boundary arithmetic the mmap path delegates to.

use keyhog_core::{SensitiveString, SourceError};
use memmap2::MmapOptions;
use std::fs::File;
use std::path::Path;

use super::raw::open_file_safe_with_metadata;
use super::MMAP_TOCTOU_SANITY_CAP_BYTES;

/// One scanning window over a large file: an absolute byte offset into
/// the original file plus the lossy-UTF-8 view of those bytes. Repeated
/// byte-identical windows share one owned text allocation.
pub(in crate::filesystem) struct FileWindow {
    pub offset: usize,
    /// Number of newlines in `bytes[0..offset]` - the count of lines that
    /// fully precede this window's first byte. Added to a match's
    /// window-local line number so findings report the absolute file
    /// line, not the per-window one (the line analog of `offset`).
    pub base_line: usize,
    pub text: SensitiveString,
}

const WINDOW_TEXT_CACHE_CAP: usize = 8;

struct WindowTextCacheEntry {
    fingerprint: [u8; 32],
    text: SensitiveString,
}

struct WindowTextCache {
    entries: std::collections::VecDeque<WindowTextCacheEntry>,
}

impl WindowTextCache {
    fn new() -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(WINDOW_TEXT_CACHE_CAP),
        }
    }

    fn text(&mut self, bytes: &[u8]) -> SensitiveString {
        let Ok(text) = std::str::from_utf8(bytes) else {
            return String::from_utf8_lossy(bytes).into_owned().into();
        };
        let fingerprint = window_fingerprint(bytes);
        if let Some(position) = self
            .entries
            .iter()
            .position(|entry| entry.fingerprint == fingerprint && entry.text.as_bytes() == bytes)
        {
            if let Some(entry) = self.entries.remove(position) {
                let text = entry.text.clone();
                self.entries.push_back(entry);
                return text;
            }
        }
        let text: SensitiveString = text.to_owned().into();
        if self.entries.len() == WINDOW_TEXT_CACHE_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(WindowTextCacheEntry {
            fingerprint,
            text: text.clone(),
        });
        text
    }
}

fn window_fingerprint(bytes: &[u8]) -> [u8; 32] {
    const SAMPLE_COUNT: usize = 8;
    const SAMPLE_BYTES: usize = 64;

    let mut hasher = blake3::Hasher::new();
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    if bytes.len() <= SAMPLE_COUNT * SAMPLE_BYTES {
        hasher.update(bytes);
    } else {
        let max_start = bytes.len() - SAMPLE_BYTES;
        for sample in 0..SAMPLE_COUNT {
            let start = max_start * sample / (SAMPLE_COUNT - 1);
            hasher.update(&bytes[start..start + SAMPLE_BYTES]);
        }
    }
    *hasher.finalize().as_bytes()
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
    let size = usize::try_from(probed).unwrap_or(0).max(1); // LAW10: an unavailable OS page-size probe falls back to a one-byte release granularity; reads and findings are unchanged.
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

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SparseRange {
    start: u64,
    end: u64,
}

#[cfg(target_os = "linux")]
fn seek_extent(file: &File, offset: u64, whence: libc::c_int) -> std::io::Result<Option<u64>> {
    use std::os::fd::AsRawFd;

    let offset = libc::off_t::try_from(offset).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sparse extent offset is not representable by off_t",
        )
    })?;
    loop {
        // SAFETY: `file` owns a live regular-file descriptor and lseek does not
        // dereference user pointers.
        let found = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
        if found >= 0 {
            return Ok(Some(found as u64));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if whence == libc::SEEK_DATA && error.raw_os_error() == Some(libc::ENXIO) {
            return Ok(None);
        }
        return Err(error);
    }
}

#[cfg(target_os = "linux")]
fn discover_sparse_ranges_with(
    file_len: u64,
    overlap: u64,
    mut seek: impl FnMut(u64, libc::c_int) -> std::io::Result<Option<u64>>,
) -> std::io::Result<Vec<SparseRange>> {
    let mut ranges: Vec<SparseRange> = Vec::new();
    let mut cursor = 0u64;
    while cursor < file_len {
        let Some(data_start) = seek(cursor, libc::SEEK_DATA)? else {
            break;
        };
        if data_start < cursor || data_start >= file_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "filesystem returned an invalid SEEK_DATA offset",
            ));
        }
        let Some(hole_start) = seek(data_start, libc::SEEK_HOLE)? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "filesystem returned no SEEK_HOLE offset after data",
            ));
        };
        if hole_start <= data_start {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "filesystem returned a non-advancing SEEK_HOLE offset",
            ));
        }

        let expanded = SparseRange {
            start: data_start.saturating_sub(overlap),
            end: hole_start
                .min(file_len)
                .saturating_add(overlap)
                .min(file_len),
        };
        if let Some(previous) = ranges.last_mut() {
            if expanded.start <= previous.end {
                previous.end = previous.end.max(expanded.end);
            } else {
                ranges.push(expanded);
            }
        } else {
            ranges.push(expanded);
        }
        cursor = hole_start.min(file_len);
    }
    Ok(ranges)
}

#[cfg(target_os = "linux")]
fn discover_sparse_ranges(
    file: &File,
    file_len: u64,
    overlap: usize,
) -> std::io::Result<Vec<SparseRange>> {
    let overlap = u64::try_from(overlap).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "window overlap is not representable as a file offset",
        )
    })?;
    discover_sparse_ranges_with(file_len, overlap, |offset, whence| {
        seek_extent(file, offset, whence)
    })
}

#[cfg(target_os = "linux")]
fn rewind_after_extent_query(file: &File) -> std::io::Result<()> {
    match seek_extent(file, 0, libc::SEEK_SET)? {
        Some(0) => Ok(()),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "failed to rewind after sparse extent query",
        )),
    }
}

#[cfg(target_os = "linux")]
fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;

    while !buffer.is_empty() {
        match file.read_at(buffer, offset) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file ended while reading an allocated sparse extent",
                ));
            }
            Ok(read) => {
                offset = offset.saturating_add(read as u64);
                buffer = &mut buffer[read..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn for_each_sparse_window(
    file: &File,
    ranges: &[SparseRange],
    window_size: usize,
    overlap: usize,
    mut emit: impl FnMut(FileWindow) -> bool,
) -> Result<(), (std::io::Error, bool)> {
    let stride = window_size - overlap;
    let mut base_line = 0usize;
    let mut emitted = false;

    for range in ranges {
        let mut offset = range.start;
        while offset < range.end {
            let remaining = range.end - offset;
            let read_len = usize::try_from(remaining.min(window_size as u64)).map_err(|error| {
                (
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error),
                    emitted,
                )
            })?;
            let mut bytes = vec![0u8; read_len];
            read_exact_at(file, &mut bytes, offset).map_err(|error| (error, emitted))?;
            let absolute_offset = usize::try_from(offset).map_err(|error| {
                (
                    std::io::Error::new(std::io::ErrorKind::InvalidData, error),
                    emitted,
                )
            })?;
            let reached_range_end = read_len < window_size || offset + read_len as u64 >= range.end;
            let advanced_newlines = if reached_range_end {
                bytecount_newlines(&bytes)
            } else {
                bytecount_newlines(&bytes[..stride])
            };
            let text: SensitiveString = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
            }
            .into();
            emitted = true;
            if !emit(FileWindow {
                offset: absolute_offset,
                base_line,
                text,
            }) {
                return Ok(());
            }

            base_line += advanced_newlines;
            if reached_range_end {
                break;
            }
            offset += stride as u64;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sparse_buffered_fallback(
    file: File,
    path: &Path,
    error: std::io::Error,
    stage: &'static str,
    emit: &mut impl FnMut(Result<FileWindow, SourceError>) -> bool,
) -> WindowedMmapOutcome {
    tracing::warn!(
        path = %path.display(),
        %error,
        stage,
        "cannot use sparse extent streaming; falling back to buffered read"
    );
    if let Err(rewind_error) = rewind_after_extent_query(&file) {
        tracing::warn!(
            path = %path.display(),
            %rewind_error,
            "cannot rewind after sparse extent failure; skipping"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        let _continue_scan = emit(Err(windowed_mmap_error(
            path,
            format!("cannot rewind after sparse extent failure ({rewind_error})"),
        )));
        WindowedMmapOutcome::Consumed
    } else {
        WindowedMmapOutcome::Fallback(file)
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
    assert!(window_size > overlap, "window must exceed overlap");
    let (file, meta) = match open_file_safe_with_metadata(path) {
        Ok(opened) => opened,
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.blocks().saturating_mul(512) < meta.len() {
            #[cfg(target_os = "linux")]
            {
                let ranges = match discover_sparse_ranges(&file, meta.len(), overlap) {
                    Ok(ranges) => ranges,
                    Err(error) => {
                        return sparse_buffered_fallback(
                            file,
                            path,
                            error,
                            "extent discovery",
                            &mut emit,
                        );
                    }
                };
                if ranges.is_empty() {
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                    let _continue_scan = emit(Err(windowed_mmap_error(
                        path,
                        "sparse file has no allocated data; no bytes were scanned",
                    )));
                    return WindowedMmapOutcome::Consumed;
                }

                match for_each_sparse_window(&file, &ranges, window_size, overlap, |window| {
                    emit(Ok(window))
                }) {
                    Ok(()) => {}
                    Err((error, false)) => {
                        return sparse_buffered_fallback(
                            file,
                            path,
                            error,
                            "first extent read",
                            &mut emit,
                        );
                    }
                    Err((error, true)) => {
                        tracing::warn!(
                            path = %path.display(),
                            %error,
                            "cannot continue sparse extent read; stopping scan of this file"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        let _continue_scan = emit(Err(windowed_mmap_error(
                            path,
                            format!("cannot continue sparse extent read ({error})"),
                        )));
                    }
                }

                use std::os::fd::AsRawFd;
                // SAFETY: Simple advisory unlock FFI call.
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
                return WindowedMmapOutcome::Consumed;
            }

            #[cfg(not(target_os = "linux"))]
            return WindowedMmapOutcome::Fallback(file);
        }
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
            let _ = dead_below; // LAW10: cfg-only unused offset on platforms without page-release support; no read result is discarded.
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
pub(in crate::filesystem) fn for_each_window(
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
    let mut text_cache = WindowTextCache::new();
    while offset < total {
        let end = (offset + window_size).min(total);
        let slice = &bytes[offset..end];
        // Valid UTF-8 windows reuse a byte-identical allocation from the
        // bounded cache. Invalid boundary slices retain the lossy fallback.
        let text = text_cache.text(slice);
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
#[cfg(all(test, target_os = "linux"))]
mod sparse_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Write;
    use std::os::unix::fs::{FileExt, MetadataExt};

    fn scripted_ranges(
        file_len: u64,
        overlap: u64,
        script: Vec<(u64, libc::c_int, std::io::Result<Option<u64>>)>,
    ) -> std::io::Result<Vec<SparseRange>> {
        let mut script = VecDeque::from(script);
        let result = discover_sparse_ranges_with(file_len, overlap, |offset, whence| {
            let (expected_offset, expected_whence, result) =
                script.pop_front().expect("unexpected extent query");
            assert_eq!(offset, expected_offset);
            assert_eq!(whence, expected_whence);
            result
        });
        assert!(script.is_empty(), "not all expected extent queries ran");
        result
    }

    fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) {
        while !bytes.is_empty() {
            let written = file.write_at(bytes, offset).expect("write sparse data");
            assert_ne!(written, 0, "sparse data write made no progress");
            bytes = &bytes[written..];
            offset += written as u64;
        }
    }

    /// Sparse extent context must be merged before reading so nearby data is
    /// covered once rather than producing duplicate overlap-expanded ranges.
    #[test]
    fn overlap_expansion_merges_nearby_extents() {
        let ranges = scripted_ranges(
            2_000,
            100,
            vec![
                (0, libc::SEEK_DATA, Ok(Some(200))),
                (200, libc::SEEK_HOLE, Ok(Some(300))),
                (300, libc::SEEK_DATA, Ok(Some(450))),
                (450, libc::SEEK_HOLE, Ok(Some(500))),
                (500, libc::SEEK_DATA, Ok(Some(1_000))),
                (1_000, libc::SEEK_HOLE, Ok(Some(1_100))),
                (1_100, libc::SEEK_DATA, Ok(None)),
            ],
        )
        .expect("valid extent script");

        assert_eq!(
            ranges,
            vec![
                SparseRange {
                    start: 100,
                    end: 600
                },
                SparseRange {
                    start: 900,
                    end: 1_200
                }
            ]
        );
    }

    /// SEEK_DATA reports ENXIO for an all-hole file; that is successful empty
    /// coverage, not an extent-query error and not permission to read the hole.
    #[test]
    fn all_hole_extent_plan_is_empty() {
        let ranges = scripted_ranges(
            8 * 1024 * 1024,
            keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES as u64,
            vec![(0, libc::SEEK_DATA, Ok(None))],
        )
        .expect("all-hole extent plan");

        assert!(ranges.is_empty());
    }

    /// Unsupported or failed extent discovery must stay an error so the
    /// production caller selects its already-open buffered fallback.
    #[test]
    fn extent_query_errors_return_rewound_buffered_fallback() {
        let error = scripted_ranges(
            8 * 1024 * 1024,
            keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES as u64,
            vec![(
                0,
                libc::SEEK_DATA,
                Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "SEEK_DATA unsupported",
                )),
            )],
        )
        .expect_err("unsupported query must request fallback");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

        let file = tempfile::tempfile().expect("fallback tempfile");
        assert_eq!(
            seek_extent(&file, 17, libc::SEEK_SET).expect("move file cursor"),
            Some(17)
        );
        let mut emitted_error = false;
        let outcome = sparse_buffered_fallback(
            file,
            Path::new("sparse-fallback-test"),
            error,
            "extent discovery",
            &mut |_| {
                emitted_error = true;
                true
            },
        );
        let WindowedMmapOutcome::Fallback(file) = outcome else {
            panic!("extent-query failure did not select buffered fallback");
        };
        assert!(!emitted_error);
        assert_eq!(
            seek_extent(&file, 0, libc::SEEK_CUR).expect("query rewound cursor"),
            Some(0)
        );
    }

    /// A real sparse file must expose credentials in its first and last
    /// allocated blocks at exact logical offsets without materializing its hole.
    #[test]
    fn sparse_file_streams_start_and_end_data_with_bounded_windows() {
        const FILE_LEN: u64 = 32 * 1024 * 1024;
        const WINDOW_SIZE: usize = keyhog_core::DEFAULT_WINDOW_SIZE_BYTES;
        const OVERLAP: usize = keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES;
        const START_SECRET: &str = "START_CREDENTIAL=alpha\n";
        const END_SECRET: &str = "END_CREDENTIAL=omega";

        let mut sparse = tempfile::NamedTempFile::new().expect("sparse tempfile");
        sparse
            .as_file_mut()
            .set_len(FILE_LEN)
            .expect("set sparse length");
        write_all_at(sparse.as_file(), START_SECRET.as_bytes(), 0);
        let end_offset = FILE_LEN - END_SECRET.len() as u64;
        write_all_at(sparse.as_file(), END_SECRET.as_bytes(), end_offset);
        sparse.as_file_mut().flush().expect("flush sparse data");

        let metadata = sparse.as_file().metadata().expect("sparse metadata");
        assert!(
            metadata.blocks().saturating_mul(512) < FILE_LEN / 4,
            "test fixture did not remain sparse"
        );
        let ranges =
            discover_sparse_ranges(sparse.as_file(), FILE_LEN, OVERLAP).expect("query extents");
        let planned_bytes: u64 = ranges.iter().map(|range| range.end - range.start).sum();
        assert!(
            planned_bytes < FILE_LEN / 4,
            "extent plan materialized too much of the sparse hole: {planned_bytes} bytes"
        );

        let mut offsets = Vec::new();
        let mut emitted_bytes = 0usize;
        let mut largest_window = 0usize;
        let mut start_hits = Vec::new();
        let mut end_hits = Vec::new();
        let mut end_base_lines = Vec::new();
        let mut errors = Vec::new();
        let outcome = for_each_file_windowed_mmap(sparse.path(), WINDOW_SIZE, OVERLAP, |row| {
            match row {
                Ok(window) => {
                    offsets.push(window.offset);
                    emitted_bytes += window.text.len();
                    largest_window = largest_window.max(window.text.len());
                    if let Some(local) = window.text.find(START_SECRET) {
                        start_hits.push(window.offset + local);
                    }
                    if let Some(local) = window.text.find(END_SECRET) {
                        end_hits.push(window.offset + local);
                        end_base_lines.push(window.base_line);
                    }
                }
                Err(error) => errors.push(error.to_string()),
            }
            true
        });

        assert!(matches!(outcome, WindowedMmapOutcome::Consumed));
        assert!(errors.is_empty(), "sparse scan errors: {errors:?}");
        assert_eq!(start_hits, vec![0]);
        assert_eq!(end_hits, vec![end_offset as usize]);
        assert_eq!(end_base_lines, vec![1]);
        assert!(largest_window <= WINDOW_SIZE);
        assert!(
            emitted_bytes < FILE_LEN as usize / 4,
            "stream emitted too much sparse-hole data: {emitted_bytes} bytes"
        );
        assert!(
            offsets.windows(2).all(|pair| pair[0] < pair[1]),
            "sparse window offsets must be strictly increasing: {offsets:?}"
        );
    }

    /// An all-hole regular file on a SEEK_DATA-capable filesystem emits an
    /// explicit coverage error and never routes through mmap or the buffered
    /// hole reader.
    #[test]
    fn real_all_hole_file_reports_unscanned_region() {
        const FILE_LEN: u64 = 16 * 1024 * 1024;
        let sparse = tempfile::NamedTempFile::new().expect("all-hole tempfile");
        sparse
            .as_file()
            .set_len(FILE_LEN)
            .expect("set sparse length");
        let metadata = sparse.as_file().metadata().expect("all-hole metadata");
        assert_eq!(metadata.blocks(), 0, "test fixture allocated data blocks");
        assert!(discover_sparse_ranges(
            sparse.as_file(),
            FILE_LEN,
            keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES
        )
        .expect("query all-hole extents")
        .is_empty());

        let mut windows = 0usize;
        let mut errors = Vec::new();
        let outcome = for_each_file_windowed_mmap(
            sparse.path(),
            keyhog_core::DEFAULT_WINDOW_SIZE_BYTES,
            keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES,
            |row| {
                match row {
                    Ok(_) => windows += 1,
                    Err(error) => errors.push(error.to_string()),
                }
                true
            },
        );

        assert!(matches!(outcome, WindowedMmapOutcome::Consumed));
        assert_eq!(windows, 0);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("no allocated data"));
    }
}
