use memmap2::MmapOptions;
use std::fs::File;
use std::path::Path;

pub(super) fn read_file_buffered(path: &Path) -> Option<String> {
    let bytes = read_file_safe(path).ok()?;
    decode_text_file(&bytes)
}

fn open_file_safe(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    // Windows has no equivalent of O_NOFOLLOW on `OpenOptions`. Without an
    // explicit symlink check, a scan could be tricked into following a
    // junction/symlink out of the scan root and reading a sensitive file
    // (e.g. `C:\Users\victim\.aws\credentials`). There is a small TOCTOU
    // window between `symlink_metadata` and `open` — for our defensive-
    // secret-scanning threat model that's an acceptable trade-off; the
    // attacker would need to win a race they don't even see initiated.
    // The proper kernel-level fix would route through
    // `windows-sys::Win32::Storage::FileSystem::CreateFileW` with
    // `FILE_FLAG_OPEN_REPARSE_POINT`; tracked as backlog.
    #[cfg(windows)]
    {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing to follow symlink (Windows safety guard)",
                ));
            }
        }
    }
    options.open(path)
}

pub(super) fn read_file_safe(path: &Path) -> std::io::Result<Vec<u8>> {
    // The previous implementation built an `IoUring::new(1)` per file, which
    // amortizes badly: ring setup + teardown is dominated by the syscalls
    // around the actual read for any file under ~1 GB. Plain buffered read
    // (and the `mmap` path used by `read_file_mmap`) outperformed it on the
    // standard corpus; see audits/legendary-2026-04-26 sources finding.
    // If io_uring becomes worthwhile again it should batch hundreds of files
    // through one shared ring — that's a significant rewrite tracked in the
    // backlog, NOT in this hot-path read.
    let mut file = open_file_safe(path)?;
    // Hint to the kernel: this fd will be read sequentially start-to-end.
    // posix_fadvise(POSIX_FADV_SEQUENTIAL) doubles the readahead window
    // and disables prefetching past the end. Free perf on Linux; no-op
    // elsewhere. Linux kernel only — macOS lacks posix_fadvise.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: posix_fadvise is a syscall with documented behavior;
        // failure (EINVAL on tmpfs/proc, ESPIPE on pipes) is non-fatal —
        // we ignore it and proceed with the read.
        unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    Ok(bytes)
}

pub(super) fn read_file_mmap(path: &Path) -> Option<String> {
    let mut file = open_file_safe(path).ok()?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory lock FFI call.
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            let mut bytes = Vec::new();
            if std::io::Read::read_to_end(&mut file, &mut bytes).is_ok() {
                return decode_text_file(&bytes);
            }
            return None;
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the mapping
    // call, and we decode the bytes immediately without storing the mmap past
    // this function.
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(_) => {
            let mut bytes = Vec::new();
            if std::io::Read::read_to_end(&mut file, &mut bytes).is_ok() {
                return decode_text_file(&bytes);
            }
            return None;
        }
    };

    // Tell the kernel we will read this mmap sequentially front-to-back,
    // not randomly. madvise(SEQUENTIAL) disables LRU protection on the
    // pages so they can be evicted faster (we won't re-read them) and
    // bumps readahead. Free perf on Linux/macOS, no-op elsewhere.
    #[cfg(unix)]
    {
        // SAFETY: madvise on a valid memory range returned by mmap; failure
        // is non-fatal — we ignore the return code.
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut libc::c_void,
                mmap.len(),
                libc::MADV_SEQUENTIAL,
            );
        }
    }

    let result = decode_text_file(&mmap);

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory unlock FFI call.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }

    result
}

/// File bytes returned to a caller that needs `&[u8]` but doesn't
/// care whether they live in a heap allocation or in a kernel-managed
/// mmap region. `as_slice` exposes a shared reference either way; the
/// caller hangs onto the `FileBytes` for as long as it holds the
/// slice.
pub(super) enum FileBytes {
    /// Memory-mapped bytes — zero heap allocation, kernel-managed
    /// readahead, dropped automatically when this variant is freed.
    /// Preferred whenever the platform supports mmap.
    Mmap(memmap2::Mmap),
    /// Heap-owned bytes from a regular read. The fallback path when
    /// mmap is refused (locked file, exotic filesystem, zero-byte
    /// input on some kernels).
    Owned(Vec<u8>),
}

impl FileBytes {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            FileBytes::Mmap(m) => m,
            FileBytes::Owned(v) => v,
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
}

/// Read a file as a borrowable byte slice, preferring mmap to avoid
/// heap-allocating the whole file. Used by the compressed-stream path
/// (`extract_compressed_chunks`) so a 1 GiB `.zst` doesn't manifest as
/// a 1 GiB `Vec<u8>` before decompression begins. `madvise(SEQUENTIAL)`
/// is applied on Unix so the kernel prefetches as ziftsieve walks the
/// blocks.
///
/// Returns `None` when the file is larger than `size_cap` (refuses
/// pathological inputs at the source rather than letting them land in
/// the decompressor) or when neither mmap nor buffered read can
/// produce bytes.
pub(super) fn read_file_for_compressed_input(
    path: &Path,
    size_cap: u64,
) -> Option<FileBytes> {
    let file = open_file_safe(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() > size_cap {
        tracing::warn!(
            path = %path.display(),
            size = metadata.len(),
            cap = size_cap,
            "compressed file exceeds size cap; refusing to map"
        );
        return None;
    }

    // Empty file: mmap of zero-length is rejected on some platforms,
    // and there's nothing for ziftsieve to do anyway. Return an owned
    // empty vec so the caller's slice is just &[].
    if metadata.len() == 0 {
        return Some(FileBytes::Owned(Vec::new()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: Simple advisory lock FFI call. A failure means
        // someone else holds an exclusive lock; back out to the
        // owned-bytes path so we still try to read (compressed
        // inputs are usually not actively being written, but
        // belt-and-braces).
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return std::fs::read(path).ok().map(FileBytes::Owned);
        }
    }

    // SAFETY: read-only mapping, the `File` lives through the call,
    // and the returned `Mmap` owns its lifetime. We deliberately drop
    // the `File` after taking the mmap; the kernel keeps the mapping
    // valid until the `Mmap` is dropped.
    match unsafe { MmapOptions::new().map(&file) } {
        Ok(mmap) => {
            #[cfg(unix)]
            {
                // SAFETY: madvise on a valid mmap range; the hint is
                // advisory and any failure is non-fatal.
                unsafe {
                    libc::madvise(
                        mmap.as_ptr() as *mut libc::c_void,
                        mmap.len(),
                        libc::MADV_SEQUENTIAL,
                    );
                }
                use std::os::unix::io::AsRawFd;
                // Release the advisory lock; the mmap stays valid.
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
            Some(FileBytes::Mmap(mmap))
        }
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
            std::fs::read(path).ok().map(FileBytes::Owned)
        }
    }
}

/// One scanning window over a large file: an absolute byte offset into
/// the original file plus the lossy-UTF-8 view of those bytes. The
/// orchestrator's match locations are translated through `offset` so
/// findings reference the right place in the source even though we
/// scanned a slice.
pub(super) struct FileWindow {
    pub offset: usize,
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
///   * an advisory shared lock cannot be taken on Unix (a writer holds
///     it; we don't want to scan a torn write),
///   * the mmap call itself fails (typically a 0-byte file or a
///     filesystem that refuses mmap — falls through to the caller's
///     non-mmap windowed path).
pub(super) fn read_file_windowed_mmap(
    path: &Path,
    window_size: usize,
    overlap: usize,
) -> Option<Vec<FileWindow>> {
    debug_assert!(window_size > overlap, "window must exceed overlap");
    let file = open_file_safe(path).ok()?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory lock FFI call. A failure means
        // someone else holds an exclusive lock — back out so the
        // caller can take the buffered fallback (or just skip).
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return None;
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the
    // mapping call, and we drop the mmap before this function returns
    // (the windows we hand back are owned `String` copies).
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
            return None;
        }
    };

    #[cfg(unix)]
    {
        // SAFETY: madvise on a valid mmap range; ignored if the kernel
        // doesn't honor the hint. SEQUENTIAL doubles readahead and
        // disables LRU protection on already-read pages — we walk
        // front-to-back and never revisit, so eviction is correct.
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut libc::c_void,
                mmap.len(),
                libc::MADV_SEQUENTIAL,
            );
        }
    }

    let windows = slice_into_windows(&mmap, window_size, overlap);

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: Simple advisory unlock FFI call.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    Some(windows)
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
pub(super) fn slice_into_windows(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
) -> Vec<FileWindow> {
    assert!(window_size > overlap, "window must exceed overlap");
    if bytes.is_empty() {
        return Vec::new();
    }
    let stride = window_size - overlap;
    let total = bytes.len();
    let mut out = Vec::with_capacity(total.div_ceil(stride));
    let mut offset = 0usize;
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
        out.push(FileWindow { offset, text });
        // Stop once we've reached the tail; stride-from-here would
        // start past EOF.
        if end >= total {
            break;
        }
        offset += stride;
    }
    out
}

fn decode_text_file(bytes: &[u8]) -> Option<String> {
    // Cheap O(1) header rejects first — no full pass needed to know a PDF or
    // ZIP isn't a text file.
    if has_binary_magic(bytes) || has_utf16_nul_pattern(bytes) {
        return None;
    }
    // BOM-keyed UTF-16 fast path (rejects in ~6 bytes when the BOM doesn't
    // match; the streaming decode fires only on real UTF-16).
    if let Some(text) = decode_utf16(bytes) {
        return Some(text);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);

    // Valid-UTF-8 fast path (the common case for source trees): one SIMD
    // pass via `std::str::from_utf8` validates the whole file in zero
    // allocations. If validation succeeds AND a quick density check on the
    // header confirms it's not a 5%-controls binary that happens to be
    // valid UTF-8 (rare but possible — e.g. a UTF-8-encoded log of escape
    // sequences), we take an owned copy and return.
    //
    // Previously we ran `looks_binary` (full O(n) controls scan) AND
    // `from_utf8_lossy` (full O(n) validate + alloc) sequentially — two
    // full passes. The fused path drops one of them on valid UTF-8.
    if let Ok(s) = std::str::from_utf8(bytes) {
        if looks_binary_header_check(bytes) {
            return None;
        }
        return Some(s.to_owned());
    }
    // Not strictly valid UTF-8 — may be partial corruption (the lossy path
    // is what makes us robust to minified-JS / log-tail encoding hiccups
    // and preserves recall) or actual binary. Fall back to the full
    // controls-density check before paying for the lossy copy.
    if looks_binary(bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Cheap header-only binary check used after a successful strict-UTF-8
/// validation has already proven the rest is decodable. We've already
/// rejected binary-magic and UTF-16 NUL patterns at this point; all that
/// remains is the C0-controls-density heuristic. Sampling the first 4 KiB
/// catches all-control files (UTF-8 escape blobs, encoded binaries) without
/// re-scanning the whole file the way `looks_binary` does.
fn looks_binary_header_check(bytes: &[u8]) -> bool {
    let window = &bytes[..bytes.len().min(4096)];
    if window.is_empty() {
        return false;
    }
    let mut suspicious: u32 = 0;
    for &byte in window {
        if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C) {
            suspicious += 1;
            // Threshold matches `looks_binary` (5% suspicious bytes).
            if (suspicious as usize) * 20 > window.len() {
                return true;
            }
        }
    }
    false
}

fn looks_binary(bytes: &[u8]) -> bool {
    if has_binary_magic(bytes) || has_utf16_nul_pattern(bytes) {
        return true;
    }
    // FIX: Be more lenient with NUL bytes. A single NUL doesn't mean it's
    // a binary blob — minified JS or UTF-16-without-BOM might have them.
    // Reject only if NUL density is high or near the start.
    if let Some(first_nul) = memchr::memchr(0, bytes) {
        if first_nul < 1024 {
            // Check if it's UTF-16 (alternating NULs)
            let is_utf16 = bytes.len() >= 4
                && ((bytes[0] == 0 && bytes[1] != 0) || (bytes[0] != 0 && bytes[1] == 0));
            if !is_utf16 {
                return true;
            }
        }
    }
    // Threshold: `suspicious * 20 > total` (i.e. >5% of the file is C0
    // controls other than the usual text whitespace/form-feed). The previous
    // implementation always ran a full O(n) `filter().count()` over every
    // byte. For source-tree scans where ~all files are obvious text, that's
    // a wasted full pass per file.
    //
    // Two-sided early exit — bail in either direction the moment the verdict
    // is provable:
    //   * As soon as `suspicious * 20 > scanned`, it's binary.
    //   * As soon as `(suspicious + remaining) * 20 ≤ total`, even worst-case
    //     remaining bytes can't push us past threshold → it's text.
    //
    // On a 100 KiB clean text file the loop now exits after ~5 KiB once the
    // worst-case branch concludes "no suspicious density possible." On a
    // binary blob it exits within the first few bytes once the density is
    // confirmed. Either way, the rare-but-pathological dense-clean-text
    // case still walks the whole file — same complexity bound, just a much
    // tighter constant.
    let total = bytes.len() as u64;
    if total == 0 {
        return false;
    }
    let mut suspicious: u64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        let is_susp = byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C);
        if is_susp {
            suspicious += 1;
            // Confirmed binary: ratio already over threshold.
            if suspicious * 20 > total {
                return true;
            }
        }
        // Confirmed text: even if every remaining byte were suspicious,
        // we couldn't reach the threshold. Sample the check once per page
        // so we don't pay the bookkeeping per byte; 4 KiB matches the
        // typical OS page size.
        if i & 0xFFF == 0xFFF {
            let scanned = (i as u64) + 1;
            let remaining = total - scanned;
            if (suspicious + remaining) * 20 <= total {
                return false;
            }
        }
    }
    suspicious * 20 > total
}

fn has_binary_magic(bytes: &[u8]) -> bool {
    const MAGIC_HEADERS: &[&[u8]] = &[
        b"%PDF-",
        b"PK\x03\x04",
        b"\x89PNG\r\n\x1a\n",
        b"\xD0\xCF\x11\xE0",
    ];
    MAGIC_HEADERS.iter().any(|header| bytes.starts_with(header))
}

fn has_utf16_nul_pattern(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[0] == 0xFF && bytes[1] == 0xFE || bytes[0] == 0xFE && bytes[1] == 0xFF)
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    let (little_endian, payload) = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        (true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        (false, rest)
    } else {
        return None;
    };
    let chunks = payload.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return None;
    }
    // Stream the u16 units straight into a String through `char::decode_utf16`,
    // skipping the previous `Vec<u16>` intermediary. For a 1 MiB UTF-16 file
    // that drops a half-megabyte temp allocation and frees its cache lines
    // for the actual scan stage. ASCII-shaped UTF-16 (the common case for
    // Windows-exported logs / config) takes the BMP fast path inside
    // `char::from_u32`, no surrogate-pair fixups.
    let units = chunks.map(|chunk| {
        if little_endian {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], chunk[1]])
        }
    });
    let mut out = String::with_capacity(payload.len() / 2);
    for r in char::decode_utf16(units) {
        out.push(r.ok()?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_binary_empty_input_is_text() {
        assert!(!looks_binary(&[]));
    }

    #[test]
    fn looks_binary_clean_ascii_is_text() {
        let s = "hello world\nfoo = bar\n".repeat(1024);
        assert!(!looks_binary(s.as_bytes()));
    }

    #[test]
    fn looks_binary_dense_controls_is_binary() {
        let mut bytes = vec![b'a'; 1024];
        for b in bytes.iter_mut().take(200) {
            *b = 0x03; // ETX, well over the 5% threshold
        }
        assert!(looks_binary(&bytes));
    }

    #[test]
    fn looks_binary_sparse_controls_is_text() {
        // Below threshold — exactly 5% would equal `suspicious * 20 == total`,
        // which is `>` test → still text.
        let mut bytes = vec![b'a'; 1000];
        for b in bytes.iter_mut().take(50) {
            *b = 0x03;
        }
        assert!(!looks_binary(&bytes));
    }

    #[test]
    fn looks_binary_short_circuit_matches_full_scan() {
        // Random fixed-seed mix; exhaustive comparison against the
        // previous "filter().count()" implementation for several sizes
        // and densities, including the page-boundary cases where the
        // remaining-bytes early-text exit fires.
        for size in [1, 100, 4095, 4096, 4097, 8192, 16384, 100_000] {
            for density in [0u8, 1, 4, 5, 6, 50] {
                let mut bytes = vec![b'.'; size];
                for i in (0..size)
                    .step_by(100usize.saturating_div(density.max(1) as usize).max(1))
                    .take((size * density as usize) / 100)
                {
                    bytes[i] = 0x03;
                }
                let suspicious = bytes
                    .iter()
                    .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0C))
                    .count() as u64;
                let expected = suspicious * 20 > bytes.len().max(1) as u64;
                assert_eq!(
                    looks_binary(&bytes),
                    expected,
                    "size={size} density={density}"
                );
            }
        }
    }

    #[test]
    fn decode_utf16_le_round_trip() {
        let s = "hello, 世界! 🌍";
        let mut bytes = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decode_utf16(&bytes).as_deref(), Some(s));
    }

    #[test]
    fn decode_utf16_be_round_trip() {
        let s = "hello, 世界! 🌍";
        let mut bytes = vec![0xFE, 0xFF];
        for u in s.encode_utf16() {
            bytes.extend_from_slice(&u.to_be_bytes());
        }
        assert_eq!(decode_utf16(&bytes).as_deref(), Some(s));
    }

    #[test]
    fn decode_utf16_no_bom_is_none() {
        let s = "hello";
        let mut bytes = Vec::new();
        for u in s.encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        assert!(decode_utf16(&bytes).is_none());
    }

    #[test]
    fn decode_utf16_odd_length_payload_is_none() {
        let bytes = [0xFF, 0xFE, 0x68];
        assert!(decode_utf16(&bytes).is_none());
    }

    #[test]
    fn decode_utf16_unpaired_surrogate_is_none() {
        // Lone high surrogate followed by ASCII — invalid UTF-16.
        let bytes = [0xFF, 0xFE, 0x00, 0xD8, b'a', 0x00];
        assert!(decode_utf16(&bytes).is_none());
    }

    #[test]
    fn decode_text_file_valid_utf8_takes_fast_path() {
        let s = "let x = 1;\nfn main() {}\n".repeat(500);
        assert_eq!(decode_text_file(s.as_bytes()).as_deref(), Some(s.as_str()));
    }

    #[test]
    fn decode_text_file_with_bom_strips_bom() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello world");
        assert_eq!(decode_text_file(&bytes).as_deref(), Some("hello world"));
    }

    #[test]
    fn decode_text_file_pdf_magic_is_rejected() {
        let mut bytes = b"%PDF-1.7\n".to_vec();
        bytes.extend_from_slice(&vec![b'a'; 4096]);
        assert!(decode_text_file(&bytes).is_none());
    }

    #[test]
    fn decode_text_file_invalid_utf8_falls_back_to_lossy() {
        // Invalid continuation byte mid-stream. Strict from_utf8 rejects;
        // looks_binary verdict is text (low control density); lossy path
        // returns the original with U+FFFD replacements.
        let mut bytes = b"valid prefix ".to_vec();
        bytes.push(0xFF); // lone byte — invalid UTF-8
        bytes.extend_from_slice(b" suffix");
        let decoded = decode_text_file(&bytes).expect("lossy fallback runs");
        assert!(decoded.contains("valid prefix"));
        assert!(decoded.contains("suffix"));
        assert!(decoded.contains('\u{FFFD}'));
    }

    #[test]
    fn decode_text_file_dense_controls_in_header_rejected() {
        // Valid UTF-8 but with >5% C0 controls in the first 4 KiB —
        // should hit the looks_binary_header_check path.
        let mut bytes = vec![b'a'; 4096];
        for b in bytes.iter_mut().take(400) {
            *b = 0x01;
        }
        assert!(decode_text_file(&bytes).is_none());
    }

    // ----- slice_into_windows: pure-function boundary behavior -----

    #[test]
    fn slice_into_windows_empty_input_returns_empty() {
        assert!(slice_into_windows(&[], 64, 8).is_empty());
    }

    #[test]
    fn slice_into_windows_smaller_than_window_yields_one_window() {
        let bytes = b"hello, world";
        let ws = slice_into_windows(bytes, 64, 8);
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0].offset, 0);
        assert_eq!(ws[0].text, "hello, world");
    }

    #[test]
    fn slice_into_windows_exactly_one_window_size() {
        let bytes = vec![b'a'; 64];
        let ws = slice_into_windows(&bytes, 64, 8);
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0].offset, 0);
        assert_eq!(ws[0].text.len(), 64);
    }

    #[test]
    fn slice_into_windows_one_byte_over_window_emits_two_windows() {
        // A 65-byte input with window=64, overlap=8 — stride is 56,
        // so window 1 starts at offset 56 and runs 56..65 = 9 bytes.
        let bytes: Vec<u8> = (0..65u8).collect();
        let ws = slice_into_windows(&bytes, 64, 8);
        assert_eq!(ws.len(), 2);
        assert_eq!(ws[0].offset, 0);
        assert_eq!(ws[0].text.len(), 64);
        assert_eq!(ws[1].offset, 56);
        assert_eq!(ws[1].text.len(), 9);
    }

    #[test]
    fn slice_into_windows_overlap_bytes_match_between_neighbours() {
        // The whole point of overlap: a secret straddling the cut
        // appears in both windows. Use ASCII-only input so lossy
        // decode is a no-op and byte length is preserved across
        // the String round-trip — otherwise U+FFFD substitution
        // makes the post-decode lengths drift from the raw slice.
        let bytes: Vec<u8> = b"0123456789abcdefghijklmnopqrstuvwxyz".iter().copied().cycle().take(200).collect();
        let ws = slice_into_windows(&bytes, 100, 16);
        assert!(ws.len() >= 2);
        for pair in ws.windows(2) {
            let prev = &pair[0];
            let next = &pair[1];
            let prev_tail = &prev.text.as_bytes()[prev.text.len() - 16..];
            let next_head = &next.text.as_bytes()[..16];
            assert_eq!(prev_tail, next_head, "overlap mismatch at {}", next.offset);
            assert_eq!(next.offset - prev.offset, 100 - 16);
        }
    }

    #[test]
    fn slice_into_windows_offsets_cover_the_whole_input() {
        // Coverage check requires that decoded text length equals raw
        // slice length, so use ASCII-only bytes and assert that
        // every byte offset is touched by at least one window.
        let bytes: Vec<u8> = (b'a'..=b'z').cycle().take(10_000).collect();
        let ws = slice_into_windows(&bytes, 256, 32);
        let mut covered = vec![false; bytes.len()];
        for w in &ws {
            assert_eq!(
                w.text.len(),
                (w.offset + w.text.len()).min(bytes.len()) - w.offset,
                "ASCII input → text len equals slice len"
            );
            for i in w.offset..(w.offset + w.text.len()).min(bytes.len()) {
                covered[i] = true;
            }
        }
        assert!(
            covered.iter().all(|&c| c),
            "every byte must be covered by some window"
        );
    }

    #[test]
    fn slice_into_windows_secret_straddling_cut_present_in_both_windows() {
        // Motivating case. window=128, overlap=32 → stride=96.
        // For exactly 2 windows we need len in (128, 128+96] = (128, 224].
        // Pick 200; windows are [0..128) and [96..200). The secret at
        // offset 100..120 sits in both — so the scanner can't miss it.
        let mut bytes = vec![b'.'; 200];
        let secret = b"AKIAIOSFODNN7EXAMPLE";
        bytes[100..100 + secret.len()].copy_from_slice(secret);
        let ws = slice_into_windows(&bytes, 128, 32);
        assert_eq!(ws.len(), 2, "expected exactly 2 windows for len=200, ws=128, ov=32");
        let s = std::str::from_utf8(secret).unwrap();
        assert!(ws[0].text.contains(s), "window 0 must carry the straddling secret");
        assert!(ws[1].text.contains(s), "window 1 must carry the straddling secret");
    }

    #[test]
    fn slice_into_windows_invalid_utf8_at_boundary_decodes_lossy() {
        // A multi-byte UTF-8 sequence cut by the window edge must not
        // panic — it becomes U+FFFD on the side that has the partial
        // bytes, and decodes correctly on the side that has the full
        // sequence. Use the snowman (☃, 0xE2 0x98 0x83) split at the
        // cut between window 0 (ends at byte 64) and window 1
        // (starts at byte 56). Picked len=120 for exactly 2 windows
        // given window=64, overlap=8 → stride=56 (max len for 2 wins
        // is 64+56=120).
        let mut bytes = vec![b'a'; 120];
        bytes[63] = 0xE2;
        bytes[64] = 0x98;
        bytes[65] = 0x83;
        let ws = slice_into_windows(&bytes, 64, 8);
        assert_eq!(ws.len(), 2, "expected 2 windows for len=120, ws=64, ov=8");
        // Window 0 covers 0..64 → only 0xE2 of the sequence is present.
        // Lossy decode replaces the dangling lead byte with U+FFFD.
        assert!(ws[0].text.ends_with('\u{FFFD}'));
        // Window 1 covers 56..120 → full snowman at relative 7..10.
        assert!(ws[1].text.contains('☃'));
    }

    #[test]
    fn slice_into_windows_large_input_window_count_matches_formula() {
        // len = 4096, window = 1024, overlap = 64 → stride = 960.
        // Windows: starts at 0, 960, 1920, 2880, 3840 — 5 windows
        // (the last one ending exactly at 4096).
        let bytes = vec![b'x'; 4096];
        let ws = slice_into_windows(&bytes, 1024, 64);
        assert_eq!(ws.len(), 5);
        assert_eq!(ws[0].offset, 0);
        assert_eq!(ws[1].offset, 960);
        assert_eq!(ws[2].offset, 1920);
        assert_eq!(ws[3].offset, 2880);
        assert_eq!(ws[4].offset, 3840);
        assert_eq!(ws[4].text.len(), 256);
    }

    #[test]
    #[should_panic(expected = "window must exceed overlap")]
    fn slice_into_windows_panics_when_overlap_geq_window() {
        // Same-as-window overlap means stride == 0 → infinite loop.
        // Catch it as a programming error at the API surface.
        slice_into_windows(b"abc", 16, 16);
    }

    #[test]
    fn read_file_windowed_mmap_roundtrip_matches_pure_helper() {
        // The mmap path is just slice_into_windows over the mmap'd
        // bytes. Write a small file, run both, assert identical.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.txt");
        let bytes: Vec<u8> = (0..u8::MAX).cycle().take(8192).collect();
        std::fs::write(&path, &bytes).unwrap();

        let pure = slice_into_windows(&bytes, 1024, 32);
        let mapped = read_file_windowed_mmap(&path, 1024, 32).expect("mmap windows");
        assert_eq!(pure.len(), mapped.len());
        for (a, b) in pure.iter().zip(mapped.iter()) {
            assert_eq!(a.offset, b.offset);
            assert_eq!(a.text, b.text);
        }
    }

    #[test]
    fn read_file_for_compressed_input_returns_full_contents_via_mmap() {
        // The mmap-or-bytes wrapper must round-trip an arbitrary
        // non-empty byte sequence — covers the common case where
        // compressed inputs are well within the size cap.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        // Use a payload with a mix of bytes so any truncation
        // manifests as a mismatch, not coincidentally-equal heads.
        let payload: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
        std::fs::write(&path, &payload).unwrap();

        let fb = read_file_for_compressed_input(&path, 1024 * 1024).expect("read ok");
        assert_eq!(fb.as_slice(), &payload[..]);
        assert_eq!(fb.len(), payload.len());
    }

    #[test]
    fn read_file_for_compressed_input_handles_empty_file() {
        // mmap of zero-byte files is rejected on some platforms; the
        // helper must return Some(Owned(empty)) so callers don't
        // misinterpret None as a hard failure.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();

        let fb = read_file_for_compressed_input(&path, 1024).expect("empty ok");
        assert!(fb.as_slice().is_empty());
        assert_eq!(fb.len(), 0);
    }

    #[test]
    fn read_file_for_compressed_input_refuses_oversize_input() {
        // size_cap is the gate that keeps a 100 GiB compressed blob
        // out of memory entirely. The helper returns None and emits
        // a tracing warning — caller treats as "skip this file".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.bin");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();

        // cap below file size → refused.
        let fb = read_file_for_compressed_input(&path, 1024);
        assert!(fb.is_none(), "input exceeding size_cap must return None");

        // cap at-or-above file size → accepted.
        let fb = read_file_for_compressed_input(&path, 4096);
        assert!(fb.is_some(), "input at-or-below size_cap must succeed");
    }

    #[test]
    fn read_file_for_compressed_input_returns_none_for_missing_path() {
        // Nonexistent path must NOT panic, and must return None so
        // the caller can move on cleanly. (Earlier implementations
        // did `std::fs::read(path)?` and bubbled the error; the new
        // wrapper folds that into None to match the Option-shaped
        // API the windowed helper uses.)
        let fb = read_file_for_compressed_input(
            std::path::Path::new("/nonexistent/keyhog/test/path"),
            1024,
        );
        assert!(fb.is_none());
    }

    #[test]
    fn read_file_windowed_mmap_handles_empty_file() {
        // Zero-byte mmap is a corner case some platforms reject. The
        // helper must return either Some(empty vec) or None — never
        // panic. Either way the caller won't emit chunks.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        let result = read_file_windowed_mmap(&path, 1024, 32);
        match result {
            Some(v) => assert!(v.is_empty()),
            None => {} // acceptable: mmap of zero-length refused
        }
    }
}
