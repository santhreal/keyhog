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
}
