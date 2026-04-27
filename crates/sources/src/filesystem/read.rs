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
    let file = open_file_safe(path).ok()?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory lock FFI call.
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return read_file_buffered(path);
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the mapping
    // call, and we decode the bytes immediately without storing the mmap past
    // this function.
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(_) => return read_file_buffered(path),
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
    if looks_binary(bytes) {
        return None;
    }
    if let Some(text) = decode_utf16(bytes) {
        return Some(text);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);

    // Use lossy decoding to ensure we don't skip files with minor UTF-8 corruption.
    // This maximizes recall for secrets hidden near invalid bytes.
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn looks_binary(bytes: &[u8]) -> bool {
    if has_binary_magic(bytes) || has_utf16_nul_pattern(bytes) {
        return true;
    }
    if memchr::memchr(0, bytes).is_some() {
        return true;
    }
    let suspicious = bytes
        .iter()
        .filter(|&&byte| byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C))
        .count();
    suspicious * 20 > bytes.len().max(1)
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
    let units: Vec<u16> = chunks
        .map(|chunk| {
            if little_endian {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            }
        })
        .collect();
    String::from_utf16(&units).ok()
}
