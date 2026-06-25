//! Safe `open`, buffered read, and whole-file mmap. All paths route
//! through [`open_file_safe`] which refuses to follow symlinks (a
//! scan tricked into reading `~/.aws/credentials` is a real attack
//! we already saw in the wild).

use memmap2::MmapOptions;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::decode::decode_text_file_owned_or_bytes;
use super::MMAP_TOCTOU_SANITY_CAP_BYTES;

pub(in crate::filesystem) enum BufferedFileRead {
    Text(String),
    Bytes(Vec<u8>),
    Mmap(memmap2::Mmap),
}

const MAX_EXACT_SIZED_READ_PREALLOC_BYTES: u64 = 16 * 1024 * 1024;

/// Hard ceiling on a single buffered (non-mmap) whole-file read. Set to the
/// same 2 GiB sanity cap the mmap path enforces post-open: `--max-file-size`
/// is validated against a pre-read stat, so a file grown after that stat (a
/// walker-stat-then-grow TOCTOU) must not be able to OOM the buffered path
/// either. The mmap twin re-stats and refuses; the buffered path bounds the
/// read with `.take(MAX_BUFFERED_READ_BYTES)`. (KH-GAP-013)
pub(super) const MAX_BUFFERED_READ_BYTES: u64 = MMAP_TOCTOU_SANITY_CAP_BYTES;

pub(in crate::filesystem) fn read_file_buffered(
    path: &Path,
    size_hint: u64,
) -> Option<BufferedFileRead> {
    // The buffered read already owns its `Vec<u8>`. Hand it to the owning
    // decoder so the valid-UTF-8 fast path can *move* the buffer straight
    // into the returned `String` (`String::from_utf8` reuses the same
    // allocation) instead of paying a full-file `s.to_owned()` heap copy.
    // At internet scale that copy is a whole extra pass over every byte
    // scanned on the hottest loop; the mmap path can't avoid it (its
    // backing store is borrowed), but the buffered path can and must.
    //
    // `size_hint` is the walker's already-known `entry.size`: `read_file_safe`
    // uses it to read the whole file in a single sized `read(2)` (no empty-Vec
    // capacity-doubling and no trailing EOF probe), instead of the many small
    // reads `read_to_end` does on a tiny file. See PERF-io_path-2.
    let bytes = match read_file_safe(path, size_hint) {
        Ok(b) => b,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot read file; skipping"
            );
            let skip = if error.kind() == std::io::ErrorKind::InvalidData {
                crate::SourceSkipEvent::OverMaxSize
            } else {
                crate::SourceSkipEvent::Unreadable
            };
            let _event = crate::record_skip_event(skip);
            return None;
        }
    };
    match decode_text_file_owned_or_bytes(bytes) {
        Ok(text) => Some(BufferedFileRead::Text(text)),
        Err(bytes) => Some(BufferedFileRead::Bytes(bytes)),
    }
}

/// Open `path` in a symlink-resistant way. POSIX gets `O_NOFOLLOW`;
/// Windows must classify the path with `symlink_metadata` before open (small
/// TOCTOU window, but acceptable for a defensive scanner - the attacker would
/// have to win a race they don't see initiated). The shipped Windows contract
/// is explicit refusal of symlink paths and fail-closed refusal when the file
/// type cannot be classified before the standard-library open.
pub(crate) fn open_file_safe(path: &Path) -> std::io::Result<File> {
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
    // window between `symlink_metadata` and `open` - for our defensive-
    // secret-scanning threat model that's an acceptable trade-off; the
    // attacker would need to win a race they don't even see initiated.
    // Keep this contract local and explicit: refuse a symlink path before
    // opening it through the cross-platform standard-library path.
    #[cfg(windows)]
    {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to follow symlink (Windows safety guard)",
            ));
        }
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: advisory shared lock on a read-only descriptor. The lock is
        // held by the returned File until the read path drops it, preventing
        // locked/torn-write inputs from being reopened through a different
        // unlocked fallback path.
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "file is locked by another process",
            ));
        }
    }
    Ok(file)
}

pub(in crate::filesystem) fn read_file_prefix_safe(
    path: &Path,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut file = open_file_safe(path)?;
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

pub(in crate::filesystem) fn read_file_safe(
    path: &Path,
    size_hint: u64,
) -> std::io::Result<Vec<u8>> {
    // The previous implementation built an `IoUring::new(1)` per file, which
    // amortizes badly: ring setup + teardown is dominated by the syscalls
    // around the actual read for any file under ~1 GB. Plain buffered read
    // (and the `mmap` path used by `read_file_mmap`) outperformed it on the
    // standard corpus; see docs/EXECUTION_PLAN.md sources finding.
    // io_uring belongs in a shared batched owner with benchmark proof, not as
    // per-file ring setup in this hot-path read.
    let file = open_file_safe(path)?;
    // Hint to the kernel: this fd will be read sequentially start-to-end.
    // posix_fadvise(POSIX_FADV_SEQUENTIAL) doubles the readahead window
    // and disables prefetching past the end. Free perf on Linux; no-op
    // elsewhere. Linux kernel only - macOS lacks posix_fadvise.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: posix_fadvise is a syscall with documented behavior;
        // failure (EINVAL on tmpfs/proc, ESPIPE on pipes) is non-fatal -
        // we ignore it and proceed with the read.
        unsafe { libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
    }
    // Bound any buffered read at MAX_BUFFERED_READ_BYTES so a TOCTOU-grown file
    // can't OOM us (the mmap twin re-stats and refuses; this is the buffered
    // equivalent). Legitimate text files sit far under the 2 GiB ceiling, so
    // this never truncates real input. (KH-GAP-013)
    let cap = size_hint.min(MAX_BUFFERED_READ_BYTES);
    if cap == 0 {
        // The caller did not know the size (size_hint == 0): fall back to the
        // grow-from-empty read, still bounded by the cap.
        let read = crate::capped_read::read_to_cap(file, MAX_BUFFERED_READ_BYTES, None)?;
        if read.truncated {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "filesystem buffered read exceeded {} byte cap",
                    MAX_BUFFERED_READ_BYTES
                ),
            ));
        }
        return Ok(read.bytes);
    }

    if cap <= MAX_EXACT_SIZED_READ_PREALLOC_BYTES {
        return read_exact_stat_sized_with_growth_probe(file, cap);
    }

    let read = crate::capped_read::read_to_cap(file, cap, Some(cap))?;
    if read.truncated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            buffered_read_exceeded_cap_message(size_hint, cap),
        ));
    }
    Ok(read.bytes)
}

fn read_exact_stat_sized_with_growth_probe(mut file: File, cap: u64) -> std::io::Result<Vec<u8>> {
    let cap_usize = usize::try_from(cap).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("filesystem buffered read cap is not addressable on this platform: {error}"),
        )
    })?;
    let mut bytes = vec![0u8; cap_usize];
    let mut filled = 0;
    while filled < cap_usize {
        match file.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    bytes.truncate(filled);
    if filled == cap_usize {
        let mut sentinel = [0u8; 1];
        loop {
            match file.read(&mut sentinel) {
                Ok(0) => break,
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        buffered_read_exceeded_cap_message(cap, cap),
                    ));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(bytes)
}

fn buffered_read_exceeded_cap_message(size_hint: u64, cap: u64) -> String {
    if size_hint <= MAX_BUFFERED_READ_BYTES {
        format!("filesystem buffered read exceeded stat-time {size_hint} byte cap")
    } else {
        format!(
            "filesystem buffered read exceeded {} byte sanity cap after stat-time size {size_hint}",
            cap
        )
    }
}

pub(in crate::filesystem) fn read_file_mmap(path: &Path) -> Option<BufferedFileRead> {
    let mut file = match open_file_safe(path) {
        Ok(f) => f,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot open file for mmap; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    };

    // Post-open re-stat: defeat the walker-stat-then-write race where
    // an attacker grows the file to multi-GiB between the walker's
    // size check and our mmap. The walker's max_file_size is the
    // user-configurable budget; this constant is a HARD ceiling on
    // any mmap-based read regardless of user config.
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot stat opened file for mmap sanity cap; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    };
    let live_size_hint = Some(meta.len());
    if meta.len() > MMAP_TOCTOU_SANITY_CAP_BYTES {
        tracing::warn!(
            path = %path.display(),
            live_size = meta.len(),
            cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
            "refusing to mmap file: live size exceeds sanity cap (likely TOCTOU growth)"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory lock FFI call.
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            tracing::warn!(
                path = %path.display(),
                "file is locked by another process; skipping to avoid scanning a torn write"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the mapping
    // call, and we decode the bytes immediately without storing the mmap past
    // this function. Do not pass the earlier stat length into mmap: if the file
    // shrank between stat and map, a stale explicit length can create a range
    // past live EOF and SIGBUS when read. Map the kernel's current file length,
    // then enforce the hard cap before touching bytes.
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot mmap file; falling back to buffered read"
            );
            // Same OOM guard as the locked-file fallback above: cap the buffered
            // read at the TOCTOU sanity ceiling so an mmap failure does not become
            // an unbounded `read_to_end` of a TOCTOU-grown file.
            // (KH-GAP-OOM-mmap-fallback)
            match crate::capped_read::read_to_cap(
                &mut file,
                MMAP_TOCTOU_SANITY_CAP_BYTES,
                live_size_hint,
            ) {
                Ok(read) => {
                    if read.truncated {
                        tracing::warn!(
                            path = %path.display(),
                            cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
                            "file grew beyond mmap fallback sanity cap while reading"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                        return None;
                    }
                    return Some(match decode_text_file_owned_or_bytes(read.bytes) {
                        Ok(text) => BufferedFileRead::Text(text),
                        Err(bytes) => BufferedFileRead::Bytes(bytes),
                    });
                }
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "cannot read file after mmap failure; skipping"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    return None;
                }
            }
        }
    };
    let mapped_len = match u64::try_from(mmap.len()) {
        Ok(len) => len,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                mapped_len = mmap.len(),
                %error,
                "cannot represent mapped file length for mmap sanity cap; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return None;
        }
    };
    if mapped_len > MMAP_TOCTOU_SANITY_CAP_BYTES {
        tracing::warn!(
            path = %path.display(),
            live_size = mapped_len,
            cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
            "refusing to mmap file: mapped length exceeds sanity cap (likely TOCTOU growth)"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return None;
    }

    // Tell the kernel we will read this mmap sequentially front-to-back,
    // not randomly. madvise(SEQUENTIAL) disables LRU protection on the
    // pages so they can be evicted faster (we won't re-read them) and
    // bumps readahead. Free perf on Linux/macOS, no-op elsewhere.
    #[cfg(unix)]
    {
        // SAFETY: madvise on a valid memory range returned by mmap; failure
        // is non-fatal - we ignore the return code.
        unsafe {
            libc::madvise(
                mmap.as_ptr() as *mut libc::c_void,
                mmap.len(),
                libc::MADV_SEQUENTIAL,
            );
        }
    }

    let result = match super::decode::decode_text_file(&mmap) {
        Some(text) => BufferedFileRead::Text(text),
        None => BufferedFileRead::Mmap(mmap),
    };

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory unlock FFI call.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }

    Some(result)
}
