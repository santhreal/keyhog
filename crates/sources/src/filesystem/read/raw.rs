//! Safe `open`, buffered read, and whole-file mmap. All paths route
//! through [`open_file_safe`] which refuses to follow symlinks (a
//! scan tricked into reading `~/.aws/credentials` is a real attack
//! we already saw in the wild).

use memmap2::MmapOptions;
use std::fs::File;
use std::path::Path;

use super::decode::{decode_text_file, decode_text_file_owned};
use super::MMAP_TOCTOU_SANITY_CAP_BYTES;

pub(in crate::filesystem) fn read_file_buffered(path: &Path) -> Option<String> {
    // The buffered read already owns its `Vec<u8>`. Hand it to the owning
    // decoder so the valid-UTF-8 fast path can *move* the buffer straight
    // into the returned `String` (`String::from_utf8` reuses the same
    // allocation) instead of paying a full-file `s.to_owned()` heap copy.
    // At internet scale that copy is a whole extra pass over every byte
    // scanned on the hottest loop; the mmap path can't avoid it (its
    // backing store is borrowed), but the buffered path can and must.
    let bytes = read_file_safe(path).ok()?;
    decode_text_file_owned(bytes)
}

/// Open `path` in a symlink-resistant way. POSIX gets `O_NOFOLLOW`;
/// Windows checks `symlink_metadata` first (small TOCTOU window, but
/// acceptable for a defensive scanner - the attacker would have to
/// win a race they don't see initiated). The kernel-level fix on
/// Windows would route through `CreateFileW` with
/// `FILE_FLAG_OPEN_REPARSE_POINT`; tracked as backlog.
pub(in crate::filesystem) fn open_file_safe(path: &Path) -> std::io::Result<File> {
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

pub(in crate::filesystem) fn read_file_safe(path: &Path) -> std::io::Result<Vec<u8>> {
    // The previous implementation built an `IoUring::new(1)` per file, which
    // amortizes badly: ring setup + teardown is dominated by the syscalls
    // around the actual read for any file under ~1 GB. Plain buffered read
    // (and the `mmap` path used by `read_file_mmap`) outperformed it on the
    // standard corpus; see audits/legendary-2026-04-26 sources finding.
    // If io_uring becomes worthwhile again it should batch hundreds of files
    // through one shared ring - that's a significant rewrite tracked in the
    // backlog, NOT in this hot-path read.
    let mut file = open_file_safe(path)?;
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
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    Ok(bytes)
}

pub(in crate::filesystem) fn read_file_mmap(path: &Path) -> Option<String> {
    let mut file = open_file_safe(path).ok()?;

    // Post-open re-stat: defeat the walker-stat-then-write race where
    // an attacker grows the file to multi-GiB between the walker's
    // size check and our mmap. The walker's max_file_size is the
    // user-configurable budget; this constant is a HARD ceiling on
    // any mmap-based read regardless of user config.
    if let Ok(meta) = file.metadata() {
        if meta.len() > MMAP_TOCTOU_SANITY_CAP_BYTES {
            tracing::warn!(
                path = %path.display(),
                live_size = meta.len(),
                cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
                "refusing to mmap file: live size exceeds sanity cap (likely TOCTOU growth)"
            );
            return None;
        }
    }

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
        // is non-fatal - we ignore the return code.
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
