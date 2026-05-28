//! [`FileBytes`] wrapper and the mmap-or-owned read used by the
//! compressed-input pipeline. Compressed streams (`.gz`, `.zst`, etc.)
//! need a `&[u8]` slice without first heap-allocating the whole file -
//! a 1 GiB `.zst` would otherwise manifest as a 1 GiB `Vec<u8>` before
//! the decompressor ever started.

use memmap2::MmapOptions;
use std::path::Path;

use super::raw::open_file_safe;

/// File bytes returned to a caller that needs `&[u8]` but doesn't
/// care whether they live in a heap allocation or in a kernel-managed
/// mmap region. `as_slice` exposes a shared reference either way; the
/// caller hangs onto the `FileBytes` for as long as it holds the
/// slice.
pub(in crate::filesystem) enum FileBytes {
    /// Memory-mapped bytes - zero heap allocation, kernel-managed
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
pub(in crate::filesystem) fn read_file_for_compressed_input(
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
                // SAFETY: `file` is a valid open `File`; `LOCK_UN`
                // releases the advisory shared lock taken above.
                // The mmap was created from this file but kernel
                // mappings outlive the underlying flock.
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
            Some(FileBytes::Mmap(mmap))
        }
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                // SAFETY: `file` is still a valid open `File` (mmap
                // failed but the fd is intact); `LOCK_UN` releases
                // the advisory shared lock taken above.
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
            }
            std::fs::read(path).ok().map(FileBytes::Owned)
        }
    }
}
