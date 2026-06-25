//! [`FileBytes`] wrapper and the mmap-or-owned read used by the
//! compressed-input pipeline. Compressed streams (`.gz`, `.zst`, etc.)
//! need a `&[u8]` slice without first heap-allocating the whole file -
//! a 1 GiB `.zst` would otherwise manifest as a 1 GiB `Vec<u8>` before
//! the decompressor ever started.

use memmap2::MmapOptions;
use std::fs::File;
use std::path::Path;

use super::raw::open_file_safe;

/// Buffered read bounded at `cap` bytes, routed through the same
/// already-open descriptor the mmap attempt used. Replaces the bare whole-file
/// `fs` read fallbacks, which (a) FOLLOWED symlinks — re-opening the path with
/// the libc default, undoing the no-follow guard the mmap open just applied —
/// and (b) were UNBOUNDED, so a compressed file grown past its stat between the
/// size check and the fallback read (a TOCTOU race) was slurped whole into a
/// `Vec`. Reading the existing descriptor preserves the no-follow open and
/// advisory lock; `.take(cap)` caps the allocation at the same ceiling the mmap
/// path already enforces. (KH-GAP-OOM-compressed-fallback)
fn read_capped_open_file(
    file: File,
    path: &Path,
    cap: u64,
    live_size: u64,
) -> std::io::Result<Vec<u8>> {
    if live_size > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "compressed file '{}' exceeds {} byte cap",
                path.display(),
                cap
            ),
        ));
    }
    let read = crate::capped_read::read_to_cap(file, cap, Some(live_size))?;
    if read.truncated {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "compressed file '{}' grew beyond {} byte cap while reading",
                path.display(),
                cap
            ),
        ));
    }
    Ok(read.bytes)
}

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
    /// Heap-owned bytes from a regular read. The fallback path when mmap is
    /// refused by an exotic filesystem or zero-byte input on some kernels.
    /// Locked files are skipped instead of reopened unlocked.
    Owned(Vec<u8>),
}

impl FileBytes {
    pub(in crate::filesystem) fn as_slice(&self) -> &[u8] {
        match self {
            FileBytes::Mmap(m) => m,
            FileBytes::Owned(v) => v,
        }
    }

    #[cfg(test)]
    pub(in crate::filesystem) fn len(&self) -> usize {
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
/// produce bytes. `size_cap == 0` means caller-level "unlimited"; this helper
/// still applies the hard 2 GiB TOCTOU sanity cap.
pub(in crate::filesystem) fn read_file_for_compressed_input(
    path: &Path,
    size_cap: u64,
) -> Option<FileBytes> {
    let effective_size_cap = if size_cap == 0 {
        super::MMAP_TOCTOU_SANITY_CAP_BYTES
    } else {
        size_cap
    };
    let file = match open_file_safe(path) {
        Ok(f) => f,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot open compressed file; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    };
    let metadata = match file.metadata() {
        Ok(m) => m,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot stat compressed file; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    };
    if metadata.len() > effective_size_cap {
        tracing::warn!(
            path = %path.display(),
            size = metadata.len(),
            cap = effective_size_cap,
            "compressed file exceeds size cap; refusing to map"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
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
        // SAFETY: Simple advisory lock FFI call. A failure means someone else
        // holds an exclusive lock; do not reopen and read the compressed file
        // unlocked because that can scan a torn write.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            tracing::warn!(
                path = %path.display(),
                "compressed file is locked by another process; skipping to avoid scanning a torn write"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
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
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot mmap compressed file; falling back to buffered read"
            );
            // Law 10: recall-safe + bounded/no-follow. The bare `std::fs::read`
            // here was both unbounded (OOM on a TOCTOU-grown compressed file)
            // and symlink-following; the open-file fallback fixes both while
            // refusing a TOCTOU-grown over-cap prefix instead of silently
            // treating truncated compressed bytes as a complete file.
            match read_capped_open_file(file, path, effective_size_cap, metadata.len()) {
                Ok(bytes) => Some(FileBytes::Owned(bytes)),
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "cannot read compressed file after mmap failure; skipping"
                    );
                    let skip = if error.kind() == std::io::ErrorKind::InvalidData {
                        crate::SourceSkipEvent::OverMaxSize
                    } else {
                        crate::SourceSkipEvent::Unreadable
                    };
                    let _event = crate::record_skip_event(skip);
                    None
                }
            }
        }
    }
}
