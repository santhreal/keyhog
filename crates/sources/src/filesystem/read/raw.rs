//! Safe `open`, buffered read, and bounded whole-file read. All paths route
//! through [`open_file_safe`] which refuses to follow symlinks (a
//! scan tricked into reading `~/.aws/credentials` is a real attack
//! we already saw in the wild).
//!
//! Nothing here maps a file. `read_file_whole_capped` documents why: a
//! file-backed mapping cannot be read race-free, and a concurrent truncation
//! turns into `SIGBUS`, which kills the scan with no report at all.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::decode::decode_text_file_owned_or_bytes;
use super::MMAP_TOCTOU_SANITY_CAP_BYTES;

pub(in crate::filesystem) enum BufferedFileRead {
    Text(String),
    Bytes(Vec<u8>),
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
    // uses it to fill the stat-sized buffer directly and probe once for growth,
    // instead of the many small reads `read_to_end` does on a tiny file. See
    // PERF-io_path-2.
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

/// Open `path` in a symlink-resistant, special-file-resistant way.
///
/// POSIX gets `O_NOFOLLOW` (never traverse a final symlink component) AND
/// `O_NONBLOCK`. The latter is load-bearing for a scanner that walks untrusted
/// trees: a plain `open(O_RDONLY)` of a FIFO with no writer BLOCKS FOREVER, so a
/// single named pipe anywhere in the scan set would hang the whole scan. With
/// `O_NONBLOCK` the open returns immediately for a FIFO, and the regular-file
/// check below then refuses it. `O_NONBLOCK` is inert on regular-file reads
/// (POSIX never returns `EAGAIN` for a regular file), so it does not change the
/// hot read path.
///
/// After the open succeeds we fstat the OPENED descriptor (not the path) and
/// refuse anything that is not a regular file. FIFO, socket, block/char device.
/// fstat'ing the fd we just opened, rather than re-stat'ing the path, closes the
/// TOCTOU window where the walker stats a regular file and an attacker swaps it
/// for a FIFO before this open (`O_NOFOLLOW` does not help, a FIFO is not a
/// symlink). A content scanner must never read from a special file; failing
/// closed here is surfaced loudly by the caller as a skip error, never silently.
///
/// Windows has no `O_NOFOLLOW`/`O_NONBLOCK` on `OpenOptions`, so it classifies
/// the path with `symlink_metadata` before open (small TOCTOU window, acceptable
/// for a defensive scanner) and the post-open regular-file check below still
/// applies. The shipped Windows contract is explicit refusal of symlink paths,
/// refusal of non-regular files, and fail-closed refusal when the file type
/// cannot be classified before the standard-library open.
pub(crate) fn open_file_safe(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK so a FIFO/device open returns immediately instead of
        // blocking on a missing writer; O_NOFOLLOW so the final path component
        // is never a followed symlink.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
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
    #[cfg(target_os = "linux")]
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ENAMETOOLONG) => {
            open_file_descriptor_relative(path)?
        }
        Err(error) => return Err(error),
    };
    #[cfg(not(target_os = "linux"))]
    let file = options.open(path)?;
    // Fail closed on any non-regular file. fstat the OPENED fd (the same object
    // the O_NONBLOCK open returned) so a FIFO/socket/device cannot reach the read
    // path: a FIFO read would hang, a device (`/dev/zero`) would stream until the
    // read cap, and neither is a scan target. Checking the fd, not the path
    // also closes the regular-file→FIFO TOCTOU swap. `is_file()` is true ONLY for
    // a regular file on every platform, so this one check covers all special
    // types (and a directory, which never reaches a content read anyway).
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to read a non-regular file (FIFO, socket, or device)",
        ));
    }
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

#[cfg(target_os = "linux")]
fn open_file_descriptor_relative(path: &Path) -> std::io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => Some(Ok(component)),
            std::path::Component::RootDir | std::path::Component::CurDir => None,
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                Some(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "descriptor-relative safe open refuses parent or platform-prefix components",
                )))
            }
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let (file_name, directories) = components.split_last().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "descriptor-relative safe open requires a file path",
        )
    })?;

    let mut root_options = std::fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    let mut directory = root_options.open(if path.is_absolute() { "/" } else { "." })?;
    for component in directories {
        directory = openat_component(
            &directory,
            component.as_bytes(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK
                | libc::O_CLOEXEC,
        )?;
    }
    openat_component(
        &directory,
        file_name.as_bytes(),
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )
}

#[cfg(target_os = "linux")]
fn openat_component(parent: &File, name: &[u8], flags: libc::c_int) -> std::io::Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let name = CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "filesystem path component contains a NUL byte",
        )
    })?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
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
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
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
    // (and the whole-file read path) outperformed it on the
    // standard corpus; see the internal design notes sources finding.
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
    let bytes = read_stat_sized_to_cap(&mut file, cap, cap)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            buffered_read_exceeded_cap_message(cap, cap),
        ));
    }
    Ok(bytes)
}
pub(super) fn read_stat_sized_to_cap(
    reader: &mut impl Read,
    expected_size: u64,
    hard_cap: u64,
) -> std::io::Result<Vec<u8>> {
    // The stat is only a reservation hint. Clamp it before converting or
    // allocating so an oversized/stale stat can never bypass the read cap,
    // including on platforms where u64 is wider than usize.
    let initial_size = expected_size.min(hard_cap);
    let initial_size = usize::try_from(initial_size).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "filesystem buffered read cap is not addressable on this platform: {error}"
            ),
        )
    })?;
    let mut bytes = vec![0u8; initial_size];
    let mut filled = 0;
    while filled < initial_size {
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!(
                        "failed to fill stat-sized filesystem buffer after {filled} of {initial_size} bytes: {error}"
                    ),
                ));
            }
        }
    }
    bytes.truncate(filled);
    if filled < initial_size {
        return Ok(bytes);
    }

    let mut sentinel = [0u8; 1];
    loop {
        match reader.read(&mut sentinel) {
            Ok(0) => return Ok(bytes),
            Ok(_) => {
                bytes.push(sentinel[0]);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(std::io::Error::new(
                    error.kind(),
                    format!("failed to probe filesystem file growth: {error}"),
                ));
            }
        }
    }

    if bytes.len() as u64 > hard_cap {
        return Ok(bytes);
    }

    let remaining_with_probe = hard_cap
        .saturating_sub(bytes.len() as u64)
        .saturating_add(1);
    if remaining_with_probe > 0 {
        reader
            .take(remaining_with_probe)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("failed to read filesystem file growth to the hard cap: {error}"),
                )
            })?;
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

/// Read a whole file into an owned buffer, bounded and truncation-safe.
///
/// This used to `mmap` the file and hand the mapping upward. It does not any
/// more, and the reason is a crash, not a preference: there is no race-free way
/// to read through a file-backed mapping. `ftruncate` by any other process
/// invalidates the page-cache pages past the new EOF, and the next touch of the
/// mapping raises `SIGBUS`, which kills the process outright. No handler, no
/// report, no findings for the rest of the scan. Reproduced on a plain
/// `keyhog scan <file>` against a file another thread was truncating: 1 of 6
/// trials at 128 KiB and 4 of 6 at 800 KiB died by signal 7.
///
/// That is not an exotic input. `scan-system` walks live filesystems where logs
/// rotate, so one rotating file could destroy a whole-system scan. `read(2)`
/// cannot fault: a truncation is just a short read, and growth is extra bytes we
/// scan. The cost is one owned copy, which this path was paying anyway (see
/// `read_file_buffered`: the mmap path could never move its backing store into
/// the decoded `String`, so it always copied).
///
/// The safety properties of the old path are all kept: one symlink-resistant
/// `open_file_safe` (which also holds the advisory `LOCK_SH`), a post-open
/// re-stat that refuses a file grown past `MMAP_TOCTOU_SANITY_CAP_BYTES` between
/// the walker's stat and here, and that same hard ceiling on the read itself.
pub(in crate::filesystem) fn read_file_whole_capped(path: &Path) -> Option<BufferedFileRead> {
    let mut file = match open_file_safe(path) {
        Ok(f) => f,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot open file for whole-file read; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    };

    // Post-open re-stat: defeat the walker-stat-then-write race where
    // an attacker grows the file to multi-GiB between the walker's
    // size check and our read. The walker's max_file_size is the
    // user-configurable budget; this constant is a HARD ceiling on
    // any whole-file read regardless of user config.
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
    let live_size = meta.len();
    if live_size > MMAP_TOCTOU_SANITY_CAP_BYTES {
        tracing::warn!(
            path = %path.display(),
            live_size,
            cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
            "refusing whole-file read: live size exceeds sanity cap (likely TOCTOU growth)"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return None;
    }
    // NB: no re-flock here. `open_file_safe` (which opened `file`) already holds
    // the advisory `LOCK_SH` on this fd, and a shared lock we already hold blocks
    // any new exclusive lock, so a re-request could only re-confirm the lock we
    // own (a redundant syscall whose "locked by another process" failure branch
    // was dead). The lock stays held for `file`'s lifetime, which spans the read
    // below. ONE owner of the flock guard: `open_file_safe`. Contract pinned by
    // `externally_exclusive_locked_file_is_refused_by_open_and_mmap`.

    // Tell the kernel we will read this fd sequentially front-to-back, not
    // randomly. posix_fadvise(SEQUENTIAL) doubles the readahead window and
    // stops prefetching past the end. Free perf on Linux, no-op elsewhere.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: posix_fadvise on a valid open descriptor; the hint is
        // advisory and any failure (EINVAL on tmpfs/procfs) is non-fatal.
        unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
    }

    // Fill the post-open size directly for files up to the bounded exact-read
    // threshold. The common unchanged-file path uses one sized data read and
    // one EOF probe without generic buffer-growth probes. Shrink still ends
    // early; growth continues through the same one-byte-past-hard-cap bound.
    let read_result = if live_size <= MAX_EXACT_SIZED_READ_PREALLOC_BYTES {
        read_stat_sized_to_cap(&mut file, live_size, MMAP_TOCTOU_SANITY_CAP_BYTES)
    } else {
        let capacity =
            usize::try_from(live_size.min(MMAP_TOCTOU_SANITY_CAP_BYTES)).unwrap_or(usize::MAX); // LAW10: unreachable on real platforms; a Vec length cannot exceed usize::MAX.
        let mut bytes = Vec::with_capacity(capacity);
        let read_limit = MMAP_TOCTOU_SANITY_CAP_BYTES.saturating_add(1);
        (&mut file)
            .take(read_limit)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    };
    let bytes = match read_result {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "cannot read file; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return None;
        }
    };
    if bytes.len() as u64 > MMAP_TOCTOU_SANITY_CAP_BYTES {
        tracing::warn!(
            path = %path.display(),
            cap = MMAP_TOCTOU_SANITY_CAP_BYTES,
            "file grew beyond the whole-file read sanity cap while reading"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: Simple advisory unlock FFI call.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }

    Some(match decode_text_file_owned_or_bytes(bytes) {
        Ok(text) => BufferedFileRead::Text(text),
        Err(bytes) => BufferedFileRead::Bytes(bytes),
    })
}
