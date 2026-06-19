use super::display_path;
use super::filter::{is_default_excluded, skip_extensions};
use super::read;
use keyhog_core::MerkleIndex;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

mod archive;
mod compressed;
mod pdf;
mod rar;
mod seven_zip;

/// Test whether `path` is a symlink. No cache: the walker visits each
/// path exactly once, so a process-lifetime `DashMap<PathBuf, bool>`
/// only ever sees a single lookup per key and retained one PathBuf per
/// file for the whole scan (1GB+ on a multi-million-file tree) while
/// providing a ~0% hit rate. A bare `symlink_metadata` stat is the
/// single-pass-correct choice. (Was KH-41 SYMLINK_CACHE; removed - the
/// cache was pure retained-forever overhead on single-pass walks.)
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false) // LAW10: empty/absent => documented numeric default, recall-safe
}

/// Minimum file size to use memory mapping. The crossover point is
/// platform-specific:
///
///   * Linux / macOS: mmap setup is sub-microsecond and avoids the
///     `read(2)` copy from kernel page cache to userland buffer. Worth
///     it as soon as the file is at least one page (4 KiB) - pick
///     64 KiB to keep tiny-config-file scans on the buffered path
///     where the syscall floor dominates either way.
///   * Windows: `MapViewOfFile` has more setup cost (security tokens,
///     section-object routing) and the `ReadFile` path is already
///     well-optimised by the OS for buffered I/O. Keep the historical
///     1 MiB threshold here to avoid regressing typical source-tree
///     scans.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MMAP_THRESHOLD: u64 = 64 * 1024;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const MMAP_THRESHOLD: u64 = 1024 * 1024;

/// Per-entry chunk extraction. Reads the file, archive, or compressed
/// stream and feeds each resulting `Chunk` to `emit` as it is produced.
#[allow(clippy::too_many_arguments)]
pub(super) fn process_entry(
    entry: codewalk::FileEntry,
    merkle: &Option<Arc<MerkleIndex>>,
    skipped: &Arc<AtomicUsize>,
    default_exclude_root: &Path,
    max_size: u64,
    window_size: usize,
    window_overlap: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let path = entry.path;
    let file_size = entry.size;

    // Built-in exclusion list (lock/minified/bundled/vendored). Gated on
    // `respect_default_excludes` so `--no-default-excludes` actually reaches this
    // in-process filter, not just the codewalk glob layer — otherwise a secret in
    // `package-lock.json` stays silently excluded even with the flag set (KH-55).
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
    let default_exclude_path = match path.strip_prefix(default_exclude_root) {
        Ok(relative) => relative.to_string_lossy(),
        Err(_) => std::borrow::Cow::Borrowed(filename), // LAW10: root-prefix mismatch uses basename-only default-exclude classification to avoid parent-directory false exclusions; recall-preserving
    };
    if respect_default_excludes && is_default_excluded(&default_exclude_path) {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
        return;
    }
    if respect_default_excludes
        && (filename.contains(".min.")
            || filename.contains(".bundle.")
            || filename.ends_with(".chunk.js")
            || filename.ends_with(".min.js")
            || filename.ends_with(".bundle.js"))
    {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Excluded);
        return;
    }

    if max_size > 0 && file_size > max_size {
        tracing::warn!(
            path = %path.display(),
            size_bytes = file_size,
            max_size,
            "skipping file: size exceeds --max-file-size cap"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("") // LAW10: missing/non-string field => empty/placeholder; recall-safe
        .to_lowercase();

    // Compile the SKIP_EXTENSIONS array into a fast HashSet at startup to accelerate file-type screening (KH-45)
    if skip_extensions().contains(ext.as_str()) {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        return;
    }

    if ext.is_empty() {
        // Sniff the first 16 bytes of files without extensions to quickly skip binary structures without full content reads (KH-50)
        if let Ok(mut f) = std::fs::File::open(&path) {
            let mut buf = [0u8; 16];
            if let Ok(n) = f.read(&mut buf) {
                if n > 0 {
                    let is_binary = buf[..n].iter().any(|&b| b == 0)
                        || buf.starts_with(b"\x7fELF")
                        || buf.starts_with(b"MZ")
                        || buf.starts_with(b"%PDF")
                        || buf.starts_with(b"PK\x03\x04");
                    if is_binary {
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
                        return;
                    }
                }
            }
        }
    }

    let live_mtime_ns = file_mtime_ns(&path);
    if let (Some(idx), Some(mtime_ns)) = (merkle.as_ref(), live_mtime_ns) {
        if idx.metadata_unchanged(&path, mtime_ns, file_size) {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }

    if ext == "pdf" {
        pdf::extract_pdf_chunks(&path, file_size, live_mtime_ns, max_size, emit);
        return;
    } else if ext == "7z" {
        seven_zip::extract_seven_zip_chunks(&path, max_size, emit);
        return;
    } else if ext == "rar" {
        rar::extract_rar_chunks(&path, max_size, emit);
        return;
    } else if archive::is_openpack_archive_ext(&ext) {
        archive::extract_openpack_archive(&path, max_size, emit);
        return;
    } else if ext == "tar" {
        // Bare (uncompressed) `.tar`: unpack per-entry exactly as the zip
        // branch does, so a secret committed inside a tarball (docker layer
        // export, helm chart, source tarball — the dominant Linux/cloud
        // archive) is found just like one inside a `.zip`. `emit_tar_entries`
        // enforces the same per-entry size cap and 4x total-uncompressed
        // (tar-bomb) budget as the zip branch.
        if is_symlink(&path) {
            // Law 10: refused symlink => this .tar path is NOT scanned; count it.
            tracing::warn!(
                archive = %path.display(),
                "refusing to open archive at a symlink path - \
                 prevents the link-swap attack class"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return;
        }
        // `read_file_safe` opens with `O_NOFOLLOW` on Unix / `symlink_metadata`
        // refusal on Windows, so an `--include`d `bundle.tar -> ~/.aws/...`
        // symlink can't redirect the read to an off-tree target.
        match read::read_file_safe(&path, file_size) {
            Ok(bytes) => {
                // Guard against a non-tar file with a `.tar` extension: only untar
                // when the ustar/GNU magic is actually present, otherwise fall
                // through to the normal scan path so the bytes are still examined.
                if compressed::looks_like_tar(&bytes) {
                    compressed::emit_tar_entries(&bytes, &display_path(&path), max_size, emit);
                    return;
                }
                tracing::info!(
                    archive = %path.display(),
                    "file has .tar extension but is not a tar archive; scanning as plain file"
                );
            }
            Err(error) => {
                tracing::warn!(
                    archive = %path.display(),
                    %error,
                    "cannot read tar file; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                return;
            }
        }
    } else if ext == "gz"
        || ext == "zst"
        || ext == "lz4"
        || ext == "sz"
        || ext == "bz2"
        || ext == "xz"
        || ext == "tgz"
    {
        // `.gz` / `.tar.gz` (ext `gz`) / `.tgz` / `.zst` / `.lz4` / `.sz` /
        // `.bz2` / `.xz`: fully decompress, then untar per-entry if the
        // decompressed stream is a tar container, else scan the real
        // decompressed bytes. These extensions are removed from SKIP_EXTENSIONS
        // so they reach this branch.
        compressed::extract_compressed_chunks(&path, max_size, emit);
        return;
    } else if ext == "har" {
        // Route the HAR read through the same no-follow-symlink guard
        // every other content path uses (`read_file_safe` -> `open_file_safe`
        // with `O_NOFOLLOW` on Unix / `symlink_metadata` refusal on Windows).
        // The old `std::fs::read` followed symlinks, so an explicitly
        // `--include`d `creds.har -> ~/.aws/credentials` symlink (include
        // paths use `is_file()`, which follows links) would be read and its
        // target's bytes scanned - the exact link-swap class the archive
        // branch's guard at the top of this function defends against. (M17)
        match read::read_file_safe(&path, file_size) {
            Ok(bytes) => {
                let path_str = display_path(&path);
                match crate::har::try_expand_har(&bytes, &path_str, max_size) {
                    Some(har_chunks) => {
                        for chunk in har_chunks {
                            if !emit(chunk) {
                                return;
                            }
                        }
                        return;
                    }
                    None => {
                        tracing::info!(
                            path = %path.display(),
                            "HAR parse failed; scanning as plain file"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "cannot read HAR file; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                return;
            }
        }
    }

    // No-follow guard for the GENERAL content read below. The archive/compressed
    // branches above each refuse a symlink path and `return`; the `.har` branch
    // reads via the `O_NOFOLLOW` `read_file_safe` but FALLS THROUGH to here when
    // the no-follow open failed or the target is not valid HAR — which is exactly
    // what an `--include`d `creds.har -> ~/.aws/credentials` symlink does: include
    // paths are admitted with `is_file()` (follows links), `O_NOFOLLOW` then
    // rejects the link so the HAR read yields nothing, and control reaches the
    // general read whose `read_file_windowed_mmap` / `File::open(&path)` DO follow
    // the link and would scan the victim's bytes. Refuse symlinks here so no read
    // path follows a link-swap target (M17 regression: the guard existed only on
    // the HAR-specific read, not on the fall-through). Same defense + style as the
    // archive-branch guards above.
    if is_symlink(&path) {
        // Law 10: refusing to follow the symlink means this explicitly-included
        // path is NOT scanned. Count it (as unreadable) so end-of-scan coverage
        // reflects the drop — a refused symlink is a deliberate non-scan, but
        // the operator must still see the path was skipped, not silently treated
        // as clean.
        tracing::warn!(
            path = %path.display(),
            "refusing to read content at a symlink path - prevents the link-swap attack class"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return;
    }

    if file_size > window_size as u64 {
        let display = display_path(&path);
        if let Some(windows) = read::read_file_windowed_mmap(&path, window_size, window_overlap) {
            for w in windows {
                let chunk = Ok(Chunk {
                    data: w.text.into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/windowed".to_string(),
                        path: Some(display.clone()),
                        base_offset: w.offset,
                        base_line: w.base_line,
                        mtime_ns: live_mtime_ns,
                        size_bytes: Some(file_size),
                        decoded_span: None,
                        ..Default::default()
                    },
                });
                if !emit(chunk) {
                    return;
                }
            }
            return;
        }
        match std::fs::File::open(&path) {
            Ok(mut file) => {
                let mut current_offset = 0;
                // Newlines in the file before `current_offset` - the absolute
                // base line of the window about to be emitted, advanced in
                // lockstep with `current_offset` so reported lines are absolute
                // (the line analog of `base_offset`).
                let mut current_base_line = 0usize;
                let mut buffer = vec![0u8; window_size];
                loop {
                    // Fill the window with a `read_exact`-style loop. `Read::read`
                    // is permitted to return fewer bytes than requested without
                    // being at EOF (a short read in the middle of a multi-MiB
                    // file); the old `if n < window_size { break }` treated any
                    // short read as EOF and silently dropped the rest of the file,
                    // missing every secret past that point. Only a 0-byte read is
                    // true EOF here. (M15)
                    let mut filled = 0;
                    let mut hit_eof = false;
                    while filled < window_size {
                        match file.read(&mut buffer[filled..]) {
                            Ok(0) => {
                                hit_eof = true;
                                break;
                            }
                            Ok(n) => filled += n,
                            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(error) => {
                                // A hard read error mid-file: stop scanning this
                                // file rather than emit a torn window with a wrong
                                // offset. Anything already emitted is correct.
                                tracing::warn!(
                                    path = %path.display(),
                                    %error,
                                    "cannot read large file; stopping scan of this file"
                                );
                                let _event =
                                    crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                                let _ = emit(Err(keyhog_core::SourceError::Io(error))); // LAW10: unused-binding marker; no runtime effect, not a fallback
                                return;
                            }
                        }
                    }
                    if filled == 0 {
                        break;
                    }
                    let data = String::from_utf8_lossy(&buffer[..filled]).into_owned();
                    let chunk = Ok(Chunk {
                        data: data.into(),
                        metadata: ChunkMetadata {
                            source_type: "filesystem/windowed".to_string(),
                            path: Some(display.clone()),
                            base_offset: current_offset,
                            base_line: current_base_line,
                            mtime_ns: live_mtime_ns,
                            size_bytes: Some(file_size),
                            decoded_span: None,
                            ..Default::default()
                        },
                    });
                    if !emit(chunk) {
                        return;
                    }
                    if hit_eof || filled < window_size {
                        break;
                    }
                    // Rewind by the overlap so a secret straddling the window cut
                    // is scanned whole in the next window. If the seek fails the
                    // stream position has NOT moved back, so `current_offset` must
                    // track the real position (advance by the full `filled`) to
                    // keep `base_offset` metadata consistent with the bytes we
                    // actually read - otherwise reported finding locations drift.
                    // (M15)
                    match file.seek(SeekFrom::Current(-(window_overlap as i64))) {
                        Ok(_) => {
                            let advanced = filled - window_overlap;
                            current_base_line +=
                                memchr::memchr_iter(b'\n', &buffer[..advanced]).count();
                            current_offset += advanced;
                        }
                        Err(_error) => {
                            // Law 10: seek-back failed => advance offset by full `filled` to keep base_offset metadata consistent; accounting-only, recall-neutral
                            current_base_line +=
                                memchr::memchr_iter(b'\n', &buffer[..filled]).count();
                            current_offset += filled;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "cannot open large file; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                let _ = emit(Err(keyhog_core::SourceError::Io(error))); // LAW10: unused-binding marker; no runtime effect, not a fallback
            }
        }
        return;
    }

    let file_text = if file_size >= MMAP_THRESHOLD {
        read::read_file_mmap(&path)
    } else {
        read::read_file_buffered(&path, file_size)
    };

    let (content, source_type) = match file_text {
        Some(text) if !text.is_empty() => (text.into(), "filesystem"),
        _ => match read::read_file_safe(&path, file_size) {
            Ok(bytes) => {
                let strings = crate::strings::extract_printable_strings(&bytes, 8);
                if strings.is_empty() {
                    return;
                }
                tracing::info!(
                    path = %path.display(),
                    "file is not valid text; scanning printable strings only"
                );
                (
                    keyhog_core::SensitiveString::join(&strings, "\n"),
                    "filesystem:binary-strings",
                )
            }
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "cannot read file; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                let _ = emit(Err(keyhog_core::SourceError::Io(error))); // LAW10: unused-binding marker; no runtime effect, not a fallback
                return;
            }
        },
    };

    if !emit(Ok(Chunk {
        data: content,
        metadata: ChunkMetadata {
            source_type: source_type.to_string(),
            path: Some(display_path(&path)),
            mtime_ns: live_mtime_ns,
            size_bytes: Some(file_size),
            decoded_span: None,
            ..Default::default()
        },
    })) {
        tracing::debug!("filesystem chunk consumer stopped before final chunk");
    }
}

/// Read the mtime as nanoseconds-since-UNIX-epoch via a single `stat`.
/// Returns `None` when the platform/filesystem doesn't expose a usable
/// modified time - in that case the cache fast-path simply doesn't fire,
/// which is strictly better than a false skip.
fn file_mtime_ns(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?; // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
    let modified = meta.modified().ok()?; // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?; // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
    let nanos = dur.as_secs() as u128 * 1_000_000_000 + dur.subsec_nanos() as u128;
    Some(u64::try_from(nanos).unwrap_or(u64::MAX)) // LAW10: empty/absent => documented numeric default, recall-safe
}
