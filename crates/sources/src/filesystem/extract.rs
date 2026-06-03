use super::display_path;
use super::filter::{is_default_excluded, skip_extensions};
use super::read;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
        .unwrap_or(false)
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
pub(super) fn process_entry(
    entry: codewalk::FileEntry,
    merkle: &Option<Arc<MerkleIndex>>,
    skipped: &Arc<AtomicUsize>,
    max_size: u64,
    window_size: usize,
    window_overlap: usize,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let path = entry.path;
    let file_size = entry.size;

    // Screen out `.min.js` and `.bundle.js` files instantly using fast checks before reading/metadata stats (KH-55)
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if is_default_excluded(filename) {
        return;
    }
    if filename.contains(".min.")
        || filename.contains(".bundle.")
        || filename.ends_with(".chunk.js")
        || filename.ends_with(".min.js")
        || filename.ends_with(".bundle.js")
    {
        return;
    }

    if max_size > 0 && file_size > max_size {
        tracing::warn!(
            path = %path.display(),
            size_bytes = file_size,
            max_size,
            "skipping file: size exceeds --max-file-size cap"
        );
        crate::SKIPPED_OVER_MAX_SIZE.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Compile the SKIP_EXTENSIONS array into a fast HashSet at startup to accelerate file-type screening (KH-45)
    if skip_extensions().contains(ext.as_str()) {
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

    if ext == "zip" || ext == "apk" || ext == "ipa" || ext == "crx" || ext == "jar" {
        if is_symlink(&path) {
            tracing::warn!(
                archive = %path.display(),
                "refusing to open archive at a symlink path - \
                 prevents the link-swap attack class"
            );
            return;
        }
        let archive_display = display_path(&path);
        let mut total_uncompressed: u64 = 0;
        let total_budget: u64 = max_size.saturating_mul(4);
        if let Ok(pack) = openpack::OpenPack::open_default(&path) {
            if let Ok(entries) = pack.entries() {
                for archive_entry in entries {
                    if archive_entry.is_dir || is_default_excluded(&archive_entry.name) {
                        continue;
                    }
                    if archive_entry.uncompressed_size > max_size {
                        tracing::warn!(
                            archive = %path.display(),
                            entry = %archive_entry.name,
                            size = archive_entry.uncompressed_size,
                            "skipping archive entry: uncompressed size exceeds per-file cap"
                        );
                        continue;
                    }
                    total_uncompressed =
                        total_uncompressed.saturating_add(archive_entry.uncompressed_size);
                    if total_uncompressed > total_budget {
                        tracing::warn!(
                            archive = %path.display(),
                            "aborting archive extraction: total uncompressed size exceeds 4x file cap (zip-bomb guard)"
                        );
                        break;
                    }
                    if let Ok(content) = pack.read_entry(&archive_entry.name) {
                        let entry_path = || format!("{}//{}", archive_display, archive_entry.name);
                        let chunk = match String::from_utf8(content) {
                            Ok(s) => Some(Ok(Chunk {
                                data: s.into(),
                                metadata: ChunkMetadata {
                                    source_type: "filesystem/archive".into(),
                                    path: Some(entry_path()),
                                    ..Default::default()
                                },
                            })),
                            Err(error) => {
                                let content = error.into_bytes();
                                let strings =
                                    crate::strings::extract_printable_strings(&content, 8);
                                if strings.is_empty() {
                                    None
                                } else {
                                    Some(Ok(Chunk {
                                        data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                        metadata: ChunkMetadata {
                                            source_type: "filesystem/archive-binary".into(),
                                            path: Some(entry_path()),
                                            ..Default::default()
                                        },
                                    }))
                                }
                            }
                        };
                        if let Some(chunk) = chunk {
                            if !emit(chunk) {
                                return;
                            }
                        }
                    }
                }
            }
        }
        return;
    } else if ext == "tar" {
        // Bare (uncompressed) `.tar`: unpack per-entry exactly as the zip
        // branch does, so a secret committed inside a tarball (docker layer
        // export, helm chart, source tarball — the dominant Linux/cloud
        // archive) is found just like one inside a `.zip`. `emit_tar_entries`
        // enforces the same per-entry size cap and 4x total-uncompressed
        // (tar-bomb) budget as the zip branch.
        if is_symlink(&path) {
            tracing::warn!(
                archive = %path.display(),
                "refusing to open archive at a symlink path - \
                 prevents the link-swap attack class"
            );
            return;
        }
        // `read_file_safe` opens with `O_NOFOLLOW` on Unix / `symlink_metadata`
        // refusal on Windows, so an `--include`d `bundle.tar -> ~/.aws/...`
        // symlink can't redirect the read to an off-tree target.
        if let Ok(bytes) = read::read_file_safe(&path) {
            // Guard against a non-tar file with a `.tar` extension: only untar
            // when the ustar/GNU magic is actually present, otherwise fall
            // through to the normal scan path so the bytes are still examined.
            if looks_like_tar(&bytes) {
                emit_tar_entries(&bytes, &display_path(&path), max_size, emit);
                return;
            }
        }
    } else if ext == "gz" || ext == "zst" || ext == "lz4" || ext == "sz" || ext == "tgz" {
        // `.gz` / `.tar.gz` (ext `gz`) / `.tgz` / `.zst` / `.lz4` / `.sz`:
        // fully decompress, then untar per-entry if the decompressed stream is
        // a tar container, else scan the real decompressed bytes. (`.tgz` is
        // removed from SKIP_EXTENSIONS so it reaches this branch.)
        extract_compressed_chunks(&path, max_size, emit);
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
        if let Ok(bytes) = read::read_file_safe(&path) {
            let path_str = display_path(&path);
            if let Some(har_chunks) = crate::har::try_expand_har(&bytes, &path_str, max_size) {
                for chunk in har_chunks {
                    if !emit(chunk) {
                        return;
                    }
                }
                return;
            }
        }
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
                        mtime_ns: live_mtime_ns,
                        size_bytes: Some(file_size),
                        ..Default::default()
                    },
                });
                if !emit(chunk) {
                    return;
                }
            }
            return;
        }
        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut current_offset = 0;
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
                        Err(_) => {
                            // A hard read error mid-file: stop scanning this
                            // file rather than emit a torn window with a wrong
                            // offset. Anything already emitted is correct.
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
                        mtime_ns: live_mtime_ns,
                        size_bytes: Some(file_size),
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
                    Ok(_) => current_offset += filled - window_overlap,
                    Err(_) => current_offset += filled,
                }
            }
        }
        return;
    }

    let file_text = if file_size >= MMAP_THRESHOLD {
        read::read_file_mmap(&path)
    } else {
        read::read_file_buffered(&path)
    };

    let (content, source_type) = match file_text {
        Some(text) if !text.is_empty() => (text.into(), "filesystem"),
        _ => {
            if let Ok(bytes) = read::read_file_safe(&path) {
                let strings = crate::strings::extract_printable_strings(&bytes, 8);
                if strings.is_empty() {
                    return;
                }
                (
                    keyhog_core::SensitiveString::join(&strings, "\n"),
                    "filesystem:binary-strings",
                )
            } else {
                return;
            }
        }
    };

    let _ = emit(Ok(Chunk {
        data: content,
        metadata: ChunkMetadata {
            source_type: source_type.to_string(),
            path: Some(display_path(&path)),
            mtime_ns: live_mtime_ns,
            size_bytes: Some(file_size),
            ..Default::default()
        },
    }));
}

/// The single-stream compression format of a `.gz` / `.zst` / `.lz4` / `.sz`
/// (or `.tgz`) file, inferred from its extension.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompressedFormat {
    Gzip,
    Zstd,
    Lz4,
    Snappy,
}

impl CompressedFormat {
    fn from_ext(ext: &str) -> Self {
        match ext {
            // `.tgz` is `gzip(tar)`; the outer stream is always gzip.
            "gz" | "tgz" => CompressedFormat::Gzip,
            "zst" => CompressedFormat::Zstd,
            "lz4" => CompressedFormat::Lz4,
            _ => CompressedFormat::Snappy,
        }
    }
}

/// Fully decompress `compressed` into the TRUE decompressed byte stream,
/// stopping once `budget` bytes have been produced (the 4x zip-bomb guard).
///
/// This replaces the old `ziftsieve::extract_from_bytes(..).literals()`
/// reassembly, which only emitted DEFLATE *literal* runs (ziftsieve is a bloom
/// PREFILTER: it deliberately drops LZ77 back-references) and spliced a
/// synthetic `\n` between blocks — so a credential that spanned a back-
/// reference or a block boundary was torn and never reached the scanner. A
/// real `flate2`/`zstd`/`lz4`/`snap` decode resolves every back-reference and
/// yields the exact original bytes.
///
/// Returns `None` if the stream is not valid for the declared format. A
/// truncated-at-budget decode returns the bytes produced so far (`Some`) so an
/// oversize-but-valid archive still surfaces the secrets in its first 4x slice.
fn decompress_to_bytes(format: CompressedFormat, compressed: &[u8], budget: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;

    // Cap the *reader* at `budget + 1` bytes: one over the budget so the caller
    // can tell "hit the cap" from "exactly fit". Every decoder below streams,
    // so a decompression bomb can never allocate beyond this ceiling.
    let take_limit = (budget as u64).saturating_add(1);
    let mut out = Vec::new();
    let read_result = match format {
        CompressedFormat::Gzip => {
            // MultiGzDecoder: stock `gzip -c` of multiple files, and some tools,
            // emit concatenated gzip members; the plain GzDecoder stops after
            // the first member and would silently drop the rest.
            let mut dec = flate2::read::MultiGzDecoder::new(compressed).take(take_limit);
            dec.read_to_end(&mut out)
        }
        CompressedFormat::Zstd => match zstd::stream::read::Decoder::new(compressed) {
            Ok(dec) => dec.take(take_limit).read_to_end(&mut out),
            Err(e) => Err(e),
        },
        CompressedFormat::Lz4 => {
            let mut dec = lz4_flex::frame::FrameDecoder::new(compressed).take(take_limit);
            dec.read_to_end(&mut out)
        }
        CompressedFormat::Snappy => {
            let mut dec = snap::read::FrameDecoder::new(compressed).take(take_limit);
            dec.read_to_end(&mut out)
        }
    };

    match read_result {
        Ok(_) => Some(out),
        // A premature-EOF / decode error after producing some bytes still leaves
        // the decoded prefix in `out`; scan what we recovered rather than drop
        // the whole file (a torn tail must not hide an intact secret in the
        // head). A hard format mismatch with zero output returns None.
        Err(_) if !out.is_empty() => Some(out),
        Err(_) => None,
    }
}

/// True when `data` is (very likely) a POSIX/ustar/GNU tar stream. A tar header
/// block is 512 bytes with the magic `ustar` at offset 257. We require at least
/// one full header block and the magic, which no plain text/JSON/PEM file
/// carries at that fixed offset.
fn looks_like_tar(data: &[u8]) -> bool {
    data.len() >= 512 && (&data[257..262] == b"ustar" || &data[257..265] == b"ustar  \0")
}

/// Untar an already-decompressed (or raw `.tar`) byte stream and emit one chunk
/// per regular file entry, tagged with the inner `archive//entry` path so the
/// reported location is the file inside the tarball, not the opaque container.
/// Enforces the same per-entry size cap and 4x total-uncompressed budget as the
/// zip branch.
fn emit_tar_entries(
    tar_bytes: &[u8],
    container_display: &str,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    use std::io::Read as _;

    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(error) => {
            tracing::warn!(archive = %container_display, %error, "failed to read tar entries");
            return;
        }
    };

    let total_budget: u64 = max_size.saturating_mul(4);
    let mut total_uncompressed: u64 = 0;

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(error) => {
                tracing::warn!(archive = %container_display, %error, "skipping unreadable tar entry");
                continue;
            }
        };

        // Only regular files carry content; skip dirs, symlinks, hardlinks,
        // devices, fifos. (A tar symlink entry has no body to read, and we
        // never follow it to a target on disk — no link-swap surface.)
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }

        let entry_size = entry.header().size().unwrap_or(0);
        let entry_name = entry
            .path()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<tar-entry>".to_string());

        if super::filter::is_default_excluded(&entry_name) {
            continue;
        }
        if max_size > 0 && entry_size > max_size {
            tracing::warn!(
                archive = %container_display,
                entry = %entry_name,
                size = entry_size,
                "skipping tar entry: uncompressed size exceeds per-file cap"
            );
            continue;
        }
        total_uncompressed = total_uncompressed.saturating_add(entry_size);
        if total_budget > 0 && total_uncompressed > total_budget {
            tracing::warn!(
                archive = %container_display,
                "aborting tar extraction: total uncompressed size exceeds 4x file cap (tar-bomb guard)"
            );
            break;
        }

        let mut content: Vec<u8> = Vec::with_capacity(entry_size.min(max_size.max(1)) as usize);
        // Bound the read at the per-file cap even if the header lies about size.
        let read_cap = if max_size > 0 { max_size } else { u64::MAX };
        if entry.by_ref().take(read_cap).read_to_end(&mut content).is_err() {
            tracing::warn!(archive = %container_display, entry = %entry_name, "failed to read tar entry body");
            continue;
        }

        let entry_path = format!("{container_display}//{entry_name}");
        let chunk = match String::from_utf8(content) {
            Ok(s) if !s.is_empty() => Some(Ok(Chunk {
                data: s.into(),
                metadata: ChunkMetadata {
                    source_type: "filesystem/archive".into(),
                    path: Some(entry_path),
                    ..Default::default()
                },
            })),
            Ok(_) => None,
            Err(error) => {
                let bytes = error.into_bytes();
                let strings = crate::strings::extract_printable_strings(&bytes, 8);
                if strings.is_empty() {
                    None
                } else {
                    Some(Ok(Chunk {
                        data: keyhog_core::SensitiveString::join(&strings, "\n"),
                        metadata: ChunkMetadata {
                            source_type: "filesystem/archive-binary".into(),
                            path: Some(entry_path),
                            ..Default::default()
                        },
                    }))
                }
            }
        };
        if let Some(chunk) = chunk {
            if !emit(chunk) {
                return;
            }
        }
    }
}

/// Decompress a `.gz` / `.zst` / `.lz4` / `.sz` / `.tgz` file to its TRUE
/// decompressed bytes, then either untar it (when the decompressed stream is a
/// tar container — `.tgz`, `.tar.gz`, `.tar.zst`, …) or scan it as a single
/// decompressed file. This is the per-file entry point routed from
/// `process_entry`.
fn extract_compressed_chunks(
    path: &Path,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    // Refuse to open a compressed container that is itself a symlink — same
    // link-swap defense the zip branch applies before reading.
    if is_symlink(path) {
        tracing::warn!(
            path = %path.display(),
            "refusing to open compressed file at a symlink path (link-swap guard)"
        );
        return;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let format = CompressedFormat::from_ext(&ext);

    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(b) => b,
        None => return,
    };
    let compressed = file_bytes.as_slice();
    let total_budget: usize = max_size.saturating_mul(4) as usize;
    let budget = if total_budget == 0 {
        // max_size==0 means "no cap"; still bound the decode so a bomb cannot
        // OOM the process. 1 GiB is far above any real source file.
        1024 * 1024 * 1024
    } else {
        total_budget
    };

    let decompressed = match decompress_to_bytes(format, compressed, budget) {
        Some(d) => d,
        None => {
            tracing::warn!(path = %path.display(), "failed to decompress file; skipping");
            return;
        }
    };
    if decompressed.len() >= budget {
        tracing::warn!(
            path = %path.display(),
            bytes = decompressed.len(),
            cap = budget,
            "compressed extraction hit the 4x decompressed-size cap (zip-bomb guard); scanning the truncated prefix"
        );
    }

    let path_display = display_path(path);

    // `.tgz` is unconditionally a tarball; for the other extensions sniff the
    // decompressed bytes (a `foo.tar.gz` arrives as ext `gz`). When it is a tar,
    // untar per-entry so each inner file is scanned whole with its real path,
    // instead of feeding the scanner the raw 512-byte-header-interleaved tar
    // framing (which tore the credential and reported the wrong path).
    if ext == "tgz" || looks_like_tar(&decompressed) {
        emit_tar_entries(&decompressed, &path_display, max_size, emit);
        return;
    }

    // Plain compressed single file: scan the real decompressed text. Binary
    // payloads fall back to printable-string extraction, matching the
    // uncompressed filesystem path.
    let (data, source_type) = match String::from_utf8(decompressed) {
        Ok(s) if !s.is_empty() => (s.into(), "filesystem/compressed"),
        Ok(_) => return,
        Err(error) => {
            let bytes = error.into_bytes();
            let strings = crate::strings::extract_printable_strings(&bytes, 8);
            if strings.is_empty() {
                return;
            }
            (
                keyhog_core::SensitiveString::join(&strings, "\n"),
                "filesystem/compressed-binary",
            )
        }
    };

    let _ = emit(Ok(Chunk {
        data,
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some(path_display),
            ..Default::default()
        },
    }));
}

/// Read the mtime as nanoseconds-since-UNIX-epoch via a single `stat`.
/// Returns `None` when the platform/filesystem doesn't expose a usable
/// modified time - in that case the cache fast-path simply doesn't fire,
/// which is strictly better than a false skip.
fn file_mtime_ns(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dur = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    let nanos = dur.as_secs() as u128 * 1_000_000_000 + dur.subsec_nanos() as u128;
    Some(u64::try_from(nanos).unwrap_or(u64::MAX))
}
