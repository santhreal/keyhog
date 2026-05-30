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
    } else if ext == "gz" || ext == "zst" || ext == "lz4" || ext == "sz" {
        extract_compressed_chunks(&path, max_size, emit);
        return;
    } else if ext == "har" {
        if let Ok(bytes) = std::fs::read(&path) {
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
            while let Ok(n) = file.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let data = String::from_utf8_lossy(&buffer[..n]).into_owned();
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
                if n < window_size {
                    break;
                }
                let _ = file.seek(SeekFrom::Current(-(window_overlap as i64)));
                current_offset += n - window_overlap;
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

fn extract_compressed_chunks(
    path: &Path,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    let format = match ext.as_str() {
        "gz" => ziftsieve::CompressionFormat::Gzip,
        "zst" => ziftsieve::CompressionFormat::Zstd,
        "lz4" => ziftsieve::CompressionFormat::Lz4,
        _ => ziftsieve::CompressionFormat::Snappy,
    };

    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(b) => b,
        None => return,
    };
    let bytes = file_bytes.as_slice();
    let total_budget: usize = max_size.saturating_mul(4) as usize;

    if let Ok(blocks) = ziftsieve::extract_from_bytes(format, bytes) {
        let mut current_chunk_literals = String::new();
        let mut total_decompressed: usize = 0;
        let path_display = display_path(path);
        for block in blocks {
            if let Ok(s) = std::str::from_utf8(block.literals()) {
                total_decompressed = total_decompressed.saturating_add(s.len());
                if total_decompressed > total_budget {
                    tracing::warn!(
                        path = %path.display(),
                        bytes = total_decompressed,
                        cap = total_budget,
                        "aborting compressed extraction: total decompressed size exceeds 4x file cap (gzip-bomb guard)"
                    );
                    break;
                }
                current_chunk_literals.push_str(s);
                current_chunk_literals.push('\n');
            }

            if current_chunk_literals.len() > 8 * 1024 * 1024 {
                if !emit(Ok(Chunk {
                    data: std::mem::take(&mut current_chunk_literals).into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/compressed".into(),
                        path: Some(path_display.clone()),
                        ..Default::default()
                    },
                })) {
                    return;
                }
            }
        }
        if !current_chunk_literals.is_empty() {
            let _ = emit(Ok(Chunk {
                data: current_chunk_literals.into(),
                metadata: ChunkMetadata {
                    source_type: "filesystem/compressed".into(),
                    path: Some(path_display),
                    ..Default::default()
                },
            }));
        }
    }
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
