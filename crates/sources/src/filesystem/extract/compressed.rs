//! Compressed stream and tar-container extraction for filesystem entries.

use super::archive::{emit_archive_unreadable_error, validate_scan_archive_entry_name};
use super::{
    display_path, extraction_total_budget, extraction_total_budget_usize, is_symlink, read,
    record_binary_without_printable_strings, record_default_excluded_archive_entry,
};
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::path::Path;

/// The single-stream compression format of a `.gz` / `.zst` / `.lz4` / `.sz` /
/// `.bz2` / `.xz` (or `.tgz`) file, inferred from its extension.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompressedFormat {
    Gzip,
    Zstd,
    Lz4,
    Snappy,
    Bzip2,
    Xz,
}

struct DecompressedBytes {
    bytes: Vec<u8>,
    recovered_after_error: bool,
}

impl CompressedFormat {
    fn from_ext(ext: &str) -> Option<Self> {
        if ext.eq_ignore_ascii_case("gz") || is_tgz_ext(ext) {
            // `.tgz` is `gzip(tar)`; the outer stream is always gzip.
            Some(CompressedFormat::Gzip)
        } else if ext.eq_ignore_ascii_case("zst") {
            Some(CompressedFormat::Zstd)
        } else if ext.eq_ignore_ascii_case("lz4") {
            Some(CompressedFormat::Lz4)
        } else if ext.eq_ignore_ascii_case("sz") {
            Some(CompressedFormat::Snappy)
        } else if ext.eq_ignore_ascii_case("bz2") {
            Some(CompressedFormat::Bzip2)
        } else if ext.eq_ignore_ascii_case("xz") {
            Some(CompressedFormat::Xz)
        } else {
            None
        }
    }
}

pub(super) fn is_compressed_ext(ext: &str) -> bool {
    CompressedFormat::from_ext(ext).is_some()
}

fn is_tgz_ext(ext: &str) -> bool {
    ext.eq_ignore_ascii_case("tgz")
}

fn decompress_to_bytes(
    format: CompressedFormat,
    compressed: &[u8],
    budget: usize,
) -> Option<DecompressedBytes> {
    use std::io::Read as _;

    // Cap the reader at `budget + 1` bytes: one over the budget so the caller
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
            Ok(mut dec) => {
                // Bound libzstd's INTERNAL window allocation to the extraction
                // budget. `.take(take_limit)` caps decoded OUTPUT, but a crafted
                // tiny `.zst` can advertise a large `windowLog` and force that
                // allocation before producing a single byte.
                match dec.window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    budget as u64,
                )) {
                    Ok(()) => dec.take(take_limit).read_to_end(&mut out),
                    Err(e) => Err(e),
                }
            }
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
        CompressedFormat::Bzip2 => {
            let mut dec = bzip2::read::MultiBzDecoder::new(compressed).take(take_limit);
            dec.read_to_end(&mut out)
        }
        CompressedFormat::Xz => match xz2::stream::Stream::new_stream_decoder(budget as u64, 0) {
            Ok(stream) => {
                let mut dec = xz2::read::XzDecoder::new_stream(compressed, stream).take(take_limit);
                dec.read_to_end(&mut out)
            }
            Err(error) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        },
    };

    match read_result {
        Ok(_) => Some(DecompressedBytes {
            bytes: out,
            recovered_after_error: false,
        }),
        // A premature-EOF / decode error after producing some bytes still leaves
        // the decoded prefix in `out`; scan what we recovered rather than drop
        // the whole file.
        Err(_) if !out.is_empty() => Some(DecompressedBytes {
            bytes: out,
            recovered_after_error: true,
        }),
        Err(_) => None, // LAW10: unrecognized/partial => caller scans whole-file/recovered prefix; recall-preserving
    }
}

/// True when `data` is likely a POSIX/ustar/GNU tar stream.
pub(super) fn looks_like_tar(data: &[u8]) -> bool {
    data.len() >= 512 && (&data[257..262] == b"ustar" || &data[257..265] == b"ustar  \0")
}

/// Untar an already-decompressed (or raw `.tar`) byte stream and emit one chunk
/// per regular file entry, tagged with the inner `archive//entry` path.
pub(super) fn emit_tar_entries(
    tar_bytes: &[u8],
    container_display: &str,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let mut total_uncompressed: u64 = 0;
    emit_tar_entries_with_state(
        tar_bytes,
        container_display,
        max_size,
        &mut total_uncompressed,
        0,
        emit,
    );
}

fn emit_tar_entries_with_state(
    tar_bytes: &[u8],
    container_display: &str,
    max_size: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    use std::io::Read as _;

    const MAX_EMBEDDED_TAR_DEPTH: usize = 8;

    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(error) => {
            // Law 10: the tar could not be enumerated => no entries scanned; count it.
            tracing::warn!(archive = %container_display, %error, "failed to read tar entries");
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_unreadable_error(
                emit,
                "tar archive",
                container_display,
                "failed to read tar entries",
                error,
            ) {
                return;
            }
            return;
        }
    };

    let total_budget: u64 = extraction_total_budget(max_size);

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(error) => {
                // Law 10: a dropped tar entry is an UNKNOWN — count it as
                // unreadable so coverage reflects it.
                tracing::warn!(archive = %container_display, %error, "skipping unreadable tar entry");
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit_tar_entry_error(
                    emit,
                    container_display,
                    "<tar-entry>",
                    format!("cannot read tar entry header ({error})"),
                ) {
                    return;
                }
                continue;
            }
        };

        let entry_name = entry
            .path()
            .ok() // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<tar-entry>".to_string()); // LAW10: missing/non-string field => empty/placeholder; recall-safe
        let entry_type = entry.header().entry_type();

        // Only regular files carry content. Directories are structural metadata;
        // symlinks, hardlinks, devices, and FIFOs are refused visibly because the
        // scanner does not follow or materialize tar link targets.
        if entry_type.is_dir() {
            continue;
        }
        if entry_type != tar::EntryType::Regular {
            tracing::warn!(
                archive = %container_display,
                entry = %entry_name,
                ?entry_type,
                "skipping non-regular tar entry"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_tar_entry_error(
                emit,
                container_display,
                &entry_name,
                format!("non-regular tar entry type {entry_type:?}; entry was not scanned"),
            ) {
                return;
            }
            continue;
        }

        let entry_size = entry.header().size().unwrap_or(0); // LAW10: empty/absent => documented numeric default, recall-safe

        if let Err(reason) = validate_scan_archive_entry_name(&entry_name) {
            tracing::warn!(
                archive = %container_display,
                entry = %entry_name,
                reason,
                "skipping unsafe tar entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_tar_entry_error(
                emit,
                container_display,
                &entry_name,
                format!("{reason}; entry was not scanned"),
            ) {
                return;
            }
            continue;
        }
        if super::super::filter::is_default_excluded(&entry_name) {
            record_default_excluded_archive_entry(container_display, &entry_name);
            continue;
        }
        if max_size > 0 && entry_size > max_size {
            // Law 10: an over-cap tar entry is dropped from the scan — count it so
            // coverage reflects the gap (the operator can re-scan with a larger cap).
            tracing::warn!(
                archive = %container_display,
                entry = %entry_name,
                size = entry_size,
                "skipping tar entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_tar_entry_error(
                emit,
                container_display,
                &entry_name,
                format!(
                    "uncompressed size {entry_size} exceeds per-file cap {max_size}; entry was not scanned"
                ),
            ) {
                return;
            }
            continue;
        }
        *total_uncompressed = (*total_uncompressed).saturating_add(entry_size);
        if total_budget > 0 && *total_uncompressed > total_budget {
            // Law 10: a tar-bomb abort truncates extraction — the remaining
            // entries are NOT scanned, so this is partial coverage the operator
            // must see (the old `tracing::warn!` was invisible at default
            // verbosity). Surface loudly + count.
            let error = super::report_archive_truncation(
                container_display,
                *total_uncompressed,
                total_budget,
            );
            if !emit(Err(error)) {
                return;
            }
            break;
        }

        let mut content: Vec<u8> = Vec::with_capacity(entry_size.min(max_size.max(1)) as usize);
        // Bound the read at the per-file cap even if the header lies about size.
        let read_cap = if max_size > 0 { max_size } else { u64::MAX };
        if entry
            .by_ref()
            .take(read_cap)
            .read_to_end(&mut content)
            .is_err()
        {
            // Law 10: a tar entry whose body could not be read is an UNKNOWN
            // dropped from the scan — count it.
            tracing::warn!(archive = %container_display, entry = %entry_name, "failed to read tar entry body");
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_tar_entry_error(
                emit,
                container_display,
                &entry_name,
                "cannot read entry body; entry was not scanned",
            ) {
                return;
            }
            continue;
        }

        if entry_is_embedded_tar(&entry_name, &content) {
            let nested_display = format!("{container_display}//{entry_name}");
            if nested_depth >= MAX_EMBEDDED_TAR_DEPTH {
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan embedded tar archive '{nested_display}': maximum nested archive depth {MAX_EMBEDDED_TAR_DEPTH} exceeded; embedded archive was not scanned"
                )))) {
                    return;
                }
                continue;
            }
            emit_tar_entries_with_state(
                &content,
                &nested_display,
                max_size,
                total_uncompressed,
                nested_depth + 1,
                emit,
            );
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
                    record_binary_without_printable_strings(&entry_path);
                    None
                } else {
                    Some(Ok(Chunk {
                        data: crate::strings::join_sensitive_strings(&strings, "\n"),
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

fn entry_is_embedded_tar(entry_name: &str, content: &[u8]) -> bool {
    let has_tar_ext = Path::new(entry_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"));
    has_tar_ext && looks_like_tar(content)
}

fn emit_tar_entry_error(
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    container_display: &str,
    entry_name: &str,
    reason: impl std::fmt::Display,
) -> bool {
    emit(Err(SourceError::Other(format!(
        "failed to scan tar entry '{container_display}//{entry_name}': {reason}"
    ))))
}

/// Decompress a `.gz` / `.zst` / `.lz4` / `.sz` / `.bz2` / `.xz` / `.tgz` file
/// to its TRUE decompressed bytes, then either untar it or scan it as a single
/// decompressed file.
pub(super) fn extract_compressed_chunks(
    path: &Path,
    ext: &str,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    // Refuse to open a compressed container that is itself a symlink - same
    // link-swap defense the zip branch applies before reading.
    if is_symlink(path) {
        // Law 10: refused symlink => this compressed path is NOT scanned; count it.
        tracing::warn!(
            path = %path.display(),
            "refusing to open compressed file at a symlink path (link-swap guard)"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        if !emit(Err(SourceError::Other(format!(
            "failed to scan compressed file '{}': refusing to open compressed file at a symlink path; compressed file was not scanned",
            display_path(path)
        )))) {
            return;
        }
        return;
    }

    let Some(format) = CompressedFormat::from_ext(ext) else {
        let path_display = display_path(path);
        if !emit(Err(SourceError::Other(format!(
            "failed to scan compressed file '{path_display}': extension '{ext}' is not a supported compressed stream"
        )))) {
            return;
        }
        return;
    };

    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(b) => b,
        None => {
            let path_display = display_path(path);
            if !emit(Err(SourceError::Other(format!(
                "failed to scan compressed file '{path_display}': cannot read compressed input; compressed file was not scanned"
            )))) {
                return;
            }
            return;
        }
    };
    let compressed = file_bytes.as_slice();
    let budget = extraction_total_budget_usize(max_size);

    let decompressed = match decompress_to_bytes(format, compressed, budget) {
        Some(d) => d,
        None => {
            // Law 10: the compressed file could not be decompressed => its content
            // was NOT scanned. Count it as unreadable so the drop is surfaced.
            tracing::warn!(path = %path.display(), "failed to decompress file; skipping");
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            let path_display = display_path(path);
            if !emit(Err(SourceError::Other(format!(
                "failed to scan compressed file '{path_display}': failed to decompress file; compressed file was not scanned"
            )))) {
                return;
            }
            return;
        }
    };
    if decompressed.recovered_after_error {
        let error = report_compressed_recovered_after_error(path, decompressed.bytes.len());
        if !emit(Err(error)) {
            return;
        }
    }
    let decompressed = decompressed.bytes;
    if decompressed.len() > budget {
        let error = report_compressed_truncation(path, budget, decompressed.len());
        if !emit(Err(error)) {
            return;
        }
    }

    let path_display = display_path(path);

    // `.tgz` is unconditionally a tarball; for the other extensions sniff the
    // decompressed bytes (a `foo.tar.gz` arrives as ext `gz`).
    if is_tgz_ext(ext) || looks_like_tar(&decompressed) {
        emit_tar_entries(&decompressed, &path_display, max_size, emit);
        return;
    }

    let (data, source_type) = match String::from_utf8(decompressed) {
        Ok(s) if !s.is_empty() => (s.into(), "filesystem/compressed"),
        Ok(_) => return,
        Err(error) => {
            let bytes = error.into_bytes();
            let strings = crate::strings::extract_printable_strings(&bytes, 8);
            if strings.is_empty() {
                record_binary_without_printable_strings(&path_display);
                return;
            }
            (
                crate::strings::join_sensitive_strings(&strings, "\n"),
                "filesystem/compressed-binary",
            )
        }
    };

    if !emit(Ok(Chunk {
        data,
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some(path_display),
            ..Default::default()
        },
    })) {
        tracing::debug!("compressed chunk consumer stopped before final chunk");
    }
}

fn report_compressed_recovered_after_error(path: &Path, decoded_len: usize) -> SourceError {
    eprintln!(
        "keyhog: WARNING: decompression of {} produced a {} byte prefix and then failed — only the recovered prefix was scanned; the rest was NOT.",
        path.display(),
        decoded_len
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "decompression of '{}' failed after recovering {decoded_len} bytes; only the recovered prefix was scanned and the remaining compressed stream was not scanned",
        path.display()
    ))
}

fn report_compressed_truncation(path: &Path, budget: usize, decoded_len: usize) -> SourceError {
    // Law 10: the decompressed stream was truncated at the bomb cap — only the
    // prefix is scanned, the tail is NOT. Surface loudly + count as a
    // truncated archive so the operator sees the partial coverage (the old
    // `tracing::warn!` was invisible at default verbosity).
    eprintln!(
        "keyhog: WARNING: decompression of {} hit the {} byte cap (= 4x --max-file-size; \
         zip-bomb guard) — only the truncated {}-byte prefix was scanned; the rest was NOT.",
        path.display(),
        budget,
        decoded_len
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "decompression of '{}' was truncated at {decoded_len} bytes by the zip-bomb guard (budget {budget}); the remaining compressed stream was not scanned",
        path.display()
    ))
}
