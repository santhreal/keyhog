//! Compressed stream and tar-container extraction for filesystem entries.

use super::{display_path, is_symlink, read, record_binary_without_printable_strings};
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

impl CompressedFormat {
    fn from_ext(ext: &str) -> Self {
        match ext {
            // `.tgz` is `gzip(tar)`; the outer stream is always gzip.
            "gz" | "tgz" => CompressedFormat::Gzip,
            "zst" => CompressedFormat::Zstd,
            "lz4" => CompressedFormat::Lz4,
            "bz2" => CompressedFormat::Bzip2,
            "xz" => CompressedFormat::Xz,
            _ => CompressedFormat::Snappy,
        }
    }
}

/// Smallest zstd `windowLog` whose window (`1 << log`) covers `budget`, clamped
/// to libzstd's valid range `[10, 31]`.
pub(crate) fn budget_window_log_max(budget: usize) -> u32 {
    let b = (budget.max(1 << 10)) as u64; // floor the window at 1 KiB
    let log = 64 - (b - 1).leading_zeros(); // ceil(log2(b))
    log.clamp(10, 31)
}

fn decompress_to_bytes(
    format: CompressedFormat,
    compressed: &[u8],
    budget: usize,
) -> Option<Vec<u8>> {
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
                match dec.window_log_max(budget_window_log_max(budget)) {
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
        Ok(_) => Some(out),
        // A premature-EOF / decode error after producing some bytes still leaves
        // the decoded prefix in `out`; scan what we recovered rather than drop
        // the whole file.
        Err(_) if !out.is_empty() => Some(out),
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
    use std::io::Read as _;

    let mut archive = tar::Archive::new(std::io::Cursor::new(tar_bytes));
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(error) => {
            // Law 10: the tar could not be enumerated => no entries scanned; count it.
            tracing::warn!(archive = %container_display, %error, "failed to read tar entries");
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return;
        }
    };

    let total_budget: u64 = max_size.saturating_mul(4);
    let mut total_uncompressed: u64 = 0;

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(error) => {
                // Law 10: a dropped tar entry is an UNKNOWN — count it as
                // unreadable so coverage reflects it.
                tracing::warn!(archive = %container_display, %error, "skipping unreadable tar entry");
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                continue;
            }
        };

        // Only regular files carry content; skip dirs, symlinks, hardlinks,
        // devices, fifos. We never follow tar symlink entries to disk.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }

        let entry_size = entry.header().size().unwrap_or(0); // LAW10: empty/absent => documented numeric default, recall-safe
        let entry_name = entry
            .path()
            .ok() // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "<tar-entry>".to_string()); // LAW10: missing/non-string field => empty/placeholder; recall-safe

        if super::super::filter::is_default_excluded(&entry_name) {
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
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            continue;
        }
        total_uncompressed = total_uncompressed.saturating_add(entry_size);
        if total_budget > 0 && total_uncompressed > total_budget {
            // Law 10: a tar-bomb abort truncates extraction — the remaining
            // entries are NOT scanned, so this is partial coverage the operator
            // must see (the old `tracing::warn!` was invisible at default
            // verbosity). Surface loudly + count.
            let error = super::report_archive_truncation(
                container_display,
                total_uncompressed,
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

/// Decompress a `.gz` / `.zst` / `.lz4` / `.sz` / `.bz2` / `.xz` / `.tgz` file
/// to its TRUE decompressed bytes, then either untar it or scan it as a single
/// decompressed file.
pub(super) fn extract_compressed_chunks(
    path: &Path,
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
        return;
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("") // LAW10: missing/non-string field => empty/placeholder; recall-safe
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
            // Law 10: the compressed file could not be decompressed => its content
            // was NOT scanned. Count it as unreadable so the drop is surfaced.
            tracing::warn!(path = %path.display(), "failed to decompress file; skipping");
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return;
        }
    };
    if decompressed.len() >= budget {
        let error = report_compressed_truncation(path, budget, decompressed.len());
        if !emit(Err(error)) {
            return;
        }
    }

    let path_display = display_path(path);

    // `.tgz` is unconditionally a tarball; for the other extensions sniff the
    // decompressed bytes (a `foo.tar.gz` arrives as ext `gz`).
    if ext == "tgz" || looks_like_tar(&decompressed) {
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
