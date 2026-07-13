//! Compressed stream and tar-container extraction for filesystem entries.

use super::archive::{emit_archive_unreadable_error, validate_scan_archive_entry_name};
use super::{
    display_path, extraction_total_budget, extraction_total_budget_usize, is_symlink, read,
    record_default_excluded_archive_entry,
};
use keyhog_core::{Chunk, SourceError};
use std::path::Path;

/// The single-stream compression format of a `.gz` / `.zst` / `.lz4` / `.sz` /
/// `.bz2` / `.xz` (or `.tgz`) file, inferred from its extension.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CompressedFormat {
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
    // Cap the reader at `budget + 1` bytes: one over the budget so the caller
    // can tell "hit the cap" from "exactly fit". Every decoder below streams,
    // so a decompression bomb can never allocate beyond this ceiling.
    let budget_u64 = u64::try_from(budget).unwrap_or(u64::MAX); // LAW10: unreachable on real platforms, only a wider-than-u64 usize target takes this arm, where u64::MAX is the largest stream cap the shared reader can represent.
    let read_cap = budget_u64.saturating_add(1);
    let read = match format {
        CompressedFormat::Gzip => {
            // MultiGzDecoder: stock `gzip -c` of multiple files, and some tools,
            // emit concatenated gzip members; the plain GzDecoder stops after
            // the first member and would silently drop the rest.
            Some(read_decoder_prefix(
                flate2::read::MultiGzDecoder::new(compressed),
                read_cap,
            ))
        }
        CompressedFormat::Zstd => match zstd::stream::read::Decoder::new(compressed) {
            Ok(mut dec) => {
                // Bound libzstd's INTERNAL window allocation to the extraction
                // budget. The shared cap helper caps decoded OUTPUT, but a crafted
                // tiny `.zst` can advertise a large `windowLog` and force that
                // allocation before producing a single byte.
                match dec.window_log_max(crate::compression_limits::zstd_window_log_max_for_budget(
                    budget_u64,
                )) {
                    Ok(()) => Some(read_decoder_prefix(dec, read_cap)),
                    Err(_error) => None,
                }
            }
            Err(_error) => None,
        },
        CompressedFormat::Lz4 => Some(read_decoder_prefix(
            lz4_flex::frame::FrameDecoder::new(compressed),
            read_cap,
        )),
        CompressedFormat::Snappy => Some(read_decoder_prefix(
            snap::read::FrameDecoder::new(compressed),
            read_cap,
        )),
        CompressedFormat::Bzip2 => Some(read_decoder_prefix(
            bzip2::read::MultiBzDecoder::new(compressed),
            read_cap,
        )),
        CompressedFormat::Xz => match xz2::stream::Stream::new_stream_decoder(budget_u64, 0) {
            Ok(stream) => Some(read_decoder_prefix(
                xz2::read::XzDecoder::new_stream(compressed, stream),
                read_cap,
            )),
            Err(_error) => None,
        },
    }?;

    match read.error {
        None => Some(DecompressedBytes {
            bytes: read.bytes,
            recovered_after_error: false,
        }),
        // A premature-EOF / decode error after producing some bytes still leaves
        // the decoded prefix in `out`; scan what we recovered rather than drop
        // the whole file.
        Some(_error) if !read.bytes.is_empty() => Some(DecompressedBytes {
            bytes: read.bytes,
            recovered_after_error: true,
        }),
        Some(_error) => None, // LAW10: unrecognized/partial => caller scans whole-file/recovered prefix; recall-preserving
    }
}

fn read_decoder_prefix(
    reader: impl std::io::Read,
    cap: u64,
) -> crate::capped_read::CappedReadPrefix {
    crate::capped_read::read_to_cap_preserving_error(reader, cap, None)
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
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    let mut total_uncompressed: u64 = 0;
    emit_tar_entries_with_state(
        tar_bytes,
        container_display,
        max_size,
        &mut total_uncompressed,
        0,
        respect_default_excludes,
        emit,
    );
}

pub(super) fn emit_tar_entries_with_state(
    tar_bytes: &[u8],
    container_display: &str,
    max_size: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
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
                // Law 10: a dropped tar entry is an UNKNOWN, count it as
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

        // Header size is a cap-check input and read pre-alloc hint only; a
        // corrupt/absent header field => 0. The entry body is still read to
        // `read_cap` below from the archive framing, so recall is unaffected.
        let entry_size = match entry.header().size() {
            Ok(size) => size,
            Err(error) => {
                tracing::warn!(
                    archive = %container_display,
                    entry = %entry_name,
                    %error,
                    "tar entry header has no valid size; using the bounded streaming reader"
                );
                0
            }
        };

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
        if respect_default_excludes && super::super::filter::is_default_excluded(&entry_name) {
            record_default_excluded_archive_entry(container_display, &entry_name);
            continue;
        }
        if max_size > 0 && entry_size > max_size {
            // Law 10: an over-cap tar entry is dropped from the scan, count it so
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
            // Law 10: a tar-bomb abort truncates extraction, the remaining
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

        let read_cap = if max_size > 0 { max_size } else { u64::MAX };
        let read = match crate::capped_read::read_to_cap(&mut entry, read_cap, Some(entry_size)) {
            Ok(read) => read,
            Err(error) => {
                // Law 10: a tar entry whose body could not be read is an UNKNOWN
                // dropped from the scan (count it).
                tracing::warn!(archive = %container_display, entry = %entry_name, %error, "failed to read tar entry body");
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit_tar_entry_error(
                    emit,
                    container_display,
                    &entry_name,
                    format!("cannot read entry body ({error}); entry was not scanned"),
                ) {
                    return;
                }
                continue;
            }
        };
        if read.truncated {
            let observed_size = read_cap.saturating_add(1);
            tracing::warn!(
                archive = %container_display,
                entry = %entry_name,
                size = observed_size,
                cap = max_size,
                "skipping tar entry: decoded size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_tar_entry_error(
                emit,
                container_display,
                &entry_name,
                format!(
                    "decoded size {observed_size} exceeds per-file cap {max_size}; entry was not scanned"
                ),
            ) {
                return;
            }
            continue;
        }
        let content = read.bytes;

        // Re-dispatch every member through the canonical handler: a tar / zip /
        // compressed member is recursed (its TRUE bytes scanned), anything else
        // is leaf-scanned with the shared UTF-16-aware decoder. One dispatch
        // point shared with the zip and 7z extractors -- see
        // `super::emit_archive_member` -- so a nested archive is never silently
        // leaf-scanned as printable strings (Law 10).
        let member_display = format!("{container_display}//{entry_name}");
        if !super::emit_archive_member(
            &entry_name,
            content,
            &member_display,
            max_size,
            total_uncompressed,
            nested_depth,
            respect_default_excludes,
            emit,
        ) {
            return;
        }
    }
}

pub(super) fn entry_is_embedded_tar(entry_name: &str, content: &[u8]) -> bool {
    let has_tar_ext = Path::new(entry_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("tar"));
    has_tar_ext && looks_like_tar(content)
}

/// Return the single-stream compression format of a tar/zip MEMBER whose name
/// carries a recognized compressed extension (`.gz` / `.tgz` / `.zst` / `.lz4`
/// / `.sz` / `.bz2` / `.xz`). A member with such an extension must be
/// decompressed and its true bytes scanned -- routing the compressed bytes to
/// the printable-strings path SILENTLY loses a secret in the payload (Law 10).
pub(super) fn compressed_member_format(entry_name: &str) -> Option<CompressedFormat> {
    let ext = Path::new(entry_name).extension().and_then(|e| e.to_str())?;
    CompressedFormat::from_ext(ext)
}

/// Decompress a compressed archive MEMBER in memory and scan its TRUE bytes:
/// untar if the decompressed stream is a tar container, else emit it as one
/// UTF-16-aware chunk -- exactly what the standalone compressed-file path does.
///
/// This closes a Law-10 silent false-clean. Previously a `.gz` member inside a
/// `.tar` (or `.zip`) fell through to the printable-strings path, so a secret
/// in its compressed payload was reported "clean" with no coverage gap.
/// Recursion into a decompressed tar is bounded by `nested_depth`; total
/// decompressed output is bounded by the shared tar/zip-bomb `total_uncompressed`
/// budget and the per-member decompress cap. Every drop (decompress failure,
/// recovered-prefix, bomb-cap truncation) is surfaced and counted, never
/// silent. Returns `true` to keep scanning, `false` when the consumer stopped.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_decompressed_member(
    format: CompressedFormat,
    content: &[u8],
    nested_display: &str,
    max_size: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let budget = extraction_total_budget_usize(max_size);
    let decompressed = match decompress_to_bytes(format, content, budget) {
        Some(d) => d,
        None => {
            // Law 10: the compressed member could not be decompressed => its
            // content was NOT scanned. Surface + count; never a silent clean.
            tracing::warn!(member = %nested_display, "failed to decompress archive member; not scanned");
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return emit(Err(SourceError::Other(format!(
                "failed to scan compressed archive member '{nested_display}': failed to decompress member; member was not scanned"
            ))));
        }
    };
    if decompressed.recovered_after_error {
        // Law 10: only the recovered prefix was scanned; surface the partial.
        let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
        if !emit(Err(SourceError::Other(format!(
            "decompression of archive member '{nested_display}' failed after recovering {} bytes; only the recovered prefix was scanned and the rest was not scanned",
            decompressed.bytes.len()
        )))) {
            return false;
        }
    }
    let decompressed = decompressed.bytes;
    if decompressed.len() > budget {
        // Law 10: the decompressed stream hit the per-member bomb cap; only the
        // prefix is scanned, the tail is NOT. Surface loudly + count.
        let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
        if !emit(Err(SourceError::Other(format!(
            "decompression of archive member '{nested_display}' was truncated at {} bytes by the zip-bomb guard (budget {budget}); the remaining compressed stream was not scanned",
            decompressed.len()
        )))) {
            return false;
        }
    }
    *total_uncompressed = (*total_uncompressed).saturating_add(decompressed.len() as u64);
    let total_budget = extraction_total_budget(max_size);
    if total_budget > 0 && *total_uncompressed > total_budget {
        // Law 10: the cumulative tar/zip-bomb budget is exhausted; surface the
        // partial-coverage abort (counted by report_archive_truncation).
        let error =
            super::report_archive_truncation(nested_display, *total_uncompressed, total_budget);
        return emit(Err(error));
    }

    if looks_like_tar(&decompressed) {
        emit_tar_entries_with_state(
            &decompressed,
            nested_display,
            max_size,
            total_uncompressed,
            nested_depth + 1,
            respect_default_excludes,
            emit,
        );
        return true;
    }

    // Leaf: scan the true decompressed bytes (UTF-16-aware), identical to the
    // standalone compressed-file path so recall is parity across the two.
    match super::chunk_from_extracted_entry(
        decompressed,
        nested_display.to_string(),
        "filesystem/archive",
        "filesystem/archive-binary",
    ) {
        Some(chunk) => emit(chunk),
        None => true,
    }
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
    respect_default_excludes: bool,
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
        emit_tar_entries(
            &decompressed,
            &path_display,
            max_size,
            respect_default_excludes,
            emit,
        );
        return;
    }

    // Canonical UTF-16-aware decode shared with every other extractor: a UTF-16
    // file compressed as `foo.txt.gz` keeps recall parity with the uncompressed
    // read path instead of being dropped as NUL-separated bytes.
    if let Some(chunk) = super::chunk_from_extracted_entry(
        decompressed,
        path_display,
        "filesystem/compressed",
        "filesystem/compressed-binary",
    ) {
        if !emit(chunk) {
            tracing::debug!("compressed chunk consumer stopped before final chunk");
        }
    }
}

fn report_compressed_recovered_after_error(path: &Path, decoded_len: usize) -> SourceError {
    eprintln!(
        "keyhog: WARNING: decompression of {} produced a {} byte prefix and then failed, only the recovered prefix was scanned; the rest was NOT.",
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
    // Law 10: the decompressed stream was truncated at the bomb cap, only the
    // prefix is scanned, the tail is NOT. Surface loudly + count as a
    // truncated archive so the operator sees the partial coverage (the old
    // `tracing::warn!` was invisible at default verbosity).
    eprintln!(
        "keyhog: WARNING: decompression of {} hit the {} byte cap (= 4x --max-file-size; \
         zip-bomb guard), only the truncated {}-byte prefix was scanned; the rest was NOT.",
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
