//! 7z archive extraction for filesystem entries.

use super::archive::{
    archive_unix_mode_is_special, emit_archive_entry_error, emit_archive_entry_over_cap_error,
    validate_scan_archive_entry_name,
};
use super::{
    display_path, extraction_total_budget, is_symlink, read, record_default_excluded_archive_entry,
};
use keyhog_core::{Chunk, SourceError};
use sevenz_rust2::{ArchiveReader, EncoderMethod, Password};
use std::io::{Cursor, Read};
use std::path::Path;

const READ_CAPACITY_HINT: u64 = 64 * 1024;

pub(super) fn extract_seven_zip_chunks(
    path: &Path,
    max_size: u64,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    if is_symlink(path) {
        tracing::warn!(
            archive = %path.display(),
            "refusing to open 7z archive at a symlink path - prevents the link-swap attack class"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        emit(Err(SourceError::Other(format!(
            "failed to scan 7z archive '{}': refusing symlink archive path; archive was not scanned",
            path.display()
        ))));
        return;
    }

    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(bytes) => bytes,
        None => {
            let archive_display = display_path(path);
            emit(Err(SourceError::Other(format!(
                "failed to scan 7z archive '{archive_display}': cannot read compressed input; archive was not scanned"
            ))));
            return;
        }
    };
    let archive_display = display_path(path);
    let cursor = Cursor::new(file_bytes.as_slice());
    let mut reader = match ArchiveReader::new(cursor, Password::empty()) {
        Ok(reader) => reader,
        Err(error) => {
            tracing::warn!(
                archive = %path.display(),
                %error,
                "cannot open 7z archive; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            emit(Err(SourceError::Other(format!(
                "failed to scan 7z archive '{}': cannot open archive ({error}); archive was not scanned",
                path.display()
            ))));
            return;
        }
    };

    if archive_uses_unbounded_lzma(reader.archive()) {
        tracing::warn!(
            archive = %path.display(),
            "refusing 7z archive using plain LZMA: sevenz-rust2 does not expose a dictionary memory limit for that method"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        emit(Err(SourceError::Other(format!(
            "failed to scan 7z archive '{}': plain LZMA is refused because no dictionary memory limit is available",
            path.display()
        ))));
        return;
    }

    let per_entry_cap = if max_size == 0 { u64::MAX } else { max_size };
    let total_budget = extraction_total_budget(max_size);
    let archive_requires_skip_drain = reader.archive().is_solid;
    let mut total_uncompressed: u64 = 0;
    let mut consumer_stopped = false;
    let mut archive_truncated = false;

    let result = reader.for_each_entries(|entry, entry_reader| {
        if entry.is_directory() {
            return Ok(true);
        }

        let entry_name = entry.name().to_string();
        if seven_zip_entry_is_special(entry) {
            tracing::warn!(
                archive = %archive_display,
                entry = %entry_name,
                attributes = entry.windows_attributes(),
                "skipping 7z special file entry"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_entry_error(
                emit,
                "7z entry",
                &archive_display,
                &entry_name,
                "special file type",
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            if entry.has_stream() {
                if !drain_skipped_entry_if_needed(
                    archive_requires_skip_drain,
                    &archive_display,
                    &entry_name,
                    entry_reader,
                    emit,
                ) {
                    consumer_stopped = true;
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        if !entry.has_stream() {
            return Ok(true);
        }
        if let Err(reason) = validate_scan_archive_entry_name(&entry_name) {
            tracing::warn!(
                archive = %archive_display,
                entry = %entry_name,
                reason,
                "skipping unsafe 7z entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_entry_error(emit, "7z entry", &archive_display, &entry_name, reason) {
                consumer_stopped = true;
                return Ok(false);
            }
            if !drain_skipped_entry_if_needed(
                archive_requires_skip_drain,
                &archive_display,
                &entry_name,
                entry_reader,
                emit,
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            return Ok(true);
        }
        if respect_default_excludes && super::super::filter::is_default_excluded(&entry_name) {
            record_default_excluded_archive_entry(&archive_display, &entry_name);
            if !drain_skipped_entry_if_needed(
                archive_requires_skip_drain,
                &archive_display,
                &entry_name,
                entry_reader,
                emit,
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            return Ok(true);
        }

        let entry_size = entry.size();
        if entry_size > per_entry_cap {
            tracing::warn!(
                archive = %archive_display,
                entry = %entry_name,
                size = entry_size,
                "skipping 7z entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_archive_entry_over_cap_error(
                emit,
                "7z entry",
                &archive_display,
                &entry_name,
                entry_size,
                per_entry_cap,
                "uncompressed",
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            if !drain_skipped_entry_if_needed(
                archive_requires_skip_drain,
                &archive_display,
                &entry_name,
                entry_reader,
                emit,
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            return Ok(true);
        }
        if total_uncompressed.saturating_add(entry_size) > total_budget {
            let error = super::report_archive_truncation(
                &archive_display,
                total_uncompressed.saturating_add(entry_size),
                total_budget,
            );
            archive_truncated = true;
            if !emit(Err(error)) {
                consumer_stopped = true;
            }
            return Ok(false);
        }

        let remaining_budget = total_budget.saturating_sub(total_uncompressed);
        let read_cap = per_entry_cap.min(remaining_budget);
        let read = match crate::capped_read::read_to_cap(
            &mut *entry_reader,
            read_cap,
            Some(entry_size.min(READ_CAPACITY_HINT)),
        ) {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    archive = %archive_display,
                    entry = %entry_name,
                    %error,
                    "cannot read 7z entry; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan 7z entry '{archive_display}//{entry_name}': cannot read entry ({error}); entry was not scanned"
                )))) {
                    consumer_stopped = true;
                    return Ok(false);
                }
                return Ok(true);
            }
        };
        let content = read.bytes;
        if read.truncated && read_cap == per_entry_cap {
            let observed_len = read_cap.saturating_add(1);
            tracing::warn!(
                archive = %archive_display,
                entry = %entry_name,
                size = observed_len,
                cap = per_entry_cap,
                "skipping 7z entry: decoded size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_archive_entry_over_cap_error(
                emit,
                "7z entry",
                &archive_display,
                &entry_name,
                observed_len,
                per_entry_cap,
                "decoded",
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            if !drain_skipped_entry_if_needed(
                archive_requires_skip_drain,
                &archive_display,
                &entry_name,
                entry_reader,
                emit,
            ) {
                consumer_stopped = true;
                return Ok(false);
            }
            return Ok(true);
        }
        if read.truncated {
            let attempted_total = total_uncompressed.saturating_add(read_cap.saturating_add(1));
            let error =
                super::report_archive_truncation(&archive_display, attempted_total, total_budget);
            archive_truncated = true;
            if !emit(Err(error)) {
                consumer_stopped = true;
            }
            return Ok(false);
        }
        total_uncompressed = total_uncompressed.saturating_add(content.len() as u64);

        let entry_path = format!("{archive_display}//{entry_name}");
        if let Some(chunk) = chunk_from_entry_content(content, entry_path) {
            if !emit(chunk) {
                consumer_stopped = true;
                return Ok(false);
            }
        }
        Ok(true)
    });

    if let Err(error) = result {
        tracing::warn!(
            archive = %path.display(),
            %error,
            "7z archive extraction failed before all entries were scanned"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        emit(Err(SourceError::Other(format!(
            "failed to scan 7z archive '{}': extraction failed before all entries were scanned ({error})",
            path.display()
        ))));
    } else if archive_truncated || consumer_stopped {
        tracing::debug!(archive = %path.display(), "7z extraction stopped early");
    }
}

fn archive_uses_unbounded_lzma(archive: &sevenz_rust2::Archive) -> bool {
    archive.blocks.iter().any(|block| {
        block
            .coders
            .iter()
            .any(|coder| coder.encoder_method_id() == EncoderMethod::LZMA.id())
    })
}

fn seven_zip_entry_is_special(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    if !entry.has_windows_attributes {
        return false;
    }
    let mode = entry.windows_attributes() >> 16;
    mode != 0 && archive_unix_mode_is_special(mode)
}

fn drain_skipped_entry_if_needed(
    archive_requires_skip_drain: bool,
    archive_display: &str,
    entry_name: &str,
    entry_reader: &mut dyn Read,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    if !archive_requires_skip_drain {
        // LAW10: non-solid 7z entries are independently seekable; skipped
        // entries were already counted, and no later entry is dropped.
        tracing::debug!(
            archive = %archive_display,
            entry = %entry_name,
            "not draining skipped non-solid 7z entry"
        );
        return true;
    }
    drain_entry_or_stop(archive_display, entry_name, entry_reader, emit)
}

fn drain_entry_or_stop(
    archive_display: &str,
    entry_name: &str,
    entry_reader: &mut dyn Read,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    match std::io::copy(entry_reader, &mut std::io::sink()) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(
                archive = %archive_display,
                entry = %entry_name,
                %error,
                "cannot drain skipped solid 7z entry; stopping archive extraction"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            let _emitted = emit(Err(SourceError::Other(format!(
                "failed to drain skipped solid 7z entry '{archive_display}//{entry_name}': {error}; remaining archive entries were not scanned"
            ))));
            false
        }
    }
}

fn chunk_from_entry_content(
    content: Vec<u8>,
    entry_path: String,
) -> Option<Result<Chunk, SourceError>> {
    // Canonical UTF-16-aware entry decode shared with every other extractor.
    super::chunk_from_extracted_entry(
        content,
        entry_path,
        "filesystem/archive",
        "filesystem/archive-binary",
    )
}
