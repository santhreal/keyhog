//! 7z archive extraction for filesystem entries.

use super::archive::validate_scan_archive_entry_name;
use super::{
    display_path, extraction_total_budget, is_symlink, read,
    record_binary_without_printable_strings, record_default_excluded_archive_entry,
};
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use sevenz_rust2::{ArchiveReader, EncoderMethod, Password};
use std::io::{Cursor, Read};
use std::path::Path;

const READ_CAPACITY_HINT: u64 = 64 * 1024;

pub(super) fn extract_seven_zip_chunks(
    path: &Path,
    max_size: u64,
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
        None => return,
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
    let mut total_uncompressed: u64 = 0;
    let mut consumer_stopped = false;
    let mut archive_truncated = false;

    let result = reader.for_each_entries(|entry, entry_reader| {
        if entry.is_directory() || !entry.has_stream() {
            return Ok(true);
        }

        let entry_name = entry.name().to_string();
        if let Err(reason) = validate_scan_archive_entry_name(&entry_name) {
            tracing::warn!(
                archive = %archive_display,
                entry = %entry_name,
                reason,
                "skipping unsafe 7z entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            drain_entry(entry_reader)?;
            return Ok(true);
        }
        if super::super::filter::is_default_excluded(&entry_name) {
            record_default_excluded_archive_entry(&archive_display, &entry_name);
            drain_entry(entry_reader)?;
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
            drain_entry(entry_reader)?;
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

        let mut content = Vec::with_capacity(entry_size.min(READ_CAPACITY_HINT) as usize);
        entry_reader.read_to_end(&mut content)?;
        total_uncompressed = total_uncompressed.saturating_add(content.len() as u64);
        if total_uncompressed > total_budget {
            let error = super::report_archive_truncation(
                &archive_display,
                total_uncompressed,
                total_budget,
            );
            archive_truncated = true;
            if !emit(Err(error)) {
                consumer_stopped = true;
            }
            return Ok(false);
        }

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

fn drain_entry(entry_reader: &mut dyn Read) -> Result<(), sevenz_rust2::Error> {
    std::io::copy(entry_reader, &mut std::io::sink())?;
    Ok(())
}

fn chunk_from_entry_content(
    content: Vec<u8>,
    entry_path: String,
) -> Option<Result<Chunk, SourceError>> {
    match String::from_utf8(content) {
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
    }
}
