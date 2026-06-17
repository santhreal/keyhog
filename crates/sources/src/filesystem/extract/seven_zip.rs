//! 7z archive extraction for filesystem entries.

use super::{display_path, is_symlink, read};
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use sevenz_rust2::{ArchiveReader, EncoderMethod, Password};
use std::io::{Cursor, Read};
use std::path::Path;

const UNCAPPED_ARCHIVE_BUDGET: u64 = 1024 * 1024 * 1024;
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
            return;
        }
    };

    if archive_uses_unbounded_lzma(reader.archive()) {
        tracing::warn!(
            archive = %path.display(),
            "refusing 7z archive using plain LZMA: sevenz-rust2 does not expose a dictionary memory limit for that method"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return;
    }

    let per_entry_cap = if max_size == 0 { u64::MAX } else { max_size };
    let total_budget = if max_size == 0 {
        UNCAPPED_ARCHIVE_BUDGET
    } else {
        max_size.saturating_mul(4)
    };
    let mut total_uncompressed: u64 = 0;
    let mut consumer_stopped = false;
    let mut archive_truncated = false;

    let result = reader.for_each_entries(|entry, entry_reader| {
        if entry.is_directory() || !entry.has_stream() {
            return Ok(true);
        }

        let entry_name = entry.name().to_string();
        if super::super::filter::is_default_excluded(&entry_name) {
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
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            drain_entry(entry_reader)?;
            return Ok(true);
        }
        if total_uncompressed.saturating_add(entry_size) > total_budget {
            eprintln!(
                "keyhog: WARNING: aborting 7z extraction of {archive_display} at {} bytes \
                 (> {total_budget} = 4x --max-file-size; archive-bomb guard) - remaining entries were NOT scanned.",
                total_uncompressed.saturating_add(entry_size)
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
            archive_truncated = true;
            return Ok(false);
        }

        let mut content = Vec::with_capacity(entry_size.min(READ_CAPACITY_HINT) as usize);
        entry_reader.read_to_end(&mut content)?;
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
    }
}
