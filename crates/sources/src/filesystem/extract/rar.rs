//! RAR archive extraction for filesystem entries.

use super::archive::{chunk_from_archive_content, validate_scan_archive_entry_name};
use super::{display_path, is_symlink, read};
use keyhog_core::{Chunk, SourceError};
use rars::{Archive, ArchiveReader};
use std::io::Write;
use std::path::Path;

const UNCAPPED_ARCHIVE_BUDGET: u64 = 1024 * 1024 * 1024;

pub(super) fn extract_rar_chunks(
    path: &Path,
    max_size: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    if is_symlink(path) {
        tracing::warn!(
            archive = %path.display(),
            "refusing to open RAR archive at a symlink path - prevents the link-swap attack class"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        emit(Err(SourceError::Other(format!(
            "failed to scan RAR archive '{}': refusing symlink archive path; archive was not scanned",
            path.display()
        ))));
        return;
    }

    let file_bytes = match read::read_file_for_compressed_input(path, max_size) {
        Some(bytes) => bytes,
        None => return,
    };
    let archive = match ArchiveReader::read(file_bytes.as_slice()) {
        Ok(archive) => archive,
        Err(error) => {
            tracing::warn!(
                archive = %path.display(),
                %error,
                "cannot open RAR archive; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            emit(Err(SourceError::Other(format!(
                "failed to scan RAR archive '{}': cannot open archive ({error}); archive was not scanned",
                path.display()
            ))));
            return;
        }
    };

    let mut state = RarExtractionState::new(path, max_size);
    match &archive {
        Archive::Rar13(archive) => {
            for entry in &archive.entries {
                let entry_name = entry.name_lossy();
                let entry_size = u64::from(entry.header.unp_size);
                if !state.entry_should_scan(&entry_name, entry_size, entry.is_directory()) {
                    if state.archive_truncated {
                        break;
                    }
                    continue;
                }
                if entry.is_encrypted() || entry.is_split_before() || entry.is_split_after() {
                    state.report_unreadable_entry(
                        &entry_name,
                        "unsupported encrypted or split RAR entry",
                    );
                    continue;
                }
                let mut sink =
                    RarEntrySink::new(entry_name.clone(), entry_size, state.per_entry_cap);
                match entry.write_to(archive, None, &mut sink) {
                    Ok(()) => state.emit_entry(emit, sink),
                    Err(error) => {
                        state.report_entry_error(&entry_name, &error);
                    }
                }
                if state.consumer_stopped {
                    return;
                }
                if state.archive_truncated {
                    break;
                }
            }
        }
        Archive::Rar15To40(archive) => {
            for entry in archive.files() {
                let entry_name = entry.name_lossy();
                let entry_size = entry.unp_size;
                if !state.entry_should_scan(&entry_name, entry_size, entry.is_directory()) {
                    if state.archive_truncated {
                        break;
                    }
                    continue;
                }
                if entry.is_encrypted() || entry.is_split_before() || entry.is_split_after() {
                    state.report_unreadable_entry(
                        &entry_name,
                        "unsupported encrypted or split RAR entry",
                    );
                    continue;
                }
                let mut sink =
                    RarEntrySink::new(entry_name.clone(), entry_size, state.per_entry_cap);
                match entry.write_to(archive, None, &mut sink) {
                    Ok(()) => state.emit_entry(emit, sink),
                    Err(error) => {
                        state.report_entry_error(&entry_name, &error);
                    }
                }
                if state.consumer_stopped {
                    return;
                }
                if state.archive_truncated {
                    break;
                }
            }
        }
        Archive::Rar50Plus(archive) => {
            for entry in archive.files() {
                let entry_name = entry.name_lossy();
                let entry_size = entry.unpacked_size;
                if !state.entry_should_scan(&entry_name, entry_size, entry.is_directory()) {
                    if state.archive_truncated {
                        break;
                    }
                    continue;
                }
                if entry.encrypted
                    || entry.is_split_before()
                    || entry.is_split_after()
                    || entry.is_redirection()
                {
                    state.report_unreadable_entry(
                        &entry_name,
                        "unsupported encrypted, split, or redirected RAR entry",
                    );
                    continue;
                }
                let mut sink =
                    RarEntrySink::new(entry_name.clone(), entry_size, state.per_entry_cap);
                match entry.write_to(archive, None, &mut sink) {
                    Ok(()) => state.emit_entry(emit, sink),
                    Err(error) => {
                        state.report_entry_error(&entry_name, &error);
                    }
                }
                if state.consumer_stopped {
                    return;
                }
                if state.archive_truncated {
                    break;
                }
            }
        }
        _ => {
            tracing::warn!(
                archive = %path.display(),
                "unsupported RAR archive family; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            emit(Err(SourceError::Other(format!(
                "failed to scan RAR archive '{}': unsupported RAR archive family; archive was not scanned",
                path.display()
            ))));
        }
    }
}

struct RarExtractionState<'a> {
    archive_path: &'a Path,
    archive_display: String,
    per_entry_cap: u64,
    total_budget: u64,
    total_uncompressed: u64,
    consumer_stopped: bool,
    archive_truncated: bool,
}

impl<'a> RarExtractionState<'a> {
    fn new(archive_path: &'a Path, max_size: u64) -> Self {
        Self {
            archive_path,
            archive_display: display_path(archive_path),
            per_entry_cap: if max_size == 0 { u64::MAX } else { max_size },
            total_budget: if max_size == 0 {
                UNCAPPED_ARCHIVE_BUDGET
            } else {
                max_size.saturating_mul(4)
            },
            total_uncompressed: 0,
            consumer_stopped: false,
            archive_truncated: false,
        }
    }

    fn entry_should_scan(&mut self, entry_name: &str, entry_size: u64, is_directory: bool) -> bool {
        if is_directory || super::super::filter::is_default_excluded(entry_name) {
            return false;
        }
        if let Err(reason) = validate_scan_archive_entry_name(entry_name) {
            tracing::warn!(
                archive = %self.archive_path.display(),
                entry = %entry_name,
                reason,
                "skipping unsafe RAR entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return false;
        }
        if entry_size > self.per_entry_cap {
            tracing::warn!(
                archive = %self.archive_path.display(),
                entry = %entry_name,
                size = entry_size,
                "skipping RAR entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return false;
        }
        if self.total_uncompressed.saturating_add(entry_size) > self.total_budget {
            eprintln!(
                "keyhog: WARNING: aborting RAR extraction of {} at {} bytes \
                 (> {} = 4x --max-file-size; archive-bomb guard) - remaining entries were NOT scanned.",
                self.archive_path.display(),
                self.total_uncompressed.saturating_add(entry_size),
                self.total_budget
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
            self.archive_truncated = true;
            return false;
        }
        true
    }

    fn report_unreadable_entry(&self, entry_name: &str, reason: &str) {
        tracing::warn!(
            archive = %self.archive_path.display(),
            entry = %entry_name,
            reason,
            "skipping RAR entry"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    }

    fn report_entry_error(&self, entry_name: &str, error: &rars::Error) {
        tracing::warn!(
            archive = %self.archive_path.display(),
            entry = %entry_name,
            %error,
            "cannot read RAR entry; skipping"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    }

    fn emit_entry(
        &mut self,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
        sink: RarEntrySink,
    ) {
        let actual_uncompressed = sink.content.len() as u64;
        if actual_uncompressed > self.per_entry_cap {
            tracing::warn!(
                archive = %self.archive_path.display(),
                entry = %sink.entry_name,
                size = actual_uncompressed,
                "skipping RAR entry: decoded size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return;
        }
        self.total_uncompressed = self.total_uncompressed.saturating_add(actual_uncompressed);
        if self.total_uncompressed > self.total_budget {
            eprintln!(
                "keyhog: WARNING: aborting RAR extraction of {} at {} bytes \
                 (> {} = 4x --max-file-size; archive-bomb guard) - remaining entries were NOT scanned.",
                self.archive_path.display(),
                self.total_uncompressed,
                self.total_budget
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
            self.archive_truncated = true;
            return;
        }
        if let Some(chunk) =
            chunk_from_archive_content(&self.archive_display, &sink.entry_name, sink.content)
        {
            self.consumer_stopped = !emit(chunk);
        }
    }
}

struct RarEntrySink {
    entry_name: String,
    content: Vec<u8>,
    cap: u64,
}

impl RarEntrySink {
    fn new(entry_name: String, expected_size: u64, cap: u64) -> Self {
        let capacity = expected_size.min(64 * 1024) as usize;
        Self {
            entry_name,
            content: Vec::with_capacity(capacity),
            cap,
        }
    }
}

impl Write for RarEntrySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_len = self.content.len().saturating_add(buf.len()) as u64;
        if next_len > self.cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR entry decoded size exceeds per-file cap",
            ));
        }
        self.content.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
