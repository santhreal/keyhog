//! RAR archive extraction for filesystem entries.

use super::archive::{
    chunk_from_archive_content, emit_archive_entry_over_cap_error, validate_scan_archive_entry_name,
};
use super::{
    display_path, extraction_total_budget, is_symlink, read, record_default_excluded_archive_entry,
};
use keyhog_core::{Chunk, SourceError};
use rars::{Archive, ArchiveReader};
use std::io::Write;
use std::path::Path;

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
        None => {
            let archive_display = display_path(path);
            emit(Err(SourceError::Other(format!(
                "failed to scan RAR archive '{archive_display}': cannot read compressed input; archive was not scanned"
            ))));
            return;
        }
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
                if !state.entry_should_scan(&entry_name, entry_size, entry.is_directory(), emit) {
                    if state.consumer_stopped {
                        return;
                    }
                    if state.archive_truncated {
                        break;
                    }
                    continue;
                }
                if entry.is_encrypted() || entry.is_split_before() || entry.is_split_after() {
                    state.report_unreadable_entry(
                        &entry_name,
                        "unsupported encrypted or split RAR entry",
                        emit,
                    );
                    if state.consumer_stopped {
                        return;
                    }
                    continue;
                }
                let mut sink = RarEntrySink::new(entry_name.clone(), entry_size, state.sink_cap());
                match entry.write_to(archive, None, &mut sink) {
                    Ok(()) => state.emit_entry(emit, sink),
                    Err(error) => {
                        state.report_entry_error(&entry_name, sink.hit_cap(), &error, emit);
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
                if !state.entry_should_scan(&entry_name, entry_size, entry.is_directory(), emit) {
                    if state.consumer_stopped {
                        return;
                    }
                    if state.archive_truncated {
                        break;
                    }
                    continue;
                }
                if entry.is_encrypted() || entry.is_split_before() || entry.is_split_after() {
                    state.report_unreadable_entry(
                        &entry_name,
                        "unsupported encrypted or split RAR entry",
                        emit,
                    );
                    if state.consumer_stopped {
                        return;
                    }
                    continue;
                }
                let mut sink = RarEntrySink::new(entry_name.clone(), entry_size, state.sink_cap());
                match entry.write_to(archive, None, &mut sink) {
                    Ok(()) => state.emit_entry(emit, sink),
                    Err(error) => {
                        state.report_entry_error(&entry_name, sink.hit_cap(), &error, emit);
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
                if !state.entry_should_scan(&entry_name, entry_size, entry.is_directory(), emit) {
                    if state.consumer_stopped {
                        return;
                    }
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
                        emit,
                    );
                    if state.consumer_stopped {
                        return;
                    }
                    continue;
                }
                let mut sink = RarEntrySink::new(entry_name.clone(), entry_size, state.sink_cap());
                match entry.write_to(archive, None, &mut sink) {
                    Ok(()) => state.emit_entry(emit, sink),
                    Err(error) => {
                        state.report_entry_error(&entry_name, sink.hit_cap(), &error, emit);
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
            total_budget: extraction_total_budget(max_size),
            total_uncompressed: 0,
            consumer_stopped: false,
            archive_truncated: false,
        }
    }

    fn entry_should_scan(
        &mut self,
        entry_name: &str,
        entry_size: u64,
        is_directory: bool,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) -> bool {
        if is_directory {
            return false;
        }
        if super::super::filter::is_default_excluded(entry_name) {
            record_default_excluded_archive_entry(&self.archive_display, entry_name);
            return false;
        }
        if let Err(reason) = validate_scan_archive_entry_name(entry_name) {
            tracing::warn!(
                archive = %self.archive_path.display(),
                entry = %entry_name,
                reason,
                "skipping unsafe RAR entry name"
            );
            self.report_unreadable_entry(entry_name, reason, emit);
            return false;
        }
        if entry_size > self.per_entry_cap {
            tracing::warn!(
                archive = %self.archive_path.display(),
                entry = %entry_name,
                size = entry_size,
                "skipping RAR entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            self.report_entry_over_cap(entry_name, entry_size, "uncompressed", emit);
            return false;
        }
        if self.total_uncompressed.saturating_add(entry_size) > self.total_budget {
            self.report_archive_truncation(
                self.total_uncompressed.saturating_add(entry_size),
                emit,
            );
            return false;
        }
        true
    }

    fn report_unreadable_entry(
        &mut self,
        entry_name: &str,
        reason: &str,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) {
        tracing::warn!(
            archive = %self.archive_path.display(),
            entry = %entry_name,
            reason,
            "skipping RAR entry"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        self.consumer_stopped = !emit(Err(SourceError::Other(format!(
            "failed to scan RAR entry '{}//{}': {reason}; entry was not scanned",
            self.archive_display, entry_name
        ))));
    }

    fn report_entry_over_cap(
        &mut self,
        entry_name: &str,
        size: u64,
        size_kind: &str,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) {
        self.consumer_stopped = !emit_archive_entry_over_cap_error(
            emit,
            "RAR entry",
            &self.archive_display,
            entry_name,
            size,
            self.per_entry_cap,
            size_kind,
        );
    }

    fn report_entry_error(
        &mut self,
        entry_name: &str,
        hit_sink_cap: bool,
        error: &rars::Error,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) {
        if hit_sink_cap {
            if self.sink_cap() < self.per_entry_cap {
                self.report_archive_truncation(self.total_budget.saturating_add(1), emit);
            } else {
                tracing::warn!(
                    archive = %self.archive_path.display(),
                    entry = %entry_name,
                    cap = self.per_entry_cap,
                    "skipping RAR entry: decoded size exceeds per-file cap; remaining entries were NOT scanned"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
                self.archive_truncated = true;
                self.consumer_stopped = !emit(Err(SourceError::Other(format!(
                    "RAR entry '{}//{}' exceeded the per-file cap during capped decode; remaining entries were not scanned",
                    self.archive_display, entry_name
                ))));
            }
            return;
        }
        tracing::warn!(
            archive = %self.archive_path.display(),
            entry = %entry_name,
            %error,
            "cannot read RAR entry; skipping"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        self.consumer_stopped = !emit(Err(SourceError::Other(format!(
            "failed to scan RAR entry '{}//{}': cannot read entry ({error}); entry was not scanned",
            self.archive_display, entry_name
        ))));
    }

    fn sink_cap(&self) -> u64 {
        self.per_entry_cap
            .min(self.total_budget.saturating_sub(self.total_uncompressed))
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
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            self.report_entry_over_cap(&sink.entry_name, actual_uncompressed, "decoded", emit);
            return;
        }
        self.total_uncompressed = self.total_uncompressed.saturating_add(actual_uncompressed);
        if self.total_uncompressed > self.total_budget {
            self.report_archive_truncation(self.total_uncompressed, emit);
            return;
        }
        if let Some(chunk) =
            chunk_from_archive_content(&self.archive_display, &sink.entry_name, sink.content)
        {
            self.consumer_stopped = !emit(chunk);
        }
    }

    fn report_archive_truncation(
        &mut self,
        attempted_total: u64,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) {
        let error = super::report_archive_truncation(
            &self.archive_display,
            attempted_total,
            self.total_budget,
        );
        self.archive_truncated = true;
        self.consumer_stopped = !emit(Err(error));
    }
}

struct RarEntrySink {
    entry_name: String,
    content: Vec<u8>,
    cap: u64,
    hit_cap: bool,
}

impl RarEntrySink {
    fn new(entry_name: String, expected_size: u64, cap: u64) -> Self {
        let capacity = expected_size.min(64 * 1024) as usize;
        Self {
            entry_name,
            content: Vec::with_capacity(capacity),
            cap,
            hit_cap: false,
        }
    }

    fn hit_cap(&self) -> bool {
        self.hit_cap
    }
}

impl Write for RarEntrySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_len = self.content.len().saturating_add(buf.len()) as u64;
        if next_len > self.cap {
            self.hit_cap = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR entry decoded size exceeds configured extraction cap",
            ));
        }
        self.content.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
