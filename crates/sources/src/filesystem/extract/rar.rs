//! RAR archive extraction for filesystem entries.

use super::archive::{
    archive_unix_mode_is_special, chunk_from_archive_content, emit_archive_entry_over_cap_error,
    validate_scan_archive_entry_name,
};
use super::{
    display_path, extraction_total_budget, is_symlink, read, record_default_excluded_archive_entry,
};
use keyhog_core::{Chunk, SourceError};
use rars::{Archive, ArchiveReader};
use std::cell::RefCell;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

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
            if extract_rar15_40_solid_regular_chunks(archive, &mut state, emit) {
                return;
            }
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
                if rar15_40_entry_is_special(entry) {
                    state.report_unreadable_entry(&entry_name, "special file type", emit);
                    if state.consumer_stopped {
                        return;
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
            if extract_rar50_solid_regular_chunks(archive, &mut state, emit) {
                return;
            }
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
                if rar50_entry_is_special(entry) {
                    state.report_unreadable_entry(&entry_name, "special file type", emit);
                    if state.consumer_stopped {
                        return;
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

const RAR_LEGACY_UNIX_HOST_OS: u64 = 3;
const RAR5_UNIX_HOST_OS: u64 = 1;

fn rar15_40_entry_is_special(entry: &rars::rar15_40::FileHeader) -> bool {
    if u64::from(entry.host_os) != RAR_LEGACY_UNIX_HOST_OS {
        return false;
    }
    archive_unix_mode_is_special(entry.attr) || archive_unix_mode_is_special(entry.attr >> 16)
}

fn rar50_entry_is_special(entry: &rars::rar50::FileHeader) -> bool {
    rar_unix_attr_is_special(entry.host_os, entry.attributes)
}

fn rar_unix_attr_is_special(host_os: u64, attr: u64) -> bool {
    matches!(host_os, RAR_LEGACY_UNIX_HOST_OS | RAR5_UNIX_HOST_OS)
        && archive_unix_mode_is_special((attr & u64::from(u32::MAX)) as u32)
}

fn extract_rar15_40_solid_regular_chunks(
    archive: &rars::rar15_40::Archive,
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let files: Vec<_> = archive.files().collect();
    if !archive.main.is_solid() && !files.iter().any(|entry| entry.is_solid()) {
        return false;
    }
    if !files.iter().all(|entry| {
        state.entry_is_solid_regular_candidate(
            &entry.name_lossy(),
            entry.unp_size,
            entry.is_directory(),
        ) && !entry.is_encrypted()
            && !entry.is_split_before()
            && !entry.is_split_after()
            && !rar15_40_entry_is_special(entry)
    }) {
        return false;
    }
    let Some(total) = files.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.unp_size)
            .filter(|sum| *sum <= state.total_budget)
    }) else {
        return false;
    };
    if total > state.total_budget {
        return false;
    }
    let cap = state.total_budget;
    extract_solid_regular_entries(
        state,
        emit,
        |decoded| {
            archive.extract_to(rars::ArchiveReadOptions::default(), |meta| {
                Ok(Box::new(SolidRarEntrySink::new(
                    String::from_utf8_lossy(&meta.name).into_owned(),
                    cap,
                    Rc::clone(decoded),
                )))
            })
        },
        "RAR 1.5-4.0 solid archive",
    );
    true
}

fn extract_rar50_solid_regular_chunks(
    archive: &rars::rar50::Archive,
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let files: Vec<_> = archive.files().collect();
    if !archive.main.is_solid()
        && !files.iter().any(|entry| {
            entry
                .decoded_compression_info()
                .is_ok_and(|info| info.solid)
        })
    {
        return false;
    }
    if !files.iter().all(|entry| {
        state.entry_is_solid_regular_candidate(
            &entry.name_lossy(),
            entry.unpacked_size,
            entry.is_directory(),
        ) && !entry.encrypted
            && !entry.is_split_before()
            && !entry.is_split_after()
            && !entry.is_redirection()
            && !rar50_entry_is_special(entry)
    }) {
        return false;
    }
    let Some(total) = files.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(entry.unpacked_size)
            .filter(|sum| *sum <= state.total_budget)
    }) else {
        return false;
    };
    if total > state.total_budget {
        return false;
    }
    let cap = state.total_budget;
    extract_solid_regular_entries(
        state,
        emit,
        |decoded| {
            archive.extract_to(rars::ArchiveReadOptions::default(), |meta| {
                Ok(Box::new(SolidRarEntrySink::new(
                    String::from_utf8_lossy(&meta.name).into_owned(),
                    cap,
                    Rc::clone(decoded),
                )))
            })
        },
        "RAR5 solid archive",
    );
    true
}

fn extract_solid_regular_entries<F>(
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    extract: F,
    archive_kind: &str,
) where
    F: FnOnce(&Rc<RefCell<Vec<RarDecodedEntry>>>) -> rars::Result<()>,
{
    let decoded = Rc::new(RefCell::new(Vec::new()));
    match extract(&decoded) {
        Ok(()) => {
            for entry in decoded.borrow_mut().drain(..) {
                state.emit_entry(emit, RarEntrySink::from_decoded(entry));
                if state.consumer_stopped || state.archive_truncated {
                    return;
                }
            }
        }
        Err(error) => {
            state.report_archive_decode_error(archive_kind, &error, emit);
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

    fn entry_is_solid_regular_candidate(
        &self,
        entry_name: &str,
        entry_size: u64,
        is_directory: bool,
    ) -> bool {
        !is_directory
            && !super::super::filter::is_default_excluded(entry_name)
            && validate_scan_archive_entry_name(entry_name).is_ok()
            && entry_size <= self.per_entry_cap
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

    fn report_archive_decode_error(
        &mut self,
        archive_kind: &str,
        error: &rars::Error,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) {
        tracing::warn!(
            archive = %self.archive_path.display(),
            %archive_kind,
            %error,
            "cannot read solid RAR archive; skipping"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        self.consumer_stopped = !emit(Err(SourceError::Other(format!(
            "failed to scan {archive_kind} '{}': cannot read archive ({error}); archive was not scanned",
            self.archive_display
        ))));
    }
}

struct RarDecodedEntry {
    entry_name: String,
    content: Vec<u8>,
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

    fn from_decoded(entry: RarDecodedEntry) -> Self {
        Self {
            entry_name: entry.entry_name,
            content: entry.content,
            cap: u64::MAX,
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

struct SolidRarEntrySink {
    entry_name: String,
    content: Vec<u8>,
    cap: u64,
    hit_cap: bool,
    decoded: Rc<RefCell<Vec<RarDecodedEntry>>>,
}

impl SolidRarEntrySink {
    fn new(entry_name: String, cap: u64, decoded: Rc<RefCell<Vec<RarDecodedEntry>>>) -> Self {
        Self {
            entry_name,
            content: Vec::with_capacity(64 * 1024),
            cap,
            hit_cap: false,
            decoded,
        }
    }
}

impl Write for SolidRarEntrySink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_len = self.content.len().saturating_add(buf.len()) as u64;
        if next_len > self.cap {
            self.hit_cap = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR solid entry decoded size exceeds configured extraction cap",
            ));
        }
        self.content.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for SolidRarEntrySink {
    fn drop(&mut self) {
        if self.hit_cap {
            return;
        }
        self.decoded.borrow_mut().push(RarDecodedEntry {
            entry_name: std::mem::take(&mut self.entry_name),
            content: std::mem::take(&mut self.content),
        });
    }
}
