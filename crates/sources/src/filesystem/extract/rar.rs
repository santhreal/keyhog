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
use std::collections::VecDeque;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;

pub(super) fn extract_rar_chunks(
    path: &Path,
    max_size: u64,
    respect_default_excludes: bool,
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

    let mut state = RarExtractionState::new(path, max_size, respect_default_excludes);
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
            if extract_rar15_40_solid_planned_chunks(archive, &mut state, emit) {
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
            if extract_rar50_solid_planned_chunks(archive, &mut state, emit) {
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

fn extract_rar15_40_solid_planned_chunks(
    archive: &rars::rar15_40::Archive,
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let files: Vec<_> = archive.files().collect();
    if !archive.main.is_solid() && !files.iter().any(|entry| entry.is_solid()) {
        return false;
    }
    let plans = plan_rar15_40_solid_entries(&files, state, emit);
    if state.consumer_stopped || state.archive_truncated {
        return true;
    }
    let cap = state.solid_emit_cap();
    extract_solid_planned_entries(
        state,
        emit,
        plans,
        |plans, plan_errors, decoded| {
            archive.extract_to(rars::ArchiveReadOptions::default(), |meta| {
                let meta_name = String::from_utf8_lossy(&meta.name).into_owned();
                Ok(solid_rar_writer_for_next_plan(
                    &plans,
                    &plan_errors,
                    meta_name,
                    cap,
                    decoded,
                ))
            })
        },
        "RAR 1.5-4.0 solid archive",
    );
    true
}

fn extract_rar50_solid_planned_chunks(
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
    let plans = plan_rar50_solid_entries(&files, state, emit);
    if state.consumer_stopped || state.archive_truncated {
        return true;
    }
    let cap = state.solid_emit_cap();
    extract_solid_planned_entries(
        state,
        emit,
        plans,
        |plans, plan_errors, decoded| {
            archive.extract_to(rars::ArchiveReadOptions::default(), |meta| {
                let meta_name = String::from_utf8_lossy(&meta.name).into_owned();
                Ok(solid_rar_writer_for_next_plan(
                    &plans,
                    &plan_errors,
                    meta_name,
                    cap,
                    decoded,
                ))
            })
        },
        "RAR5 solid archive",
    );
    true
}

fn plan_rar15_40_solid_entries(
    files: &[&rars::rar15_40::FileHeader],
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> VecDeque<SolidRarEntryPlan> {
    let mut planned_scan_total = state.total_uncompressed;
    let mut plans = VecDeque::new();
    for entry in files {
        if state.consumer_stopped || state.archive_truncated {
            break;
        }
        let entry_name = entry.name_lossy();
        let unsupported_reason =
            (entry.is_encrypted() || entry.is_split_before() || entry.is_split_after())
                .then_some("unsupported encrypted or split RAR entry");
        if let Some(action) = state.solid_entry_action(
            &entry_name,
            entry.unp_size,
            entry.is_directory(),
            rar15_40_entry_is_special(entry).then_some("special file type"),
            unsupported_reason,
            &mut planned_scan_total,
            emit,
        ) {
            plans.push_back(SolidRarEntryPlan { entry_name, action });
        }
    }
    plans
}

fn plan_rar50_solid_entries(
    files: &[&rars::rar50::FileHeader],
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> VecDeque<SolidRarEntryPlan> {
    let mut planned_scan_total = state.total_uncompressed;
    let mut plans = VecDeque::new();
    for entry in files {
        if state.consumer_stopped || state.archive_truncated {
            break;
        }
        let entry_name = entry.name_lossy();
        let unsupported_reason = (entry.encrypted
            || entry.is_split_before()
            || entry.is_split_after()
            || entry.is_redirection())
        .then_some("unsupported encrypted, split, or redirected RAR entry");
        if let Some(action) = state.solid_entry_action(
            &entry_name,
            entry.unpacked_size,
            entry.is_directory(),
            rar50_entry_is_special(entry).then_some("special file type"),
            unsupported_reason,
            &mut planned_scan_total,
            emit,
        ) {
            plans.push_back(SolidRarEntryPlan { entry_name, action });
        }
    }
    plans
}

fn extract_solid_planned_entries<F>(
    state: &mut RarExtractionState<'_>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    plans: VecDeque<SolidRarEntryPlan>,
    extract: F,
    archive_kind: &str,
) where
    F: FnOnce(
        Rc<RefCell<VecDeque<SolidRarEntryPlan>>>,
        Rc<RefCell<Vec<String>>>,
        &Rc<RefCell<Vec<RarDecodedEntry>>>,
    ) -> rars::Result<()>,
{
    let decoded = Rc::new(RefCell::new(Vec::new()));
    let plans = Rc::new(RefCell::new(plans));
    let plan_errors = Rc::new(RefCell::new(Vec::new()));
    match extract(Rc::clone(&plans), Rc::clone(&plan_errors), &decoded) {
        Ok(()) => {
            let remaining_plan = plans.borrow().front().map(|plan| plan.entry_name.clone());
            if let Some(entry_name) = remaining_plan {
                state.report_solid_plan_error(
                    archive_kind,
                    &format!("decoder did not produce planned entry '{entry_name}'"),
                    emit,
                );
                return;
            }
            let plan_errors = plan_errors.borrow();
            if !plan_errors.is_empty() {
                for error in plan_errors.iter() {
                    state.report_solid_plan_error(archive_kind, error, emit);
                    if state.consumer_stopped {
                        return;
                    }
                }
                return;
            }
            for entry in decoded.borrow_mut().drain(..) {
                state.emit_entry(emit, RarEntrySink::from_decoded(entry));
                if state.consumer_stopped || state.archive_truncated {
                    return;
                }
            }
        }
        Err(error) => {
            let plan_errors = plan_errors.borrow();
            if !plan_errors.is_empty() {
                for plan_error in plan_errors.iter() {
                    state.report_solid_plan_error(archive_kind, plan_error, emit);
                    if state.consumer_stopped {
                        return;
                    }
                }
                return;
            }
            drop(plan_errors);
            for entry in decoded.borrow_mut().drain(..) {
                state.emit_entry(emit, RarEntrySink::from_decoded(entry));
                if state.consumer_stopped || state.archive_truncated {
                    return;
                }
            }
            state.report_archive_decode_error(archive_kind, &error, emit);
        }
    }
}

fn solid_rar_writer_for_next_plan(
    plans: &Rc<RefCell<VecDeque<SolidRarEntryPlan>>>,
    plan_errors: &Rc<RefCell<Vec<String>>>,
    meta_name: String,
    emit_cap: u64,
    decoded: &Rc<RefCell<Vec<RarDecodedEntry>>>,
) -> Box<dyn Write> {
    let Some(plan) = plans.borrow_mut().pop_front() else {
        plan_errors.borrow_mut().push(format!(
            "decoder produced unexpected entry '{meta_name}' with no extraction plan"
        ));
        return Box::new(SolidRarDrainSink::new(0));
    };
    if plan.entry_name != meta_name {
        plan_errors.borrow_mut().push(format!(
            "decoder produced entry '{meta_name}' while extraction plan expected '{}'",
            plan.entry_name
        ));
        return Box::new(SolidRarDrainSink::new(0));
    }
    match plan.action {
        SolidRarEntryAction::Emit => Box::new(SolidRarEntrySink::new(
            plan.entry_name,
            emit_cap,
            Rc::clone(decoded),
        )),
        SolidRarEntryAction::Drain { cap } => Box::new(SolidRarDrainSink::new(cap)),
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
    respect_default_excludes: bool,
}

impl<'a> RarExtractionState<'a> {
    fn new(archive_path: &'a Path, max_size: u64, respect_default_excludes: bool) -> Self {
        Self {
            archive_path,
            archive_display: display_path(archive_path),
            per_entry_cap: if max_size == 0 { u64::MAX } else { max_size },
            total_budget: extraction_total_budget(max_size),
            total_uncompressed: 0,
            consumer_stopped: false,
            archive_truncated: false,
            respect_default_excludes,
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
        if self.respect_default_excludes && super::super::filter::is_default_excluded(entry_name) {
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

    fn solid_entry_action(
        &mut self,
        entry_name: &str,
        entry_size: u64,
        is_directory: bool,
        special_reason: Option<&str>,
        unsupported_reason: Option<&str>,
        planned_scan_total: &mut u64,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) -> Option<SolidRarEntryAction> {
        if is_directory {
            return Some(SolidRarEntryAction::Drain { cap: 0 });
        }
        if self.respect_default_excludes && super::super::filter::is_default_excluded(entry_name) {
            record_default_excluded_archive_entry(&self.archive_display, entry_name);
            return Some(SolidRarEntryAction::Drain {
                cap: self.solid_drain_cap(entry_size),
            });
        }
        if let Err(reason) = validate_scan_archive_entry_name(entry_name) {
            tracing::warn!(
                archive = %self.archive_path.display(),
                entry = %entry_name,
                reason,
                "skipping unsafe RAR entry name"
            );
            self.report_unreadable_entry(entry_name, reason, emit);
            return (!self.consumer_stopped).then_some(SolidRarEntryAction::Drain {
                cap: self.solid_drain_cap(entry_size),
            });
        }
        if let Some(reason) = special_reason {
            self.report_unreadable_entry(entry_name, reason, emit);
            return (!self.consumer_stopped).then_some(SolidRarEntryAction::Drain {
                cap: self.solid_drain_cap(entry_size),
            });
        }
        if let Some(reason) = unsupported_reason {
            self.report_unreadable_entry(entry_name, reason, emit);
            return (!self.consumer_stopped).then_some(SolidRarEntryAction::Drain {
                cap: self.solid_drain_cap(entry_size),
            });
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
            return (!self.consumer_stopped).then_some(SolidRarEntryAction::Drain {
                cap: self.solid_drain_cap(entry_size),
            });
        }
        let attempted_total = planned_scan_total.saturating_add(entry_size);
        if attempted_total > self.total_budget {
            self.report_archive_truncation(attempted_total, emit);
            return None;
        }
        *planned_scan_total = attempted_total;
        Some(SolidRarEntryAction::Emit)
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
                    "skipping RAR entry: decoded size exceeds per-file cap"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                self.report_entry_over_cap(
                    entry_name,
                    self.per_entry_cap.saturating_add(1),
                    "decoded",
                    emit,
                );
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

    fn solid_drain_cap(&self, entry_size: u64) -> u64 {
        entry_size.min(self.total_budget)
    }

    fn solid_emit_cap(&self) -> u64 {
        self.per_entry_cap.min(self.total_budget)
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

    fn report_solid_plan_error(
        &mut self,
        archive_kind: &str,
        error: &str,
        emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    ) {
        tracing::warn!(
            archive = %self.archive_path.display(),
            %archive_kind,
            error,
            "RAR solid archive metadata did not match extraction plan"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        self.consumer_stopped = !emit(Err(SourceError::Other(format!(
            "failed to scan {archive_kind} '{}': extraction plan mismatch ({error}); archive was not scanned",
            self.archive_display
        ))));
    }
}

struct SolidRarEntryPlan {
    entry_name: String,
    action: SolidRarEntryAction,
}

enum SolidRarEntryAction {
    Emit,
    Drain { cap: u64 },
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

struct SolidRarDrainSink {
    cap: u64,
    written: u64,
}

impl SolidRarDrainSink {
    fn new(cap: u64) -> Self {
        Self { cap, written: 0 }
    }
}

impl Write for SolidRarDrainSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_written = self.written.saturating_add(buf.len() as u64);
        if next_written > self.cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR solid drain exceeds configured extraction cap",
            ));
        }
        self.written = next_written;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
