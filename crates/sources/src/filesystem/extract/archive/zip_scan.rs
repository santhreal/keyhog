use super::{
    archive_unix_mode_is_special, emit_archive_content_with_depth, emit_archive_entry_error,
    emit_archive_entry_over_cap_error, emit_archive_unreadable_error, report_archive_truncation,
    validate_scan_archive_entry_name,
};
use crate::filesystem::filter;
use keyhog_core::{Chunk, SourceError};
use std::fs::File;
use std::io::{Cursor, Read, Seek};
use std::path::Path;

mod duplicates;

pub(crate) fn duplicate_zip_central_entries_error_for_test(path: &Path) -> Result<String, String> {
    duplicates::read_central_zip_entries_error_for_test(path)
}

pub(crate) fn duplicate_zip_local_entry_data_error_for_test(
    path: &Path,
    compressed_size: u64,
) -> Result<String, String> {
    duplicates::read_local_zip_entry_data_error_for_test(path, compressed_size)
}

pub(crate) fn duplicate_zip_reopen_error_for_test(path: &Path) -> Option<String> {
    duplicates::duplicate_zip_reopen_error_for_test(path)
}

pub(super) fn extract_zip_archive(
    path: &Path,
    archive_display: &str,
    per_entry_cap: u64,
    total_budget: u64,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    match duplicates::duplicate_central_zip_entries(path) {
        Ok(Some(entries)) => {
            duplicates::extract_zip_archive_from_central_entries(
                path,
                archive_display,
                per_entry_cap,
                total_budget,
                emit,
                entries,
            );
            return;
        }
        // No duplicate central-directory entries: the standard parser below sees
        // every entry, so its coverage of this archive is complete.
        Ok(None) => {}
        Err(error) => {
            // LAW 10: do NOT silently degrade. The duplicate-entry detector could
            // not run (e.g. a zip64 central directory it does not model, or a
            // malformed/truncated central directory), so the standard `zip` parser
            // below surfaces only one entry per name and may miss a duplicated /
            // shadow central-directory entry an attacker hid a secret in. Surface
            // the partial-coverage gap loudly and record it so the recall gap is
            // visible in the scan summary instead of vanishing.
            tracing::warn!(
                archive = %path.display(),
                %error,
                "zip duplicate-entry detection unavailable; scanning with the standard \
                 parser, which may miss a duplicated/shadow central-directory entry"
            );
            let _event =
                crate::record_skip_event(crate::SourceSkipEvent::ArchiveDuplicateScanUnavailable);
            if !emit(Err(SourceError::Other(format!(
                "ZIP duplicate-entry detection unavailable for '{archive_display}': {error}; scanning continued with the standard parser, which may miss duplicated or shadowed entries"
            )))) {
                return;
            }
        }
    }

    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!(
                archive = %path.display(),
                %error,
                "cannot open archive; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_unreadable_error(
                emit,
                "ZIP archive",
                archive_display,
                "cannot open archive",
                error,
            ) {
                return;
            }
            return;
        }
    };
    let archive = match zip::ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(error) => {
            tracing::warn!(
                archive = %path.display(),
                %error,
                "cannot read zip archive directory; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_unreadable_error(
                emit,
                "ZIP archive",
                archive_display,
                "cannot read zip archive directory",
                error,
            ) {
                return;
            }
            return;
        }
    };

    let mut total_uncompressed = 0u64;
    if !extract_zip_archive_entries(
        archive,
        archive_display,
        per_entry_cap,
        total_budget,
        &mut total_uncompressed,
        0,
        emit,
    ) {
        return;
    }
}

pub(super) fn extract_embedded_zip_archive(
    content: Vec<u8>,
    archive_display: &str,
    per_entry_cap: u64,
    total_budget: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let archive = match zip::ZipArchive::new(Cursor::new(content)) {
        Ok(archive) => archive,
        Err(error) => {
            tracing::warn!(
                archive = archive_display,
                %error,
                "cannot read embedded zip archive directory; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return emit(Err(SourceError::Other(format!(
                "failed to scan embedded ZIP archive '{archive_display}': cannot read archive directory ({error}); embedded archive was not scanned"
            ))));
        }
    };

    extract_zip_archive_entries(
        archive,
        archive_display,
        per_entry_cap,
        total_budget,
        total_uncompressed,
        nested_depth,
        emit,
    )
}

fn extract_zip_archive_entries<R: Read + Seek>(
    mut archive: zip::ZipArchive<R>,
    archive_display: &str,
    per_entry_cap: u64,
    total_budget: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    for index in 0..archive.len() {
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    index,
                    %error,
                    "cannot read archive entry metadata; skipping entry"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan ZIP entry #{index} in '{archive_display}': cannot read entry metadata ({error}); entry was not scanned"
                )))) {
                    return false;
                }
                continue;
            }
        };
        let entry_name = entry.name().to_string();
        if entry.is_dir() {
            continue;
        }
        if filter::is_default_excluded(&entry_name) {
            super::super::record_default_excluded_archive_entry(archive_display, &entry_name);
            continue;
        }
        if let Err(reason) = validate_scan_archive_entry_name(&entry_name) {
            tracing::warn!(
                archive = archive_display,
                entry = %entry_name,
                reason,
                "skipping unsafe archive entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_entry_error(emit, "ZIP entry", archive_display, &entry_name, reason) {
                return false;
            }
            continue;
        }
        if zip_entry_is_special(&entry) {
            tracing::warn!(
                archive = archive_display,
                entry = %entry_name,
                "skipping special archive entry"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_entry_error(
                emit,
                "ZIP entry",
                archive_display,
                &entry_name,
                "special file type",
            ) {
                return false;
            }
            continue;
        }

        let advertised_uncompressed = entry.size();
        if advertised_uncompressed > per_entry_cap {
            tracing::warn!(
                archive = archive_display,
                entry = %entry_name,
                size = advertised_uncompressed,
                "skipping archive entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_archive_entry_over_cap_error(
                emit,
                "ZIP entry",
                archive_display,
                &entry_name,
                advertised_uncompressed,
                per_entry_cap,
                "uncompressed",
            ) {
                return false;
            }
            continue;
        }
        if advertised_uncompressed > 0
            && (*total_uncompressed).saturating_add(advertised_uncompressed) > total_budget
        {
            let error = report_archive_truncation(
                archive_display,
                (*total_uncompressed).saturating_add(advertised_uncompressed),
                total_budget,
            );
            if !emit(Err(error)) {
                return false;
            }
            break;
        }

        let remaining_budget = total_budget.saturating_sub(*total_uncompressed);
        let read_cap = per_entry_cap.min(remaining_budget);
        let read = match crate::capped_read::read_to_cap(
            &mut entry,
            read_cap,
            Some(advertised_uncompressed),
        ) {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry_name,
                    %error,
                    "cannot read archive entry; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                        "failed to scan ZIP entry '{archive_display}//{entry_name}': cannot read entry ({error}); entry was not scanned"
                    )))) {
                        return false;
                    }
                continue;
            }
        };
        let content = read.bytes;

        let actual_uncompressed = match u64::try_from(content.len()) {
            Ok(len) => len,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry_name,
                    %error,
                    "archive entry decoded length cannot be represented; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan ZIP entry '{archive_display}//{entry_name}': decoded length cannot be represented ({error}); entry was not scanned"
                )))) {
                    return false;
                }
                continue;
            }
        };
        if read.truncated && read_cap == per_entry_cap {
            let observed_uncompressed = read_cap.saturating_add(1);
            tracing::warn!(
                archive = archive_display,
                entry = %entry_name,
                size = observed_uncompressed,
                "skipping archive entry: decoded size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_archive_entry_over_cap_error(
                emit,
                "ZIP entry",
                archive_display,
                &entry_name,
                observed_uncompressed,
                per_entry_cap,
                "decoded",
            ) {
                return false;
            }
            continue;
        }
        if read.truncated {
            let attempted_total = (*total_uncompressed).saturating_add(read_cap.saturating_add(1));
            let error = report_archive_truncation(archive_display, attempted_total, total_budget);
            if !emit(Err(error)) {
                return false;
            }
            break;
        }
        *total_uncompressed = (*total_uncompressed).saturating_add(actual_uncompressed);
        if *total_uncompressed > total_budget {
            let error =
                report_archive_truncation(archive_display, *total_uncompressed, total_budget);
            if !emit(Err(error)) {
                return false;
            }
            break;
        }

        if !emit_archive_content_with_depth(
            archive_display,
            &entry_name,
            content,
            per_entry_cap,
            total_budget,
            total_uncompressed,
            nested_depth,
            emit,
        ) {
            return false;
        }
    }
    true
}

fn zip_entry_is_special(entry: &zip::read::ZipFile<'_>) -> bool {
    entry.unix_mode().is_some_and(archive_unix_mode_is_special)
}

fn zip_external_attrs_are_special(external_attrs: u32) -> bool {
    let mode = external_attrs >> 16;
    mode != 0 && archive_unix_mode_is_special(mode)
}
