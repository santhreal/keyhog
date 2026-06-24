use super::{
    chunk_from_archive_content, emit_archive_unreadable_error, report_archive_truncation,
    validate_scan_archive_entry_name,
};
use crate::filesystem::filter;
use keyhog_core::{Chunk, SourceError};
use std::fs::File;
use std::io::Read;
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
    let mut archive = match zip::ZipArchive::new(file) {
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
    for index in 0..archive.len() {
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    archive = %path.display(),
                    index,
                    %error,
                    "cannot read archive entry metadata; skipping entry"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan ZIP entry #{index} in '{archive_display}': cannot read entry metadata ({error}); entry was not scanned"
                )))) {
                    return;
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
                archive = %path.display(),
                entry = %entry_name,
                reason,
                "skipping unsafe archive entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            continue;
        }
        if zip_entry_is_special(&entry) {
            tracing::warn!(
                archive = %path.display(),
                entry = %entry_name,
                "skipping special archive entry"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            continue;
        }

        let advertised_uncompressed = entry.size();
        if advertised_uncompressed > per_entry_cap {
            tracing::warn!(
                archive = %path.display(),
                entry = %entry_name,
                size = advertised_uncompressed,
                "skipping archive entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            continue;
        }
        if advertised_uncompressed > 0
            && total_uncompressed.saturating_add(advertised_uncompressed) > total_budget
        {
            let error = report_archive_truncation(
                archive_display,
                total_uncompressed.saturating_add(advertised_uncompressed),
                total_budget,
            );
            if !emit(Err(error)) {
                return;
            }
            break;
        }

        let read_limit = per_entry_cap.saturating_add(1).min(
            total_budget
                .saturating_sub(total_uncompressed)
                .saturating_add(1),
        );
        let mut content = Vec::new();
        if let Err(error) = (&mut entry).take(read_limit).read_to_end(&mut content) {
            tracing::warn!(
                archive = %path.display(),
                entry = %entry_name,
                %error,
                "cannot read archive entry; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit(Err(SourceError::Other(format!(
                "failed to scan ZIP entry '{archive_display}//{entry_name}': cannot read entry ({error}); entry was not scanned"
            )))) {
                return;
            }
            continue;
        }

        let actual_uncompressed = match u64::try_from(content.len()) {
            Ok(len) => len,
            Err(error) => {
                tracing::warn!(
                    archive = %path.display(),
                    entry = %entry_name,
                    %error,
                    "archive entry decoded length cannot be represented; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan ZIP entry '{archive_display}//{entry_name}': decoded length cannot be represented ({error}); entry was not scanned"
                )))) {
                    return;
                }
                continue;
            }
        };
        if actual_uncompressed > per_entry_cap {
            tracing::warn!(
                archive = %path.display(),
                entry = %entry_name,
                size = actual_uncompressed,
                "skipping archive entry: decoded size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            continue;
        }
        total_uncompressed = total_uncompressed.saturating_add(actual_uncompressed);
        if total_uncompressed > total_budget {
            let error =
                report_archive_truncation(archive_display, total_uncompressed, total_budget);
            if !emit(Err(error)) {
                return;
            }
            break;
        }

        if let Some(chunk) = chunk_from_archive_content(archive_display, &entry_name, content) {
            if !emit(chunk) {
                return;
            }
        }
    }
}

fn zip_entry_is_special(entry: &zip::read::ZipFile<'_>) -> bool {
    entry.unix_mode().is_some_and(zip_unix_mode_is_special)
}

fn zip_external_attrs_are_special(external_attrs: u32) -> bool {
    let mode = external_attrs >> 16;
    mode != 0 && zip_unix_mode_is_special(mode)
}

fn zip_unix_mode_is_special(mode: u32) -> bool {
    const S_IFMT: u32 = 0o170000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFBLK: u32 = 0o060000;
    const S_IFCHR: u32 = 0o020000;
    const S_IFIFO: u32 = 0o010000;
    const S_IFSOCK: u32 = 0o140000;

    matches!(
        mode & S_IFMT,
        S_IFLNK | S_IFBLK | S_IFCHR | S_IFIFO | S_IFSOCK
    )
}
