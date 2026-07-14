use super::{
    archive_unix_mode_is_special, emit_archive_entry_error, emit_archive_entry_over_cap_error,
    emit_archive_unreadable_error, report_archive_truncation, validate_scan_archive_entry_name,
};
use crate::filesystem::extract::tex_package::{
    member_needs_source_bytes, TexPackageAnalysis, TexPackageBuilder,
};
use crate::filesystem::filter;
use keyhog_core::{Chunk, SourceError};
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
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    match duplicates::duplicate_central_zip_entries(path) {
        Ok(Some(entries)) => {
            duplicates::extract_zip_archive_from_central_entries(
                path,
                archive_display,
                per_entry_cap,
                total_budget,
                respect_default_excludes,
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

    let file = match crate::filesystem::open_file_safe(path) {
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
        respect_default_excludes,
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
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let mut cursor = Cursor::new(content);
    match duplicates::duplicate_central_zip_entries_from_reader(&mut cursor) {
        Ok(Some(entries)) => {
            return duplicates::extract_zip_archive_from_central_entries_reader(
                &mut cursor,
                archive_display,
                per_entry_cap,
                total_budget,
                total_uncompressed,
                nested_depth,
                respect_default_excludes,
                emit,
                entries,
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(
                archive = archive_display,
                %error,
                "embedded zip duplicate-entry detection unavailable; scanning with the standard \
                 parser, which may miss a duplicated/shadow central-directory entry"
            );
            let _event =
                crate::record_skip_event(crate::SourceSkipEvent::ArchiveDuplicateScanUnavailable);
            if !emit(Err(SourceError::Other(format!(
                "embedded ZIP duplicate-entry detection unavailable for '{archive_display}': {error}; scanning continued with the standard parser, which may miss duplicated or shadowed entries"
            )))) {
                return false;
            }
        }
    }

    let archive = match zip::ZipArchive::new(cursor) {
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
        respect_default_excludes,
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
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    let mut tex_package = analyze_tex_package(&mut archive);
    if tex_package.is_bounded()
        && !emit(Err(SourceError::Other(format!(
            "TeX provenance analysis for '{archive_display}' exceeded its bounded member or source-byte budget; every archive member is still scanned without TeX role annotations"
        ))))
    {
        return false;
    }

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
        if respect_default_excludes && filter::is_default_excluded(&entry_name) {
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
        let read = if let Some(mut bytes) = tex_package.take_source_content(&entry_name) {
            let cap = usize::try_from(read_cap).unwrap_or(usize::MAX); // LAW10: recall-preserving bounded conversion saturates to the largest addressable buffer cap; every readable byte remains eligible.
            let truncated = bytes.len() > cap;
            bytes.truncate(cap);
            crate::capped_read::CappedRead { bytes, truncated }
        } else {
            match crate::capped_read::read_to_cap(
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

        if !super::emit_archive_content_with_tex_provenance(
            archive_display,
            &entry_name,
            content,
            per_entry_cap,
            total_budget,
            total_uncompressed,
            respect_default_excludes,
            nested_depth,
            tex_package.get(&entry_name),
            emit,
        ) {
            return false;
        }
    }
    true
}

fn analyze_tex_package<R: Read + Seek>(archive: &mut zip::ZipArchive<R>) -> TexPackageAnalysis {
    if !archive.file_names().any(member_needs_source_bytes) {
        return TexPackageAnalysis::default();
    }
    let mut builder = TexPackageBuilder::default();
    for index in 0..archive.len() {
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(_) => {
                // LAW10: TeX analysis marks bounded and the caller emits a visible coverage error; ordinary archive members are still scanned.
                builder.mark_bounded();
                continue;
            }
        };
        if entry.is_dir() || zip_entry_is_special(&entry) {
            continue;
        }
        let name = entry.name().to_string();
        if validate_scan_archive_entry_name(&name).is_err() {
            continue;
        }
        if !member_needs_source_bytes(&name) {
            builder.add_member(&name, None);
            continue;
        }
        let entry_size = entry.size();
        let read = match crate::capped_read::read_to_cap(
            &mut entry,
            TexPackageBuilder::source_member_read_cap(),
            Some(entry_size),
        ) {
            Ok(read) => read,
            Err(_) => {
                // LAW10: TeX analysis marks bounded and the caller emits a visible coverage error; this member is still scanned without TeX annotations.
                builder.mark_bounded();
                builder.add_member(&name, None);
                continue;
            }
        };
        if read.truncated {
            builder.mark_bounded();
            builder.add_member(&name, None);
        } else {
            builder.add_member(&name, Some(&read.bytes));
        }
    }
    builder.finish()
}

fn zip_entry_is_special(entry: &zip::read::ZipFile<'_>) -> bool {
    entry.unix_mode().is_some_and(archive_unix_mode_is_special)
}

fn zip_external_attrs_are_special(external_attrs: u32) -> bool {
    let mode = external_attrs >> 16;
    mode != 0 && archive_unix_mode_is_special(mode)
}

/// Open-safety for the ZIP archive path.
///
/// Every other archive type (7z, rar, gz/xz, pdf) reads through `open_file_safe`
/// or refuses a symlink path explicitly; ZIP was the lone holdout using raw
/// `File::open`, so a symlinked `.zip` was FOLLOWED (a possible escape out of the
/// scan root) and a FIFO swapped in at a `.zip` path would HANG the scan forever.
/// All three ZIP open sites now route through `open_file_safe`, which applies
/// `O_NOFOLLOW` + `O_NONBLOCK` + an `is_file()` guard. These tests drive each open
/// site directly (codewalk's `is_file()` filter hides them from a normal walk, so
/// the live exposure is the regular->special TOCTOU swap and explicit calls) and
/// assert refusal WITHOUT hanging. Unix-only because they fabricate FIFOs /
/// symlinks / devices; the `is_file()` guard they exercise is cross-platform.
#[cfg(all(test, unix))]
mod open_safety {
    use super::{duplicates, extract_zip_archive};
    use crate::filesystem::special_file_test_support::{make_fifo, symlink_to, within_timeout};
    use std::path::PathBuf;

    /// `duplicate_central_zip_entries` (open site #1) (returns Ok(has_dups)/Err).
    fn dup_central(path: PathBuf) -> Result<bool, String> {
        within_timeout(move || {
            duplicates::duplicate_central_zip_entries(&path).map(|o| o.is_some())
        })
    }

    /// `extract_zip_archive_from_central_entries` (open site #2). (chunks, errors).
    fn from_central(path: PathBuf) -> (usize, Vec<String>) {
        within_timeout(move || {
            let mut chunks = 0usize;
            let mut errors = Vec::new();
            duplicates::extract_zip_archive_from_central_entries(
                &path,
                "archive.zip",
                u64::MAX,
                u64::MAX,
                true,
                &mut |row| {
                    match row {
                        Ok(_) => chunks += 1,
                        Err(error) => errors.push(error.to_string()),
                    }
                    true
                },
                Vec::new(),
            );
            (chunks, errors)
        })
    }

    /// `extract_zip_archive` (the entry that chains all three opens). (chunks, errors).
    fn extract(path: PathBuf) -> (usize, Vec<String>) {
        within_timeout(move || {
            let mut chunks = 0usize;
            let mut errors = Vec::new();
            extract_zip_archive(&path, "archive.zip", u64::MAX, u64::MAX, true, &mut |row| {
                match row {
                    Ok(_) => chunks += 1,
                    Err(error) => errors.push(error.to_string()),
                }
                true
            });
            (chunks, errors)
        })
    }

    // ── open site #1: duplicate_central_zip_entries ─────────────────────

    #[test]
    fn dup_central_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.bin");
        std::fs::write(&target, b"not a zip").unwrap();
        let link = symlink_to(dir.path(), "a.zip", &target);
        assert!(
            dup_central(link).is_err(),
            "a symlinked zip must not be followed"
        );
    }

    #[test]
    fn dup_central_refuses_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "a.zip");
        assert!(
            dup_central(fifo).is_err(),
            "a FIFO at a zip path must be refused"
        );
    }

    #[test]
    fn dup_central_refuses_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(dup_central(dir.path().to_path_buf()).is_err());
    }

    #[test]
    fn dup_central_refuses_dev_null() {
        assert!(dup_central(PathBuf::from("/dev/null")).is_err());
    }

    #[test]
    fn dup_central_refuses_symlink_to_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let link = symlink_to(dir.path(), "a.zip", &fifo);
        assert!(dup_central(link).is_err());
    }

    #[test]
    fn dup_central_regular_non_zip_errs_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junk.zip");
        std::fs::write(&path, b"this is not a zip central directory").unwrap();
        // Opens fine (regular file), then the central-directory parse fails, a
        // graceful error, never a hang.
        assert!(dup_central(path).is_err());
    }

    #[test]
    fn dup_central_nonexistent_path_errs() {
        let dir = tempfile::tempdir().unwrap();
        assert!(dup_central(dir.path().join("missing.zip")).is_err());
    }

    // ── open site #2: extract_zip_archive_from_central_entries ───────────

    #[test]
    fn from_central_refuses_symlink_with_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.bin");
        std::fs::write(&target, b"not a zip").unwrap();
        let link = symlink_to(dir.path(), "a.zip", &target);
        let (chunks, errors) = from_central(link);
        assert_eq!(chunks, 0, "a symlinked zip must yield no chunks");
        assert!(
            !errors.is_empty(),
            "the refusal must be surfaced loudly (Law 10)"
        );
    }

    #[test]
    fn from_central_refuses_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "a.zip");
        let (chunks, _errors) = from_central(fifo);
        assert_eq!(chunks, 0, "a FIFO must yield no chunks");
    }

    #[test]
    fn from_central_refuses_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (chunks, _errors) = from_central(dir.path().to_path_buf());
        assert_eq!(chunks, 0);
    }

    #[test]
    fn from_central_refuses_dev_null() {
        let (chunks, _errors) = from_central(PathBuf::from("/dev/null"));
        assert_eq!(chunks, 0);
    }

    // ── entry point: extract_zip_archive (chains all three opens) ────────

    #[test]
    fn extract_refuses_symlink_no_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.bin");
        std::fs::write(&target, b"not a zip").unwrap();
        let link = symlink_to(dir.path(), "a.zip", &target);
        let (chunks, _errors) = extract(link);
        assert_eq!(
            chunks, 0,
            "a symlinked zip must not be followed into chunks"
        );
    }

    #[test]
    fn extract_symlink_emits_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.bin");
        std::fs::write(&target, b"not a zip").unwrap();
        let link = symlink_to(dir.path(), "a.zip", &target);
        let (_chunks, errors) = extract(link);
        assert!(
            !errors.is_empty(),
            "refusing a symlinked zip must be loud, never silent"
        );
    }

    #[test]
    fn extract_refuses_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "a.zip");
        let (chunks, _errors) = extract(fifo);
        assert_eq!(
            chunks, 0,
            "a FIFO at a zip path must yield no chunks and not hang"
        );
    }

    #[test]
    fn extract_fifo_emits_loud_error() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "a.zip");
        let (_chunks, errors) = extract(fifo);
        assert!(
            !errors.is_empty(),
            "refusing a FIFO zip must be surfaced loudly"
        );
    }

    #[test]
    fn extract_refuses_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (chunks, _errors) = extract(dir.path().to_path_buf());
        assert_eq!(chunks, 0);
    }

    #[test]
    fn extract_refuses_dev_null() {
        let (chunks, _errors) = extract(PathBuf::from("/dev/null"));
        assert_eq!(chunks, 0);
    }

    #[test]
    fn extract_refuses_symlink_to_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let link = symlink_to(dir.path(), "a.zip", &fifo);
        let (chunks, _errors) = extract(link);
        assert_eq!(chunks, 0);
    }

    #[test]
    fn extract_regular_non_zip_no_chunks_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junk.zip");
        std::fs::write(&path, b"definitely not a zip").unwrap();
        let (chunks, _errors) = extract(path);
        assert_eq!(
            chunks, 0,
            "a non-zip regular file yields no chunks and must not hang"
        );
    }

    #[test]
    fn extract_nonexistent_path_emits_error() {
        let dir = tempfile::tempdir().unwrap();
        let (chunks, errors) = extract(dir.path().join("missing.zip"));
        assert_eq!(chunks, 0);
        assert!(
            !errors.is_empty(),
            "a missing archive must surface an error"
        );
    }

    #[test]
    fn from_central_regular_non_zip_no_chunks_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junk.zip");
        std::fs::write(&path, b"definitely not a zip").unwrap();
        let (chunks, _errors) = from_central(path);
        assert_eq!(chunks, 0);
    }
}
