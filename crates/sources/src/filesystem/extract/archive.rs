//! Zip/APK/IPA/CRX/JAR + OOXML/ODF office-document archive extraction.

use super::hexnib::hex_value;
use super::{
    display_path, extraction_total_budget, is_symlink, record_default_excluded_archive_entry,
    MAX_NESTED_ARCHIVE_DEPTH,
};
use keyhog_core::{Chunk, SourceError};
use std::fmt::Display;
use std::path::{Component, Path};

pub(super) use super::report_archive_truncation;

mod zip_scan;

pub(crate) fn duplicate_zip_central_entries_error_for_test(path: &Path) -> Result<String, String> {
    zip_scan::duplicate_zip_central_entries_error_for_test(path)
}

pub(crate) fn duplicate_zip_local_entry_data_error_for_test(
    path: &Path,
    compressed_size: u64,
) -> Result<String, String> {
    zip_scan::duplicate_zip_local_entry_data_error_for_test(path, compressed_size)
}

pub(crate) fn duplicate_zip_reopen_error_for_test(path: &Path) -> Option<String> {
    zip_scan::duplicate_zip_reopen_error_for_test(path)
}

pub(super) fn is_openpack_archive_ext(ext: &str) -> bool {
    const OPENPACK_EXTS: &[&str] = &[
        // Plain ZIP and ZIP-wrapped app/package formats.
        "zip", "apk", "ipa", "crx", "jar",
        // Compiled / published package artifacts that are ALSO plain ZIP
        // containers. Without these a `.whl` / `.war` / `.aar` / … is read as
        // opaque binary, so a credential baked into a DEFLATE-compressed entry
        // (a `application.properties` in a WAR, a config in a Python wheel, a
        // `.nuspec`/embedded appsettings in a NuGet package) is never reached.
        // Unpacking the ZIP scans each entry like any other archived file.
        //   whl   — Python wheel            war/ear — Java web/enterprise archive
        //   aar   — Android library         nupkg/snupkg — NuGet (+symbols) package
        //   egg   — Python egg              xpi   — Firefox extension
        //   vsix  — VS Code extension
        "whl", "war", "ear", "aar", "nupkg", "snupkg", "egg", "xpi", "vsix",
        // OOXML office documents (Word/Excel/PowerPoint) are ZIP containers
        // whose text lives in member XML (`word/document.xml`,
        // `xl/sharedStrings.xml`, `ppt/slides/*.xml`). A credential pasted into
        // a spreadsheet/doc is a real, common leak that was previously dropped
        // silently at the walker (it was in SKIP_EXTENSIONS); unpacking the ZIP
        // reaches the XML so it is scanned like any other archived file.
        "docx", "xlsx", "pptx",
        // OpenDocument (LibreOffice/OpenOffice) are likewise ZIP containers
        // (`content.xml`); without this they would be read as opaque binary.
        "odt", "ods", "odp",
    ];
    OPENPACK_EXTS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

pub(super) fn extract_openpack_archive(
    path: &Path,
    ext: &str,
    max_size: u64,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) {
    if is_symlink(path) {
        // Law 10: refused symlink => this archive path is NOT scanned; count it so
        // coverage reflects the drop.
        tracing::warn!(
            archive = %path.display(),
            "refusing to open archive at a symlink path - prevents the link-swap attack class"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        if !emit(Err(SourceError::Other(format!(
            "failed to scan archive '{}': refusing to open archive at a symlink path; archive was not scanned",
            display_path(path)
        )))) {
            return;
        }
        return;
    }

    let archive_display = display_path(path);
    let mut total_uncompressed: u64 = 0;
    // `max_size == 0` means "no per-file cap"; extraction still uses the shared
    // aggregate bomb ceiling instead of letting the budget collapse to 0.
    let per_entry_cap: u64 = if max_size == 0 { u64::MAX } else { max_size };
    let total_budget: u64 = extraction_total_budget(max_size);
    let is_crx = ext.eq_ignore_ascii_case("crx");
    if !is_crx {
        zip_scan::extract_zip_archive(
            path,
            &archive_display,
            per_entry_cap,
            total_budget,
            respect_default_excludes,
            emit,
        );
        return;
    }

    let mut limits = openpack::Limits::default();
    // KeyHog enforces its own decoded-byte scan budget below. Keep Openpack's
    // bounded read defaults, but disable ratio rejection so a high-ratio archive
    // still emits the safe prefix before KeyHog records a counted truncation.
    limits.max_compression_ratio = f64::MAX;
    match openpack::OpenPack::open(path, limits) {
        Ok(pack) => match pack.entries() {
            Ok(entries) => {
                for archive_entry in entries {
                    if archive_entry.is_dir {
                        continue;
                    }
                    if let Err(reason) = validate_scan_archive_entry_name(&archive_entry.name) {
                        tracing::warn!(
                            archive = %path.display(),
                            entry = %archive_entry.name,
                            reason,
                            "skipping unsafe archive entry name"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        if !emit_archive_entry_error(
                            emit,
                            "archive entry",
                            &archive_display,
                            &archive_entry.name,
                            reason,
                        ) {
                            return;
                        }
                        continue;
                    }
                    if respect_default_excludes
                        && super::super::filter::is_default_excluded(&archive_entry.name)
                    {
                        record_default_excluded_archive_entry(
                            &archive_display,
                            &archive_entry.name,
                        );
                        continue;
                    }
                    if archive_entry.uncompressed_size > per_entry_cap {
                        tracing::warn!(
                            archive = %path.display(),
                            entry = %archive_entry.name,
                            size = archive_entry.uncompressed_size,
                            "skipping archive entry: uncompressed size exceeds per-file cap"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                        if !emit_archive_entry_over_cap_error(
                            emit,
                            "archive entry",
                            &archive_display,
                            &archive_entry.name,
                            archive_entry.uncompressed_size,
                            per_entry_cap,
                            "uncompressed",
                        ) {
                            return;
                        }
                        continue;
                    }
                    if archive_entry.uncompressed_size > 0
                        && total_uncompressed.saturating_add(archive_entry.uncompressed_size)
                            > total_budget
                    {
                        // Law 10: a zip-bomb abort truncates extraction, so the
                        // remaining entries are NOT scanned — partial coverage the
                        // operator must see. The old `tracing::warn!` was invisible
                        // at default verbosity; surface it loudly + count it.
                        let error = report_archive_truncation(
                            &archive_display,
                            total_uncompressed.saturating_add(archive_entry.uncompressed_size),
                            total_budget,
                        );
                        if !emit(Err(error)) {
                            return;
                        }
                        break;
                    }
                    match pack.read_entry(&archive_entry.name) {
                        Ok(content) => {
                            let actual_uncompressed = content.len() as u64;
                            if actual_uncompressed > per_entry_cap {
                                tracing::warn!(
                                    archive = %path.display(),
                                    entry = %archive_entry.name,
                                    size = actual_uncompressed,
                                    "skipping archive entry: decoded size exceeds per-file cap"
                                );
                                let _event =
                                    crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
                                if !emit_archive_entry_over_cap_error(
                                    emit,
                                    "archive entry",
                                    &archive_display,
                                    &archive_entry.name,
                                    actual_uncompressed,
                                    per_entry_cap,
                                    "decoded",
                                ) {
                                    return;
                                }
                                continue;
                            }
                            total_uncompressed =
                                total_uncompressed.saturating_add(actual_uncompressed);
                            if total_uncompressed > total_budget {
                                // Law 10: ZIP metadata can under-report or omit
                                // uncompressed size for deflated entries. Enforce
                                // the guard on decoded bytes before emitting the
                                // chunk so partial archive coverage is still loud.
                                let error = report_archive_truncation(
                                    &archive_display,
                                    total_uncompressed,
                                    total_budget,
                                );
                                if !emit(Err(error)) {
                                    return;
                                }
                                break;
                            }
                            // Canonical UTF-16-aware entry decode shared with
                            // every other extractor (zip/tar/7z/compressed).
                            let chunk = super::chunk_from_extracted_entry(
                                content,
                                format!("{}//{}", archive_display, archive_entry.name),
                                "filesystem/archive",
                                "filesystem/archive-binary",
                            );
                            if let Some(chunk) = chunk {
                                if !emit(chunk) {
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            // Law 10: a dropped archive entry is an UNKNOWN, not a
                            // clean entry — count it as unreadable so end-of-scan
                            // coverage reflects it (the `tracing::warn!` alone is
                            // invisible at default verbosity).
                            tracing::warn!(
                                archive = %path.display(),
                                entry = %archive_entry.name,
                                %error,
                                "cannot read archive entry; skipping"
                            );
                            let _event =
                                crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                            if !emit_archive_entry_error(
                                emit,
                                "archive entry",
                                &archive_display,
                                &archive_entry.name,
                                format!("cannot read archive entry ({error})"),
                            ) {
                                return;
                            }
                        }
                    }
                }
            }
            Err(error) => {
                // Law 10: the whole archive could not be enumerated => none of its
                // entries were scanned. Count it as unreadable so the operator
                // sees the archive was NOT covered (not silently treated clean).
                tracing::warn!(
                    archive = %path.display(),
                    %error,
                    "cannot list archive entries; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit_archive_unreadable_error(
                    emit,
                    "archive",
                    &archive_display,
                    "cannot list archive entries",
                    error,
                ) {
                    return;
                }
            }
        },
        Err(error) => {
            // Law 10: the archive could not be opened => not scanned at all; count it.
            tracing::warn!(
                archive = %path.display(),
                %error,
                "cannot open archive; skipping"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_unreadable_error(
                emit,
                "archive",
                &archive_display,
                "cannot open archive",
                error,
            ) {
                return;
            }
        }
    }
}

pub(super) fn emit_archive_unreadable_error(
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    kind: &str,
    path_display: &str,
    action: &str,
    error: impl Display,
) -> bool {
    emit(Err(SourceError::Other(format!(
        "failed to scan {kind} '{path_display}': {action} ({error}); {kind} was not scanned"
    ))))
}

pub(super) fn emit_archive_entry_error(
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    kind: &str,
    archive_display: &str,
    entry_name: &str,
    reason: impl Display,
) -> bool {
    emit(Err(SourceError::Other(format!(
        "failed to scan {kind} '{archive_display}//{entry_name}': {reason}; entry was not scanned"
    ))))
}

pub(super) fn emit_archive_entry_over_cap_error(
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    kind: &str,
    archive_display: &str,
    entry_name: &str,
    size: u64,
    cap: u64,
    size_kind: &str,
) -> bool {
    emit_archive_entry_error(
        emit,
        kind,
        archive_display,
        entry_name,
        format_args!("{size_kind} size {size} exceeds per-file cap {cap}"),
    )
}

pub(super) fn archive_unix_mode_is_special(mode: u32) -> bool {
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

pub(super) fn emit_archive_content_with_depth(
    archive_display: &str,
    entry_name: &str,
    content: Vec<u8>,
    per_entry_cap: u64,
    total_budget: u64,
    total_uncompressed: &mut u64,
    respect_default_excludes: bool,
    nested_depth: usize,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    if entry_is_embedded_openpack_archive(entry_name, &content) {
        let nested_display = format!("{archive_display}//{entry_name}");
        if nested_depth >= MAX_NESTED_ARCHIVE_DEPTH {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return emit(Err(SourceError::Other(format!(
                "failed to scan embedded ZIP archive '{nested_display}': maximum nested archive depth {MAX_NESTED_ARCHIVE_DEPTH} exceeded; embedded archive was not scanned"
            ))));
        }
        return zip_scan::extract_embedded_zip_archive(
            content,
            &nested_display,
            per_entry_cap,
            total_budget,
            total_uncompressed,
            nested_depth + 1,
            respect_default_excludes,
            emit,
        );
    }

    // A tar member inside this zip (`bundle.zip//layer.tar`, the dominant
    // docker/helm layout) must be untarred so a secret in the tarball is found,
    // not leaf-scanned as printable strings -- which silently missed it (Law 10).
    if super::compressed::entry_is_embedded_tar(entry_name, &content) {
        let nested_display = format!("{archive_display}//{entry_name}");
        if nested_depth >= MAX_NESTED_ARCHIVE_DEPTH {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return emit(Err(SourceError::Other(format!(
                "failed to scan embedded tar archive '{nested_display}': maximum nested archive depth {MAX_NESTED_ARCHIVE_DEPTH} exceeded; embedded archive was not scanned"
            ))));
        }
        super::compressed::emit_tar_entries_with_state(
            &content,
            &nested_display,
            per_entry_cap,
            total_uncompressed,
            nested_depth + 1,
            respect_default_excludes,
            emit,
        );
        return true;
    }

    // A compressed member inside this zip (`.gz` / `.tgz` / `.zst` / `.lz4` /
    // `.sz` / `.bz2` / `.xz`): decompress and scan its TRUE bytes, exactly as
    // the standalone compressed-file path does. Previously the compressed bytes
    // were routed to the printable-strings path and a secret in the payload was
    // a SILENT false-clean (Law 10). Bounded by depth + the shared zip-bomb
    // budget; every drop is surfaced and counted.
    if let Some(format) = super::compressed::compressed_member_format(entry_name) {
        let nested_display = format!("{archive_display}//{entry_name}");
        if nested_depth >= MAX_NESTED_ARCHIVE_DEPTH {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return emit(Err(SourceError::Other(format!(
                "failed to scan compressed archive member '{nested_display}': maximum nested archive depth {MAX_NESTED_ARCHIVE_DEPTH} exceeded; member was not scanned"
            ))));
        }
        return super::compressed::emit_decompressed_member(
            format,
            &content,
            &nested_display,
            per_entry_cap,
            total_uncompressed,
            nested_depth,
            respect_default_excludes,
            emit,
        );
    }

    match chunk_from_archive_content_inner(archive_display, entry_name, content) {
        Some(chunk) => emit(chunk),
        None => true,
    }
}

fn entry_is_embedded_openpack_archive(entry_name: &str, content: &[u8]) -> bool {
    let has_openpack_ext = Path::new(entry_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(is_openpack_archive_ext);
    has_openpack_ext && crate::magic::starts_with_zip_container_prefix(content)
}

/// True when a member of ANY archive is itself a zip-family (openpack) container
/// (`.zip` / `.jar` / `.war` / ... with the local-file-header magic). Exposed so
/// the tar extractor can recurse into a zip nested in a tar, symmetric with the
/// zip extractor already recursing into a tar nested in a zip.
pub(super) fn member_is_embedded_zip(entry_name: &str, content: &[u8]) -> bool {
    entry_is_embedded_openpack_archive(entry_name, content)
}

/// Recurse into a zip-family MEMBER discovered inside another archive (e.g.
/// `bundle.tar//app.jar`): unzip and scan its entries in memory so a
/// DEFLATE-compressed secret is found, not leaf-scanned as printable strings
/// (which silently missed it -- Law 10). Bounded by `nested_depth` and the
/// shared bomb budget; the depth-exceeded case is surfaced and counted. Returns
/// false when the consumer asked to stop.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_embedded_zip_member(
    content: Vec<u8>,
    nested_display: &str,
    per_entry_cap: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    if nested_depth >= MAX_NESTED_ARCHIVE_DEPTH {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return emit(Err(SourceError::Other(format!(
            "failed to scan embedded ZIP archive '{nested_display}': maximum nested archive depth {MAX_NESTED_ARCHIVE_DEPTH} exceeded; embedded archive was not scanned"
        ))));
    }
    let total_budget = super::extraction_total_budget(per_entry_cap);
    zip_scan::extract_embedded_zip_archive(
        content,
        nested_display,
        per_entry_cap,
        total_budget,
        total_uncompressed,
        nested_depth + 1,
        respect_default_excludes,
        emit,
    )
}

fn chunk_from_archive_content_inner(
    archive_display: &str,
    entry_name: &str,
    content: Vec<u8>,
) -> Option<Result<Chunk, SourceError>> {
    // Canonical UTF-16-aware entry decode shared with every other extractor.
    super::chunk_from_extracted_entry(
        content,
        format!("{archive_display}//{entry_name}"),
        "filesystem/archive",
        "filesystem/archive-binary",
    )
}

pub(crate) fn validate_scan_archive_entry_name(name: &str) -> Result<(), &'static str> {
    let mut current = name.to_string();
    for _ in 0..10 {
        validate_archive_path_text(&current)?;
        let decoded = percent_decode_lossy_once(&current);
        if decoded == current {
            return Ok(());
        }
        current = decoded;
    }
    Err("path contains excessively encoded percent sequences")
}

fn validate_archive_path_text(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty entry name");
    }
    if name.contains('\0') {
        return Err("nul byte in entry name");
    }
    if name.contains('\\') {
        return Err("backslash in entry name");
    }
    if contains_parent_traversal(name) || keyhog_core::winpath::has_windows_drive_prefix(name) {
        return Err("path traversal in entry name");
    }
    if Path::new(name).components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err("absolute or parent path component in entry name");
    }
    Ok(())
}

fn percent_decode_lossy_once(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut changed = false;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                out.push((hi << 4) | lo);
                index += 3;
                changed = true;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    if changed {
        String::from_utf8_lossy(&out).into_owned()
    } else {
        value.to_string()
    }
}

fn contains_parent_traversal(value: &str) -> bool {
    value.contains("../") || value.ends_with("/..") || value == ".."
}

