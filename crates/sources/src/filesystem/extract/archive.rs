//! Zip/APK/IPA/CRX/JAR + OOXML/ODF office-document archive extraction.

use super::{display_path, is_symlink, record_binary_without_printable_strings};
use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use std::path::{Component, Path};

mod zip_scan;

pub(super) fn is_openpack_archive_ext(ext: &str) -> bool {
    matches!(
        ext,
        // Plain ZIP and ZIP-wrapped app/package formats.
        "zip" | "apk" | "ipa" | "crx" | "jar"
        // OOXML office documents (Word/Excel/PowerPoint) are ZIP containers
        // whose text lives in member XML (`word/document.xml`,
        // `xl/sharedStrings.xml`, `ppt/slides/*.xml`). A credential pasted into
        // a spreadsheet/doc is a real, common leak that was previously dropped
        // silently at the walker (it was in SKIP_EXTENSIONS); unpacking the ZIP
        // reaches the XML so it is scanned like any other archived file.
        | "docx" | "xlsx" | "pptx"
        // OpenDocument (LibreOffice/OpenOffice) are likewise ZIP containers
        // (`content.xml`); without this they would be read as opaque binary.
        | "odt" | "ods" | "odp"
    )
}

pub(super) fn extract_openpack_archive(
    path: &Path,
    max_size: u64,
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
        return;
    }

    let archive_display = display_path(path);
    let mut total_uncompressed: u64 = 0;
    // `max_size == 0` means "no per-file cap". The compressed-stream path treats
    // that as a 1 GiB hard ceiling so a bomb still can't OOM the process; the zip
    // path must do the SAME, otherwise `total_budget` would be 0 and the FIRST
    // non-empty entry would trip the bomb guard, truncating every archive to
    // nothing (a recall bug, not a safety win). Match the two paths.
    const UNCAPPED_ARCHIVE_BUDGET: u64 = 1024 * 1024 * 1024;
    let per_entry_cap: u64 = if max_size == 0 { u64::MAX } else { max_size };
    let total_budget: u64 = if max_size == 0 {
        UNCAPPED_ARCHIVE_BUDGET
    } else {
        max_size.saturating_mul(4)
    };
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => ext.to_ascii_lowercase(),
        None => String::new(),
    };
    if ext != "crx" {
        zip_scan::extract_zip_archive(path, &archive_display, per_entry_cap, total_budget, emit);
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
                    if archive_entry.is_dir
                        || super::super::filter::is_default_excluded(&archive_entry.name)
                    {
                        continue;
                    }
                    if archive_entry.uncompressed_size > per_entry_cap {
                        tracing::warn!(
                            archive = %path.display(),
                            entry = %archive_entry.name,
                            size = archive_entry.uncompressed_size,
                            "skipping archive entry: uncompressed size exceeds per-file cap"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
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
                            path,
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
                                    crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
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
                                    path,
                                    total_uncompressed,
                                    total_budget,
                                );
                                if !emit(Err(error)) {
                                    return;
                                }
                                break;
                            }
                            let entry_path =
                                || format!("{}//{}", archive_display, archive_entry.name);
                            let chunk = match String::from_utf8(content) {
                                Ok(s) if !s.is_empty() => Some(Ok(Chunk {
                                    data: s.into(),
                                    metadata: ChunkMetadata {
                                        source_type: "filesystem/archive".into(),
                                        path: Some(entry_path()),
                                        ..Default::default()
                                    },
                                })),
                                Ok(_) => None,
                                Err(error) => {
                                    tracing::info!(
                                        archive = %path.display(),
                                        entry = %archive_entry.name,
                                        %error,
                                        "archive entry is not valid UTF-8; scanning printable strings"
                                    );
                                    let content = error.into_bytes();
                                    let strings =
                                        crate::strings::extract_printable_strings(&content, 8);
                                    if strings.is_empty() {
                                        record_binary_without_printable_strings(&entry_path());
                                        None
                                    } else {
                                        Some(Ok(Chunk {
                                            data: crate::strings::join_sensitive_strings(
                                                &strings, "\n",
                                            ),
                                            metadata: ChunkMetadata {
                                                source_type: "filesystem/archive-binary".into(),
                                                path: Some(entry_path()),
                                                ..Default::default()
                                            },
                                        }))
                                    }
                                }
                            };
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
        }
    }
}

pub(super) fn chunk_from_archive_content(
    archive_display: &str,
    entry_name: &str,
    content: Vec<u8>,
) -> Option<Result<Chunk, SourceError>> {
    let entry_path = || format!("{archive_display}//{entry_name}");
    match String::from_utf8(content) {
        Ok(s) if !s.is_empty() => Some(Ok(Chunk {
            data: s.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem/archive".into(),
                path: Some(entry_path()),
                ..Default::default()
            },
        })),
        Ok(_) => None,
        Err(error) => {
            let content = error.into_bytes();
            let strings = crate::strings::extract_printable_strings(&content, 8);
            if strings.is_empty() {
                record_binary_without_printable_strings(&entry_path());
                None
            } else {
                Some(Ok(Chunk {
                    data: crate::strings::join_sensitive_strings(&strings, "\n"),
                    metadata: ChunkMetadata {
                        source_type: "filesystem/archive-binary".into(),
                        path: Some(entry_path()),
                        ..Default::default()
                    },
                }))
            }
        }
    }
}

fn report_archive_truncation(path: &Path, attempted_total: u64, total_budget: u64) -> SourceError {
    eprintln!(
        "keyhog: WARNING: aborting archive extraction of {} at {} bytes \
         (> {} = 4x --max-file-size; zip-bomb guard) - remaining entries were \
         NOT scanned.",
        path.display(),
        attempted_total,
        total_budget
    );
    let _event = crate::record_skip_event(crate::SourceSkipEvent::ArchiveTruncated);
    SourceError::Other(format!(
        "archive extraction of '{}' was truncated at {attempted_total} bytes by the zip-bomb guard (budget {total_budget}); remaining entries were not scanned",
        path.display()
    ))
}

pub(super) fn validate_scan_archive_entry_name(name: &str) -> Result<(), &'static str> {
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
    if contains_parent_traversal(name) || is_windows_absolute(name) {
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

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn contains_parent_traversal(value: &str) -> bool {
    value.contains("../") || value.ends_with("/..") || value == ".."
}

fn is_windows_absolute(value: &str) -> bool {
    value.len() >= 2 && value.as_bytes()[0].is_ascii_alphabetic() && value.as_bytes()[1] == b':'
}
