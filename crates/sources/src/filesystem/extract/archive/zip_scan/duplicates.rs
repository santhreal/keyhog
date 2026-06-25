use super::super::{
    emit_archive_content_with_depth, emit_archive_entry_error, emit_archive_entry_over_cap_error,
    emit_archive_unreadable_error, report_archive_truncation,
};
use super::{validate_scan_archive_entry_name, zip_external_attrs_are_special};
use crate::filesystem::filter;
use crate::magic::{
    ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE, ZIP_END_OF_CENTRAL_DIRECTORY_PREFIX,
    ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE, ZIP_LOCAL_FILE_HEADER_SIGNATURE,
};
use keyhog_core::{Chunk, SourceError};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub(super) struct CentralZipEntry {
    name: String,
    compression_method: u16,
    crc32: u32,
    compressed_size: u64,
    uncompressed_size: u64,
    local_header_offset: u64,
    external_attrs: u32,
}

pub(super) fn duplicate_central_zip_entries(
    path: &Path,
) -> Result<Option<Vec<CentralZipEntry>>, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    duplicate_central_zip_entries_from_reader(&mut file)
}

pub(super) fn duplicate_central_zip_entries_from_reader<R: Read + Seek>(
    reader: &mut R,
) -> Result<Option<Vec<CentralZipEntry>>, String> {
    let entries = read_central_zip_entries(reader)?;
    let mut names = HashSet::new();
    let has_duplicates = entries
        .iter()
        .any(|entry| !names.insert(entry.name.clone()));
    Ok(has_duplicates.then_some(entries))
}

pub(super) fn extract_zip_archive_from_central_entries(
    path: &Path,
    archive_display: &str,
    per_entry_cap: u64,
    total_budget: u64,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    entries: Vec<CentralZipEntry>,
) {
    let mut file = match File::open(path) {
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
                "duplicate ZIP archive",
                archive_display,
                "cannot open archive",
                error,
            ) {
                return;
            }
            return;
        }
    };

    let mut total_uncompressed = 0u64;
    let _completed = extract_zip_archive_from_central_entries_reader(
        &mut file,
        archive_display,
        per_entry_cap,
        total_budget,
        &mut total_uncompressed,
        0,
        respect_default_excludes,
        emit,
        entries,
    );
}

pub(super) fn extract_zip_archive_from_central_entries_reader<R: Read + Seek>(
    reader: &mut R,
    archive_display: &str,
    per_entry_cap: u64,
    total_budget: u64,
    total_uncompressed: &mut u64,
    nested_depth: usize,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
    entries: Vec<CentralZipEntry>,
) -> bool {
    let mut occurrence_counts: HashMap<String, usize> = HashMap::new();

    for entry in entries {
        let occurrence = occurrence_counts.entry(entry.name.clone()).or_insert(0);
        *occurrence += 1;
        let entry_path_name = if *occurrence == 1 {
            entry.name.clone()
        } else {
            format!("{}#{}", entry.name, *occurrence)
        };

        if entry.name.ends_with('/') {
            continue;
        }
        if respect_default_excludes && filter::is_default_excluded(&entry.name) {
            super::super::super::record_default_excluded_archive_entry(
                archive_display,
                &entry.name,
            );
            continue;
        }
        if let Err(reason) = validate_scan_archive_entry_name(&entry.name) {
            tracing::warn!(
                archive = archive_display,
                entry = %entry.name,
                reason,
                "skipping unsafe archive entry name"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_entry_error(
                emit,
                "duplicate ZIP entry",
                archive_display,
                &entry.name,
                reason,
            ) {
                return false;
            }
            continue;
        }
        if zip_external_attrs_are_special(entry.external_attrs) {
            tracing::warn!(
                archive = archive_display,
                entry = %entry.name,
                "skipping special archive entry"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            if !emit_archive_entry_error(
                emit,
                "duplicate ZIP entry",
                archive_display,
                &entry.name,
                "special file type",
            ) {
                return false;
            }
            continue;
        }
        if entry.uncompressed_size > per_entry_cap {
            tracing::warn!(
                archive = archive_display,
                entry = %entry.name,
                size = entry.uncompressed_size,
                "skipping archive entry: uncompressed size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_archive_entry_over_cap_error(
                emit,
                "duplicate ZIP entry",
                archive_display,
                &entry.name,
                entry.uncompressed_size,
                per_entry_cap,
                "uncompressed",
            ) {
                return false;
            }
            continue;
        }
        if entry.uncompressed_size > 0
            && (*total_uncompressed).saturating_add(entry.uncompressed_size) > total_budget
        {
            let error = report_archive_truncation(
                archive_display,
                (*total_uncompressed).saturating_add(entry.uncompressed_size),
                total_budget,
            );
            if !emit(Err(error)) {
                return false;
            }
            break;
        }

        let compressed = match read_local_zip_entry_data(reader, &entry) {
            Ok(data) => data,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry.name,
                    error,
                    "cannot read archive entry payload; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan duplicate ZIP entry '{}//{}': cannot read local entry payload ({error}); entry was not scanned",
                    archive_display, entry.name
                )))) {
                    return false;
                }
                continue;
            }
        };
        let single_entry_zip = match build_single_entry_zip(&entry, "__keyhog_entry__", &compressed)
        {
            Ok(zip) => zip,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry.name,
                    error,
                    "cannot rebuild duplicate archive entry for isolated scan; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan duplicate ZIP entry '{}//{}': cannot rebuild isolated entry ({error}); entry was not scanned",
                    archive_display, entry.name
                )))) {
                    return false;
                }
                continue;
            }
        };
        let mut single_archive = match zip::ZipArchive::new(Cursor::new(single_entry_zip)) {
            Ok(archive) => archive,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry.name,
                    %error,
                    "cannot rebuild duplicate archive entry for isolated scan; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan duplicate ZIP entry '{}//{}': cannot open rebuilt isolated entry ({error}); entry was not scanned",
                    archive_display, entry.name
                )))) {
                    return false;
                }
                continue;
            }
        };
        let mut single_entry = match single_archive.by_index(0) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry.name,
                    %error,
                    "cannot open duplicate archive entry for isolated scan; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan duplicate ZIP entry '{}//{}': cannot open isolated entry ({error}); entry was not scanned",
                    archive_display, entry.name
                )))) {
                    return false;
                }
                continue;
            }
        };
        let remaining_budget = total_budget.saturating_sub(*total_uncompressed);
        let read_cap = per_entry_cap.min(remaining_budget);
        let read = match crate::capped_read::read_to_cap(
            &mut single_entry,
            read_cap,
            Some(entry.uncompressed_size),
        ) {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    archive = archive_display,
                    entry = %entry.name,
                    %error,
                    "cannot read duplicate archive entry; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan duplicate ZIP entry '{}//{}': cannot read entry ({error}); entry was not scanned",
                    archive_display, entry.name
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
                    entry = %entry.name,
                    %error,
                    "duplicate archive entry decoded length cannot be represented; skipping"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                if !emit(Err(SourceError::Other(format!(
                    "failed to scan duplicate ZIP entry '{}//{}': decoded length cannot be represented ({error}); entry was not scanned",
                    archive_display, entry.name
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
                entry = %entry.name,
                size = observed_uncompressed,
                "skipping archive entry: decoded size exceeds per-file cap"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            if !emit_archive_entry_over_cap_error(
                emit,
                "duplicate ZIP entry",
                archive_display,
                &entry.name,
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
            &entry_path_name,
            content,
            per_entry_cap,
            total_budget,
            total_uncompressed,
            respect_default_excludes,
            nested_depth,
            emit,
        ) {
            return false;
        }
    }
    true
}

fn read_central_zip_entries<R: Read + Seek>(
    reader: &mut R,
) -> Result<Vec<CentralZipEntry>, String> {
    const EOCD_LEN: usize = 22;
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| error.to_string())?;
    let tail_len = usize::try_from(file_len.min(66_000)).map_err(|error| error.to_string())?;
    if tail_len < EOCD_LEN {
        return Err(
            "zip file is too short to contain an end-of-central-directory record".to_string(),
        );
    }
    reader
        .seek(SeekFrom::End(-(tail_len as i64)))
        .map_err(|error| error.to_string())?;
    let mut tail = vec![0u8; tail_len];
    reader
        .read_exact(&mut tail)
        .map_err(|error| error.to_string())?;
    let tail_file_offset = file_len.saturating_sub(tail_len as u64);
    let mut eocd = None;
    let mut last_candidate_error = None;
    for (index, window) in tail.windows(EOCD_LEN).enumerate().rev() {
        if !window.starts_with(ZIP_END_OF_CENTRAL_DIRECTORY_PREFIX) {
            continue;
        }
        let comment_len = usize::from(read_u16(&tail[index + 20..index + 22])?);
        if index
            .checked_add(EOCD_LEN)
            .and_then(|value| value.checked_add(comment_len))
            != Some(tail.len())
        {
            continue;
        }
        let central_size = read_u32(&tail[index + 12..index + 16])?;
        let central_offset = read_u32(&tail[index + 16..index + 20])?;
        let absolute_eocd = tail_file_offset
            .checked_add(index as u64)
            .ok_or_else(|| "zip end-of-central-directory offset overflow".to_string())?;
        let central_end = u64::from(central_offset)
            .checked_add(u64::from(central_size))
            .ok_or_else(|| "zip central directory end offset overflow".to_string())?;
        if central_end == absolute_eocd {
            eocd = Some(index);
            break;
        }
        last_candidate_error = Some(if central_end > file_len {
            "zip end-of-central-directory record declares a central directory past the end of the file"
                .to_string()
        } else {
            "zip end-of-central-directory record does not point to the central directory immediately before it"
                .to_string()
        });
    }
    let eocd = match eocd {
        Some(eocd) => eocd,
        None => {
            return Err(match last_candidate_error {
                Some(error) => error,
                None => "valid zip end-of-central-directory record not found".to_string(),
            });
        }
    };
    let total_entries = read_u16(&tail[eocd + 10..eocd + 12])?;
    let central_size = read_u32(&tail[eocd + 12..eocd + 16])?;
    let central_offset = read_u32(&tail[eocd + 16..eocd + 20])?;
    if total_entries == u16::MAX || central_size == u32::MAX || central_offset == u32::MAX {
        return Err("zip64 central directory is not handled by duplicate fallback".to_string());
    }
    reader
        .seek(SeekFrom::Start(u64::from(central_offset)))
        .map_err(|error| error.to_string())?;
    let central_len = usize::try_from(central_size).map_err(|error| error.to_string())?;
    // A crafted EOCD can declare a central-directory size far larger than the
    // file. `vec![0u8; central_len]` eagerly reserves that many bytes (an
    // alloc-bomb that aborts the process under a memory cap / cgroup, or a large
    // virtual-memory spike under overcommit) BEFORE `read_exact` could fail at
    // EOF. The central directory must physically fit within the file at its
    // declared offset, so reject any size that overruns the file before
    // allocating.
    if u64::from(central_offset).saturating_add(u64::from(central_size)) > file_len {
        return Err(
            "zip end-of-central-directory record declares a central directory past the end of the file"
                .to_string(),
        );
    }
    let mut central = vec![0u8; central_len];
    reader
        .read_exact(&mut central)
        .map_err(|error| error.to_string())?;

    let mut entries = Vec::with_capacity(usize::from(total_entries));
    let mut offset = 0usize;
    for _ in 0..total_entries {
        let fixed_end = offset
            .checked_add(46)
            .ok_or_else(|| "zip central directory fixed header length overflow".to_string())?;
        if fixed_end > central.len() {
            return Err("truncated zip central directory entry".to_string());
        }
        if read_u32(&central[offset..offset + 4])? != ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE {
            return Err("invalid zip central directory signature".to_string());
        }
        let compression_method = read_u16(&central[offset + 10..offset + 12])?;
        let crc32 = read_u32(&central[offset + 16..offset + 20])?;
        let compressed_size = read_u32(&central[offset + 20..offset + 24])?;
        let uncompressed_size = read_u32(&central[offset + 24..offset + 28])?;
        let name_len = usize::from(read_u16(&central[offset + 28..offset + 30])?);
        let extra_len = usize::from(read_u16(&central[offset + 30..offset + 32])?);
        let comment_len = usize::from(read_u16(&central[offset + 32..offset + 34])?);
        let external_attrs = read_u32(&central[offset + 38..offset + 42])?;
        let local_header_offset = read_u32(&central[offset + 42..offset + 46])?;
        if compressed_size == u32::MAX
            || uncompressed_size == u32::MAX
            || local_header_offset == u32::MAX
        {
            return Err(
                "zip64 central directory entry is not handled by duplicate fallback".to_string(),
            );
        }
        let name_start = fixed_end;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| "zip central directory name length overflow".to_string())?;
        let next = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| "zip central directory entry length overflow".to_string())?;
        if next > central.len() {
            return Err("truncated zip central directory variable fields".to_string());
        }
        let name = String::from_utf8_lossy(&central[name_start..name_end]).into_owned();
        entries.push(CentralZipEntry {
            name,
            compression_method,
            crc32,
            compressed_size: u64::from(compressed_size),
            uncompressed_size: u64::from(uncompressed_size),
            local_header_offset: u64::from(local_header_offset),
            external_attrs,
        });
        offset = next;
    }
    Ok(entries)
}

fn read_local_zip_entry_data<R: Read + Seek>(
    reader: &mut R,
    entry: &CentralZipEntry,
) -> Result<Vec<u8>, String> {
    let file_len = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| error.to_string())?;
    reader
        .seek(SeekFrom::Start(entry.local_header_offset))
        .map_err(|error| error.to_string())?;
    let mut header = [0u8; 30];
    reader
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if read_u32(&header[0..4])? != ZIP_LOCAL_FILE_HEADER_SIGNATURE {
        return Err("invalid zip local file header signature".to_string());
    }
    let name_len = u64::from(read_u16(&header[26..28])?);
    let extra_len = u64::from(read_u16(&header[28..30])?);
    let data_offset = entry
        .local_header_offset
        .checked_add(30)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| "zip local entry offset overflow".to_string())?;
    reader
        .seek(SeekFrom::Start(data_offset))
        .map_err(|error| error.to_string())?;
    let data_len = usize::try_from(entry.compressed_size)
        .map_err(|error| format!("zip entry compressed size is too large: {error}"))?;
    // Bound the allocation by the bytes actually present after the local header:
    // a crafted central entry can claim a `compressed_size` far larger than the
    // file, and `vec![0u8; data_len]` would reserve it eagerly (aborting under a
    // memory cap) before `read_exact` hits EOF.
    if entry.compressed_size > file_len.saturating_sub(data_offset) {
        return Err(
            "zip local entry declares compressed data past the end of the file".to_string(),
        );
    }
    let mut data = vec![0u8; data_len];
    reader
        .read_exact(&mut data)
        .map_err(|error| error.to_string())?;
    Ok(data)
}

fn build_single_entry_zip(
    entry: &CentralZipEntry,
    name: &str,
    compressed: &[u8],
) -> Result<Vec<u8>, String> {
    let name_bytes = name.as_bytes();
    let local_offset = 0u32;
    let compressed_size = u32::try_from(entry.compressed_size)
        .map_err(|error| format!("compressed size does not fit zip32: {error}"))?;
    let uncompressed_size = u32::try_from(entry.uncompressed_size)
        .map_err(|error| format!("uncompressed size does not fit zip32: {error}"))?;
    let name_len = u16::try_from(name_bytes.len())
        .map_err(|error| format!("entry name length does not fit zip32: {error}"))?;
    let mut out = Vec::new();
    write_u32(&mut out, ZIP_LOCAL_FILE_HEADER_SIGNATURE);
    write_u16(&mut out, 20);
    write_u16(&mut out, 0);
    write_u16(&mut out, entry.compression_method);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u32(&mut out, entry.crc32);
    write_u32(&mut out, compressed_size);
    write_u32(&mut out, uncompressed_size);
    write_u16(&mut out, name_len);
    write_u16(&mut out, 0);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(compressed);

    let central_offset = u32::try_from(out.len())
        .map_err(|error| format!("central directory offset does not fit zip32: {error}"))?;
    write_u32(&mut out, ZIP_CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE);
    write_u16(&mut out, 20);
    write_u16(&mut out, 20);
    write_u16(&mut out, 0);
    write_u16(&mut out, entry.compression_method);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u32(&mut out, entry.crc32);
    write_u32(&mut out, compressed_size);
    write_u32(&mut out, uncompressed_size);
    write_u16(&mut out, name_len);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u32(&mut out, entry.external_attrs);
    write_u32(&mut out, local_offset);
    out.extend_from_slice(name_bytes);

    let central_end = u32::try_from(out.len())
        .map_err(|error| format!("central directory end does not fit zip32: {error}"))?;
    let central_size = central_end
        .checked_sub(central_offset)
        .ok_or_else(|| "central directory size underflow".to_string())?;
    write_u32(&mut out, ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 1);
    write_u16(&mut out, 1);
    write_u32(&mut out, central_size);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0);
    Ok(out)
}

fn read_u16(bytes: &[u8]) -> Result<u16, String> {
    let array: [u8; 2] = bytes
        .try_into()
        .map_err(|_| "short zip u16 field".to_string())?;
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8]) -> Result<u32, String> {
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| "short zip u32 field".to_string())?;
    Ok(u32::from_le_bytes(array))
}

pub(crate) fn read_central_zip_entries_error_for_test(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    match read_central_zip_entries(&mut file) {
        Ok(_entries) => Err("zip central directory parsed without an error".to_string()),
        Err(error) => Ok(error),
    }
}

pub(crate) fn read_local_zip_entry_data_error_for_test(
    path: &Path,
    compressed_size: u64,
) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let entry = CentralZipEntry {
        name: "entry".to_string(),
        compression_method: 0,
        crc32: 0,
        compressed_size,
        uncompressed_size: 0,
        local_header_offset: 0,
        external_attrs: 0,
    };
    match read_local_zip_entry_data(&mut file, &entry) {
        Ok(_data) => Err("zip local entry payload read without an error".to_string()),
        Err(error) => Ok(error),
    }
}

pub(crate) fn duplicate_zip_reopen_error_for_test(path: &Path) -> Option<String> {
    let mut errors = Vec::new();
    extract_zip_archive_from_central_entries(
        path,
        &path.display().to_string(),
        u64::MAX,
        u64::MAX,
        true,
        &mut |row| {
            if let Err(error) = row {
                errors.push(error.to_string());
            }
            true
        },
        Vec::new(),
    );
    errors.pop()
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
