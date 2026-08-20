//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use keyhog_core::MerkleIndex;
use keyhog_core::{Chunk, Source, SourceError};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod descriptor_walk;
mod discovery;
pub use discovery::DiscoveryCounts;
mod extract;
#[cfg(fuzzing)]
pub use extract::fuzz_extract_pdf_text;
pub(crate) mod filter;
mod path;
mod read;
mod reader;
#[cfg(all(test, unix))]
pub(crate) mod special_file_test_support;

pub(crate) use extract::extraction_total_budget;
pub(crate) use extract::validate_scan_archive_entry_name;
use filter::{walker_config, FilesystemWalkConfig};
pub(crate) use path::{display_path, display_path_arc};
pub(crate) use read::decode_text_file;
pub(crate) use read::{open_file_safe, open_file_safe_with_metadata};

#[cfg(feature = "docker")]
/// Emit image-metadata chunks for an in-memory layer member whose extension is a
/// recognised image type. Returns `Ok(Some(true))` when the member was an image and
/// emission completed, `Ok(Some(false))` when the consumer stopped, and `Ok(None)`
/// when the bytes are not a recognised image payload so the caller can fall through
/// to the ordinary Binary skip.
pub(crate) fn try_emit_image_metadata_member(
    entry_name: &str,
    bytes: &[u8],
    ext: &str,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> Result<Option<bool>, SourceError> {
    extract::try_emit_image_metadata_member(entry_name, bytes, ext, emit)
}

#[cfg(feature = "docker")]
pub(crate) fn try_emit_pdf_member(
    entry_name: &str,
    bytes: Vec<u8>,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    extract::try_emit_pdf_member(entry_name, bytes, emit)
}

#[cfg(feature = "docker")]
/// Shared container-magic probe used by Docker layer streaming and the
/// filesystem extensionless-container router.
pub(crate) fn container_extension_from_prefix(bytes: &[u8]) -> Option<&'static str> {
    extract::container_extension_from_prefix(bytes)
}

#[cfg(feature = "docker")]
/// True when `ext` is an openpack-handled archive extension (zip/jar/apk/ipa/crx/…).
pub(crate) fn is_openpack_archive_ext(ext: &str) -> bool {
    extract::is_openpack_archive_ext(ext)
}

#[cfg(feature = "docker")]
/// Scan one already-buffered archive/layer member through the shared in-memory
/// dispatcher (nested tar/zip/compressed descent + leaf text/strings). Used by
/// Docker layer streaming so a layer never has to hit the filesystem first.
/// Extract a top-level Docker-layer 7z/RAR member from already-buffered bytes.
/// Nested archive members must not use this helper.
pub(crate) fn emit_top_level_seven_zip_or_rar_member(
    ext: &str,
    content: Vec<u8>,
    member_display: &str,
    max_size: u64,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    extract::emit_top_level_seven_zip_or_rar_member(
        ext,
        content,
        member_display,
        max_size,
        respect_default_excludes,
        emit,
    )
}

#[cfg(feature = "docker")]
pub(crate) fn emit_in_memory_zip_member(
    member_display: &str,
    content: Vec<u8>,
    max_size: u64,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    extract::emit_in_memory_zip_member(
        member_display,
        content,
        max_size,
        respect_default_excludes,
        emit,
    )
}

#[cfg(feature = "docker")]
pub(crate) fn emit_in_memory_member(
    entry_name: &str,
    content: Vec<u8>,
    member_display: &str,
    max_size: u64,
    respect_default_excludes: bool,
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    extract::emit_in_memory_member(
        entry_name,
        content,
        member_display,
        max_size,
        respect_default_excludes,
        emit,
    )
}

/// Crate-visible read of the walker's default window size for the limits
/// ordering guard. `reader::DEFAULT_WINDOW_SIZE` is `pub(in crate::filesystem)`,
/// so a test outside this module cannot see it directly, and the guard has to
/// compare it against the scanner's decode ceiling.
pub(crate) fn default_window_size_for_test() -> usize {
    reader::DEFAULT_WINDOW_SIZE
}
/// Crate-visible wrapper over the walker's guarded single-file read (`read`'s
/// `pub(super)` primitive, which is `pub(in crate::filesystem)` and so cannot be
/// re-exported crate-wide directly) so the crate-public
/// [`crate::read_file_safe_bytes`] entry point used by `keyhog watch` shares the
/// SAME `O_NOFOLLOW` + special-file-refusing + size-capped read the scan walker
/// uses, instead of a raw `std::fs::read`. `cap == 0` selects the walker's hard
/// 2 GiB TOCTOU ceiling (see `read::read_file_safe`).
pub(crate) fn read_file_safe(path: &std::path::Path, cap: u64) -> std::io::Result<Vec<u8>> {
    read::read_file_safe(path, cap)
}

/// Default directory names excluded by the filesystem scanner (`.git`, `target`, `node_modules`, ...).
pub fn default_exclude_dirs() -> &'static [String] {
    filter::default_exclude_dirs()
}

/// Returns `true` if `path` matches any default exclusion rule (directory, file pattern, or suffix).
pub fn is_default_excluded_path(path: &str) -> bool {
    filter::is_default_excluded(path)
}

/// Returns `true` if raw UTF-8 `path` matches any default exclusion rule.
/// Returns `true` if path bytes match default exclude rules.
pub fn is_default_excluded_path_bytes(path: &[u8]) -> bool {
    filter::is_default_excluded_bytes(path)
}

/// Returns `true` if file extension `ext` is in the default skip extensions list.
pub fn is_default_skip_extension(ext: &str) -> bool {
    filter::is_skip_extension(ext)
}

/// Returns `true` if a single directory name `name` is a default excluded directory name.
pub fn is_default_excluded_dir_name(name: &std::ffi::OsStr) -> bool {
    filter::is_default_excluded_dir_name(name)
}

pub(crate) fn reader_pool_thread_count_for_test(scanner_threads: usize) -> usize {
    reader::reader_thread_count(scanner_threads, None)
}

pub(crate) fn reader_pool_thread_count_with_config_for_test(
    scanner_threads: usize,
    configured: NonZeroUsize,
) -> usize {
    reader::reader_thread_count(scanner_threads, Some(configured))
}

pub(crate) fn reader_panic_rows_for_test() -> Vec<Result<Chunk, SourceError>> {
    struct PanicEntries;

    impl Iterator for PanicEntries {
        type Item = codewalk::FileEntry;

        fn next(&mut self) -> Option<Self::Item> {
            panic!("reader exploded")
        }
    }

    let rx = reader::spawn_chunk_producer(
        Box::new(PanicEntries),
        None,
        Arc::new(AtomicUsize::new(0)),
        PathBuf::from("."),
        keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
        reader::DEFAULT_WINDOW_SIZE,
        reader::DEFAULT_WINDOW_OVERLAP,
        true,
        NonZeroUsize::new(1),
        crate::acquire_scan_read_lease(),
    );
    rx.into_iter().collect()
}

pub(crate) fn reader_process_entry_panic_rows_for_test() -> Vec<Result<Chunk, SourceError>> {
    reader::process_entry_panic_rows_for_test()
}

pub(crate) fn process_entry_with_recorded_size_for_test(
    path: PathBuf,
    recorded_size: u64,
    max_size: u64,
) -> Vec<Result<Chunk, SourceError>> {
    let mut rows = Vec::new();
    let entry = codewalk::FileEntry {
        path,
        size: recorded_size,
        is_binary: false,
    };
    // This helper drives `process_entry` directly (no gated `chunks()`), and a
    // refused symlink / unreadable entry records an Unreadable skip. Hold the
    // scan read lease across it so a counter-asserting test's exclusive scope
    // serializes the recording. A no-op in production where the gate is never
    // armed; see `skip::gate_scan`.
    let _scan_lease = crate::acquire_scan_read_lease();
    let _attributed = _scan_lease.enter();
    extract::process_entry(
        entry,
        &None,
        &Arc::new(AtomicUsize::new(0)),
        std::path::Path::new("."),
        max_size,
        reader::DEFAULT_WINDOW_SIZE,
        reader::DEFAULT_WINDOW_OVERLAP,
        true,
        &mut |row| {
            rows.push(row);
            true
        },
    );
    rows
}

pub(crate) fn process_entry_with_merkle_for_test(
    path: PathBuf,
    recorded_size: u64,
    max_size: u64,
    merkle: Arc<MerkleIndex>,
) -> (Vec<Result<Chunk, SourceError>>, usize) {
    let mut rows = Vec::new();
    let skipped = Arc::new(AtomicUsize::new(0));
    let entry = codewalk::FileEntry {
        path,
        size: recorded_size,
        is_binary: false,
    };
    // This helper drives `process_entry` directly (no gated `chunks()`), and a
    // refused symlink / unreadable entry records an Unreadable skip. Hold the
    // scan read lease across it so a counter-asserting test's exclusive scope
    // serializes the recording. A no-op in production where the gate is never
    // armed; see `skip::gate_scan`.
    let _scan_lease = crate::acquire_scan_read_lease();
    let _attributed = _scan_lease.enter();
    extract::process_entry(
        entry,
        &Some(merkle),
        &skipped,
        std::path::Path::new("."),
        max_size,
        reader::DEFAULT_WINDOW_SIZE,
        reader::DEFAULT_WINDOW_OVERLAP,
        true,
        &mut |row| {
            rows.push(row);
            true
        },
    );
    (rows, skipped.load(std::sync::atomic::Ordering::Relaxed))
}

pub(crate) fn max_buffered_read_bytes_for_test() -> u64 {
    read::max_buffered_read_bytes_for_test()
}

pub(crate) fn mmap_toctou_sanity_cap_bytes_for_test() -> u64 {
    read::mmap_toctou_sanity_cap_bytes_for_test()
}

#[derive(serde::Deserialize)]
struct ExpandableSymlinkExtensions {
    extensions: Vec<String>,
}

fn parse_expandable_symlink_extensions(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<ExpandableSymlinkExtensions>(raw)
        .map(|parsed| parsed.extensions)
        .map_err(|error| error.to_string())
}

static EXPANDABLE_SYMLINK_EXTS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_expandable_symlink_extensions(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/rules/expandable-symlink-extensions.toml"
    ))) {
        Ok(extensions) => extensions,
        Err(error) => panic!(
            "rules/expandable-symlink-extensions.toml is invalid: {error}. \
                 Fix the bundled Tier-B expandable-symlink extensions list."
        ),
    }
});

fn is_expandable_path(path: &Path) -> bool {
    path.extension()
        // LAW10: missing extension means a plain path; target-extension classification still runs separately; recall-safe
        .and_then(|e| e.to_str())
        // LAW10: non-UTF8 extension cannot match the curated ASCII archive-extension set; fail-closed
        .is_some_and(|ext| {
            (&*EXPANDABLE_SYMLINK_EXTS)
                .iter()
                .any(|candidate| ext.eq_ignore_ascii_case(candidate))
        })
}

fn resolved_link_target_for_classification(path: &Path) -> Result<PathBuf, std::io::Error> {
    let target = std::fs::read_link(path)?;
    if target.is_absolute() {
        Ok(target)
    } else {
        Ok(path
            .parent()
            .unwrap_or_else(|| Path::new("")) // LAW10: parentless relative target classification never opens or follows the link target; recall-safe
            .join(target))
    }
}

fn symlink_target_classification_error(path: &Path, error: &std::io::Error) -> SourceError {
    SourceError::Other(format!(
        "failed to inspect symlink target '{}': {error}; symlink target was not classified",
        display_path(path)
    ))
}

fn archive_symlink_error(path: &Path) -> SourceError {
    let path_display = display_path(path);
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or(""); // LAW10: missing/non-UTF8 extension falls back to generic archive-symlink wording; the symlink remains refused; recall-preserving
    let message = if ext.eq_ignore_ascii_case("tar") {
        format!(
            "failed to scan tar file '{path_display}': refusing to open archive at a symlink path; tar file was not scanned"
        )
    } else if ext.eq_ignore_ascii_case("har") {
        format!(
            "failed to scan HAR file '{path_display}': refusing to open archive at a symlink path; HAR file was not scanned"
        )
    } else {
        format!(
            "refusing to scan archive symlink '{path_display}': archive symlink expansion is blocked to prevent link-swap exfiltration"
        )
    };
    SourceError::Other(message)
}

fn classify_archive_symlink(path: &Path) -> Option<SourceError> {
    let path_is_expandable = is_expandable_path(path);
    match resolved_link_target_for_classification(path) {
        Ok(target) if path_is_expandable || is_expandable_path(&target) => {
            Some(archive_symlink_error(path))
        }
        Ok(_) => None,
        Err(error) if path_is_expandable => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "failed to inspect archive symlink target; refusing by link name"
            );
            Some(archive_symlink_error(path))
        }
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "failed to inspect symlink target during archive-symlink audit"
            );
            Some(symlink_target_classification_error(path, &error))
        }
    }
}

fn collect_walk_archive_symlink_errors(
    root: &Path,
    respect_default_excludes: bool,
    discovery_byte_limit: Option<u64>,
) -> Vec<SourceError> {
    let mut errors = Vec::new();
    let mut stack = Vec::new();
    let mut discovery_charge = 0_u64;

    match std::fs::symlink_metadata(root) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                if let Some(error) = classify_archive_symlink(root) {
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    errors.push(error);
                }
            } else if file_type.is_dir() {
                stack.push(root.to_path_buf());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return errors;
        }
        Err(error) => {
            tracing::warn!(
                path = %root.display(),
                %error,
                "failed to inspect filesystem root during archive-symlink audit"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            errors.push(SourceError::Other(format!(
                "failed to inspect filesystem root '{}': {error}; root was not scanned",
                display_path(root)
            )));
            return errors;
        }
    }

    // Ordinary discovery classifies symlinks in the configured walk below.
    // Budgeted discovery retains this path-sorted prewalk because its byte
    // ceiling applies before regular-file admission.
    if discovery_byte_limit.is_none() {
        return errors;
    }

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(
                    dir = %dir.display(),
                    %error,
                    "failed to read directory during archive-symlink audit"
                );
                let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                errors.push(SourceError::Other(format!(
                    "failed to inspect filesystem directory '{}': {error}; directory was not scanned",
                    display_path(&dir)
                )));
                continue;
            }
        };

        // Budgeted scans retain the previous path-sorted charging order.
        let mut paths = entries
            .filter_map(|entry| archive_walk_entry_path(&dir, entry, &mut errors))
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            if !inspect_walk_archive_path(
                path,
                root,
                respect_default_excludes,
                discovery_byte_limit,
                &mut discovery_charge,
                &mut stack,
                &mut errors,
            ) {
                return errors;
            }
        }
    }

    errors
}

#[cfg(target_os = "linux")]
fn collect_descriptor_archive_symlink_errors(
    root: &Path,
    respect_default_excludes: bool,
) -> Vec<SourceError> {
    use descriptor_walk::{walk_descriptor_relative, DescriptorEntryKind};
    use std::os::unix::ffi::OsStrExt;

    let mut errors = Vec::new();
    let result = walk_descriptor_relative(root, |entry| {
        if respect_default_excludes {
            let relative = entry
                .path
                .strip_prefix(root)
                .unwrap_or(entry.path.as_path());
            if filter::is_default_excluded_bytes(relative.as_os_str().as_bytes()) {
                // Prune default-excluded directories; skip excluded non-dirs.
                return Ok(false);
            }
        }
        if let DescriptorEntryKind::Symlink { target } = &entry.kind {
            let resolved_target = if target.is_absolute() {
                target.clone()
            } else {
                entry.path.parent().unwrap_or(root).join(target) // LAW10: a parentless relative symlink entry is resolved from the enumerated scan root; expansion checks still run on the result.
            };
            if is_expandable_path(&entry.path) || is_expandable_path(&resolved_target) {
                errors.push((entry.path.clone(), archive_symlink_error(&entry.path)));
            }
        }
        Ok(true)
    });
    if let Err(error) = result {
        errors.push((root.to_path_buf(), error));
    }
    errors.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    errors.into_iter().map(|(_, error)| error).collect()
}

fn archive_walk_entry_path(
    dir: &Path,
    entry: std::io::Result<std::fs::DirEntry>,
    errors: &mut Vec<SourceError>,
) -> Option<PathBuf> {
    match entry {
        Ok(entry) => Some(entry.path()),
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to read filesystem directory entry during archive-symlink audit"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            errors.push(SourceError::Other(format!(
                "failed to inspect filesystem directory entry under '{}': {error}; entry was not scanned",
                display_path(dir)
            )));
            None
        }
    }
}

fn inspect_walk_archive_path(
    path: PathBuf,
    root: &Path,
    respect_default_excludes: bool,
    discovery_byte_limit: Option<u64>,
    discovery_charge: &mut u64,
    stack: &mut Vec<PathBuf>,
    errors: &mut Vec<SourceError>,
) -> bool {
    let relative_path = match path.strip_prefix(root) {
        Ok(relative) => relative.to_string_lossy(),
        Err(_) => path.to_string_lossy(), // LAW10: a path outside the root keeps its full path for conservative exclude matching; the entry is not silently discarded here.
    };
    if respect_default_excludes && filter::is_default_excluded(&relative_path) {
        return true;
    }

    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "failed to inspect filesystem path during archive-symlink audit"
            );
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            errors.push(SourceError::Other(format!(
                "failed to inspect filesystem path '{}': {error}; path was not scanned",
                display_path(&path)
            )));
            return true;
        }
    };
    let file_type = metadata.file_type();
    let charge = if file_type.is_file() {
        metadata.len().max(1)
    } else {
        1
    };
    if let Some(limit) = discovery_byte_limit {
        let Some(total) = discovery_charge.checked_add(charge) else {
            return false;
        };
        if total > limit {
            return false;
        }
        *discovery_charge = total;
    }

    if file_type.is_symlink() {
        if let Some(error) = classify_archive_symlink(&path) {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            errors.push(error);
        }
    } else if file_type.is_dir() {
        stack.push(path);
    }
    true
}

pub(crate) fn read_file_safe_capped_for_test(
    path: &std::path::Path,
    cap: u64,
) -> std::io::Result<Vec<u8>> {
    read::read_file_safe_capped_for_test(path, cap)
}

pub(crate) fn read_stat_sized_to_cap_for_test(
    bytes: &[u8],
    expected_size: u64,
    hard_cap: u64,
) -> std::io::Result<Vec<u8>> {
    read::read_stat_sized_to_cap_for_test(bytes, expected_size, hard_cap)
}

pub(crate) fn read_file_mmap_for_test(path: &std::path::Path) -> Option<String> {
    read::read_file_mmap_for_test(path)
}

pub(crate) fn read_file_for_compressed_input_for_test(
    path: &std::path::Path,
    size_cap: u64,
) -> Option<Vec<u8>> {
    read::read_file_for_compressed_input_for_test(path, size_cap)
}

pub(crate) fn read_file_windowed_mmap_len_for_test(
    path: &std::path::Path,
    window_size: usize,
    overlap: usize,
) -> Option<usize> {
    read::read_file_windowed_mmap_len_for_test(path, window_size, overlap)
}

pub(crate) fn slice_into_windows_for_test(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
) -> Vec<String> {
    read::slice_into_windows_for_test(bytes, window_size, overlap)
}

pub(crate) fn decode_utf16_for_test(bytes: &[u8]) -> Option<String> {
    read::decode_utf16_for_test(bytes)
}

pub(crate) fn looks_binary_for_test(bytes: &[u8]) -> bool {
    read::looks_binary_for_test(bytes)
}
pub(crate) fn decode_text_file_for_test(bytes: &[u8]) -> Option<String> {
    read::decode_text_file_for_test(bytes)
}

pub(crate) fn decode_text_file_owned_or_bytes_for_test(bytes: Vec<u8>) -> Result<String, Vec<u8>> {
    read::decode_text_file_owned_or_bytes_for_test(bytes)
}

pub(crate) fn looks_binary_prefix_for_test(bytes: &[u8]) -> bool {
    read::looks_binary_prefix_for_test(bytes)
}

#[cfg(feature = "docker")]
pub(crate) fn has_utf16_bom_prefix(bytes: &[u8]) -> bool {
    read::has_utf16_bom_prefix(bytes)
}

#[cfg(feature = "docker")]
pub(crate) fn looks_binary_prefix(bytes: &[u8]) -> bool {
    read::looks_binary_prefix_for_test(bytes)
}

#[cfg(feature = "docker")]
pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    read::looks_binary_for_test(bytes)
}

pub(crate) fn slice_into_windows_with_offsets_for_test(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
) -> Vec<(usize, String)> {
    read::slice_into_windows_with_offsets_for_test(bytes, window_size, overlap)
}

pub(crate) fn read_file_windowed_mmap_for_test(
    path: &std::path::Path,
    window_size: usize,
    overlap: usize,
) -> Option<Vec<(usize, String)>> {
    read::read_file_windowed_mmap_for_test(path, window_size, overlap)
}

pub(crate) use read::ForEachWindowedMmapTestOutcome;

pub(crate) fn for_each_file_windowed_mmap_for_test<F>(
    path: &std::path::Path,
    window_size: usize,
    overlap: usize,
    emit: F,
) -> ForEachWindowedMmapTestOutcome
where
    F: FnMut(Result<(usize, String), String>) -> bool,
{
    read::for_each_file_windowed_mmap_for_test(path, window_size, overlap, emit)
}

pub(crate) fn read_file_buffered_text_for_test(
    path: &std::path::Path,
    size_hint: u64,
) -> Option<String> {
    read::read_file_buffered_text_for_test(path, size_hint)
}

pub(crate) fn read_file_prefix_safe_for_test(
    path: &std::path::Path,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    read::read_file_prefix_safe_for_test(path, buf)
}

pub(crate) fn duplicate_zip_central_entries_error_for_test(
    path: &std::path::Path,
) -> Result<String, String> {
    extract::duplicate_zip_central_entries_error_for_test(path)
}

pub(crate) fn duplicate_zip_local_entry_data_error_for_test(
    path: &std::path::Path,
    compressed_size: u64,
) -> Result<String, String> {
    extract::duplicate_zip_local_entry_data_error_for_test(path, compressed_size)
}

pub(crate) fn duplicate_zip_reopen_error_for_test(path: &std::path::Path) -> Option<String> {
    extract::duplicate_zip_reopen_error_for_test(path)
}

pub(crate) fn default_max_file_size_for_test() -> u64 {
    FilesystemSource::new(PathBuf::from(".")).max_file_size
}

/// Scans files in a directory tree.
pub struct FilesystemSource {
    root: PathBuf,
    max_file_size: u64,
    ignore_paths: Vec<String>,
    include_paths: Vec<PathBuf>,
    /// Whether to honor `.gitignore` / `.keyhogignore` files during the walk.
    /// `true` (default) is correct for normal scans. `keyhog scan-system`
    /// flips this to `false` because an attacker stashing a leaked key
    /// inside a project would `.gitignore` it.
    respect_gitignore: bool,
    /// Optional merkle-index handle. When set, the iterator consults the
    /// index per file BEFORE reading: if `(path, mtime_ns, size)` matches
    /// a stored entry the file is skipped without an open() / read() -
    /// the dominant cost on cold-cache disk. Doubles as an output sink:
    /// when `record_metadata` is true, the source records the live
    /// `(mtime, size)` of every chunk it does emit so the orchestrator
    /// only has to attach the BLAKE3 hash post-scan.
    merkle: Option<Arc<MerkleIndex>>,
    /// Counter incremented for every file the metadata fast-path skips.
    /// The orchestrator reads it after the scan to log how much I/O the
    /// cache saved. Atomic so rayon-driven walkers don't have to lock.
    skipped: Arc<AtomicUsize>,
    /// Window size for the big-file scan path. Tests override this via
    /// `with_window_config` to exercise the windowed flow without
    /// writing the 1 MiB fixtures the production threshold requires.
    window_size: usize,
    /// Bytes of overlap between consecutive windows. Same rationale.
    window_overlap: usize,
    /// Whether the walker's built-in exclusion list (lock files, minified /
    /// bundled JS, vendored directories: `filter::is_default_excluded` + the
    /// `.min.`/`.bundle.` filename checks) is applied. `true` (default) is the
    /// normal scan. `--no-default-excludes` flips this to `false` so a secret
    /// committed inside e.g. `package-lock.json` is still scanned, previously
    /// the flag only reached the codewalk glob layer, NOT this in-process
    /// filter, so the lock/vendored files stayed silently excluded.
    respect_default_excludes: bool,
    /// Explicit filesystem reader thread count. `None` keeps the source-derived
    /// default tied to the configured scan worker pool.
    reader_threads: Option<NonZeroUsize>,
    /// Optional metadata-discovery budget used by bounded whole-tree scans.
    discovery_byte_limit: Option<u64>,
    /// Set when discovery admits the first file beyond the configured budget.
    discovery_limit_reached: Arc<AtomicBool>,
    discovery_tracker: Arc<discovery::DiscoveryTracker>,
}

impl FilesystemSource {
    /// Create a filesystem source rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        // Canonicalize so discovered file paths and caller-provided explicit
        // include paths can be compared under one stable root.
        let root = root.canonicalize().unwrap_or(root); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
        Self {
            root,
            max_file_size: keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES,
            ignore_paths: Vec::new(),
            include_paths: Vec::new(),
            respect_gitignore: true,
            merkle: None,
            skipped: Arc::new(AtomicUsize::new(0)),
            window_size: reader::DEFAULT_WINDOW_SIZE,
            window_overlap: reader::DEFAULT_WINDOW_OVERLAP,
            respect_default_excludes: true,
            reader_threads: None,
            discovery_byte_limit: None,
            discovery_limit_reached: Arc::new(AtomicBool::new(false)),
            discovery_tracker: Arc::new(discovery::DiscoveryTracker::default()),
        }
    }

    /// Return the canonical scan root owned by this source.
    ///
    /// Daemon clients use this to send local path metadata instead of copying
    /// file payload bytes through the IPC frame.
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    /// Toggle the walker's built-in exclusion list (lock/minified/vendored).
    /// Pass `false` (from `--no-default-excludes`) to scan files the default
    /// list would otherwise drop. Default `true`.
    #[must_use]
    pub fn with_default_excludes(mut self, respect: bool) -> Self {
        self.respect_default_excludes = respect;
        self
    }
    /// Configure streaming window overlap size.
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        assert!(self.window_size > overlap, "window must exceed overlap");
        self.window_overlap = overlap;
        self
    }

    /// Override the windowed-scan overlap in bytes.
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        assert!(self.window_size > overlap, "window must exceed overlap");
        self.window_overlap = overlap;
        self
    }

    /// Configure streaming window overlap in bytes.
    #[must_use]
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        self.window_overlap = overlap;
        self
    }

    /// Override the windowed-scan parameters. Production callers stick
    /// with the defaults (1 MiB / 128 KiB); tests use this to exercise
    /// the multi-window path on tiny fixtures. `window_size` must
    /// strictly exceed `overlap` (the underlying slicer asserts this).
    #[must_use]
    pub fn with_window_config(mut self, window_size: usize, overlap: usize) -> Self {
        assert!(window_size > overlap, "window must exceed overlap");
        self.window_size = window_size;
        self.window_overlap = overlap;
        self
    }
    /// Override the window overlap size in bytes.
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        self.window_overlap = overlap;
        self
    }

    /// Override the streaming window overlap in bytes.
    #[must_use]
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        assert!(self.window_size > overlap, "window must exceed overlap");
        self.window_overlap = overlap;
        self
    }

    /// Override the streaming window overlap in bytes.
    #[must_use]
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        assert!(
            self.window_size > overlap,
            "window size must exceed overlap"
        );
        self.window_overlap = overlap;
        self
    }

    /// Override the window overlap size.
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        assert!(self.window_size > overlap, "window must exceed overlap");
        self.window_overlap = overlap;
        self
    }

    /// Override the streaming window overlap size.
    pub fn with_window_overlap(mut self, overlap: usize) -> Self {
        assert!(
            self.window_size > overlap,
            "window size must exceed overlap"
        );
        self.window_overlap = overlap;
        self
    }

    /// Wire the source up to a merkle index so `(path, mtime, size)`
    /// matches skip the file *before* it is read. The cache contents
    /// themselves are loaded by the orchestrator (which also handles
    /// detector-spec-hash invalidation) and shared via `Arc` so multiple
    /// sources can consult one index.
    pub fn with_merkle_skip(mut self, merkle: Arc<MerkleIndex>) -> Self {
        self.merkle = Some(merkle);
        self
    }

    /// Returns a counter that the source increments every time the
    /// metadata fast-path skips a file. Cloned `Arc<AtomicUsize>`, safe
    /// to read after the iterator drains.
    pub(crate) fn skipped_counter(&self) -> Arc<AtomicUsize> {
        self.skipped.clone()
    }

    /// Number of files skipped by the Merkle metadata fast-path.
    ///
    /// This is read by CLI dispatch after the source iterator drains because
    /// metadata-skipped files emit no chunks, so chunk-level incremental
    /// accounting cannot observe them.
    pub fn skipped_unchanged_count(&self) -> usize {
        self.skipped.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Only include files whose paths match one of the given paths.
    /// Paths are compared against the absolute path of each discovered file.
    pub fn with_include_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.include_paths = paths;
        self
    }

    /// Override the maximum file size scanned from disk.
    pub fn with_max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }

    /// Add patterns to ignore during the walk.
    pub fn with_ignore_paths(mut self, paths: Vec<String>) -> Self {
        self.ignore_paths = paths;
        self
    }

    /// Override whether the walk honors `.gitignore` / `.keyhogignore`.
    /// `keyhog scan-system` flips this to `false` so a leaked key
    /// stashed in `.gitignore` can't hide.
    pub fn with_respect_gitignore(mut self, respect: bool) -> Self {
        self.respect_gitignore = respect;
        self
    }

    /// Override the dedicated filesystem reader thread count.
    pub fn with_reader_threads(mut self, threads: NonZeroUsize) -> Self {
        self.reader_threads = Some(threads);
        self
    }

    /// Bound recursive file discovery by cumulative metadata size.
    ///
    /// The first file that crosses the limit is still admitted so the caller's
    /// chunk-level budget can refuse it and report partial coverage. Explicit
    /// include paths are unaffected.
    #[must_use]
    pub fn with_discovery_byte_limit(mut self, bytes: u64) -> Self {
        self.discovery_byte_limit = Some(bytes);
        self
    }

    /// Return whether recursive discovery stopped at its byte limit.
    #[must_use]
    pub fn discovery_limit_reached(&self) -> bool {
        self.discovery_limit_reached.load(Ordering::Relaxed)
    }

    /// Counters from the most recent production metadata discovery workflow.
    #[must_use]
    pub fn discovery_counts(&self) -> DiscoveryCounts {
        self.discovery_tracker.snapshot()
    }
}

impl Source for FilesystemSource {
    fn name(&self) -> &str {
        "filesystem"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        // Top-level acquisition: root validation, include admission, archive
        // symlink audit, and the directory walk all run under SourceAcquire.
        let _acquire = crate::profile::acquire_span();
        // Taken before any walk-error recording or reader-pool spawn so a
        // concurrent scan blocks here behind an active counter-asserting test
        // instead of polluting the process-global skip counters. No-op in
        // production (the gate is never armed). See `skip::gate_scan`.
        let scan_lease = crate::acquire_scan_read_lease();
        // Everything eager below (root validation, the archive-symlink audit,
        // the walk) records on this thread, so attribute it to this scan.
        let _attributed = scan_lease.enter();
        self.discovery_limit_reached.store(false, Ordering::Relaxed);
        self.discovery_tracker.reset();
        let max_size = self.max_file_size;
        let mut config = walker_config(
            self.max_file_size,
            &self.ignore_paths,
            self.respect_default_excludes,
        );
        if !self.respect_gitignore {
            config = config.respect_gitignore(false);
        }
        if self.include_paths.is_empty() {
            match self.root.try_exists() {
                Ok(true) => {}
                Ok(false) => {
                    self.discovery_tracker.record_error();
                    let error = SourceError::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "filesystem root '{}' does not exist; path was not scanned",
                            self.root.display()
                        ),
                    ));
                    return crate::attach_scan_lease(
                        scan_lease,
                        Box::new(std::iter::once(Err(error))),
                    );
                }
                Err(error) => {
                    self.discovery_tracker.record_error();
                    let error = SourceError::Io(std::io::Error::new(
                        error.kind(),
                        format!(
                            "failed to stat filesystem root '{}': {error}; path was not scanned",
                            self.root.display()
                        ),
                    ));
                    return crate::attach_scan_lease(
                        scan_lease,
                        Box::new(std::iter::once(Err(error))),
                    );
                }
            }
        }
        // Autoroute calibration and replay bucket the fused pipeline by chunk
        // batch shape. A parallel walker can emit the same tree in different
        // orders across runs, which changes which files land in a 32-chunk
        // batch and makes a freshly calibrated cache miss on replay. Collecting
        // and sorting FileEntry metadata by path keeps batch identity stable;
        // the heavier file reads still flow through the existing reader pool
        // below. Per-entry errors are counted and emitted as SourceError rows,
        // so one unreadable sibling cannot turn a partial scan into a clean
        // result.
        fn sorted_entries(
            root: &Path,
            config: &FilesystemWalkConfig,
            discovery_budget: &mut Option<u64>,
            discovery_limit_reached: &AtomicBool,
            tracker: &discovery::DiscoveryTracker,
        ) -> (Vec<codewalk::FileEntry>, Vec<SourceError>) {
            // Walking and walk-time filtering (gitignore, default excludes).
            let _walk = crate::profile::walk_span();
            let mut source_errors = Vec::new();
            let mut entries = Vec::new();
            // Returns false once discovery has admitted the first over-budget
            // entry, which is the signal to stop walking.
            let mut admit = |result: Result<codewalk::FileEntry, String>| -> bool {
                match result {
                    Ok(entry) => {
                        if let Some(remaining) = discovery_budget {
                            let charge = entry.size.max(1);
                            if charge > *remaining {
                                discovery_limit_reached.store(true, Ordering::Relaxed);
                                entries.push(entry);
                                return false;
                            }
                            *remaining -= charge;
                        }
                        entries.push(entry);
                        true
                    }
                    Err(error) => {
                        // An unreadable entry is an UNKNOWN, not a clean file. Count
                        // and emit it so a partial tree cannot read as clean.
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        tracing::warn!(
                            %error,
                            "skipping unreadable filesystem entry; scan continues"
                        );
                        source_errors.push(SourceError::Other(format!(
                            "failed to inspect filesystem entry: {error}; entry was not scanned"
                        )));
                        true
                    }
                }
            };
            // A discovery budget is charged in arrival order and stops at the
            // first crossing entry, so bounded discovery remains serial.
            discovery::walk_metadata_tracked(root, config, tracker, &mut admit);
            entries.sort_by(|left, right| left.path.cmp(&right.path));
            (entries, source_errors)
        }

        let mut source_errors: Vec<SourceError> = Vec::new();
        let mut discovery_budget = self.discovery_byte_limit;
        let entries: Box<dyn Iterator<Item = codewalk::FileEntry> + Send> = if !self
            .include_paths
            .is_empty()
        {
            // Restrict the walk to the canonicalized allowed set so we
            // never traverse unrequested subdirectories (KH-54). The set is
            // small (user-supplied include list); directory entries are
            // collected deterministically before the reader pool, and
            // explicitly-named single files are stat'd directly without a walk.
            let mut allowed: Vec<PathBuf> = Vec::new();
            for p in &self.include_paths {
                // No-follow guard at include-admission (M17), scoped to the
                // dangerous case. Include paths are admitted below via
                // `canonicalize()` + `is_file()`, BOTH of which follow
                // symlinks, and canonicalize resolves the link before any
                // later `is_symlink(path)` check can see it, so the refusal
                // must happen HERE, on the original pre-canonicalization path.
                //
                // ASYMMETRY (two pinned contracts): a symlink to a PLAIN file
                // is read (documented "canonicalize-then-read", the user
                // explicitly named it; see
                // `included_symlinked_plain_file_is_canonicalized_then_read`).
                // But a symlink whose link name OR resolved target extension marks
                // it as an ARCHIVE / expandable container (`creds.har ->
                // ~/.aws/credentials`, `creds.txt -> ~/capture.har`, `x.zip ->
                // /etc/...`) is REFUSED: following it would read AND structurally
                // EXPAND an out-of-tree target, the link-swap exfiltration class
                // (see `har_symlink_target_is_not_followed_via_include`).
                // The expandable-extension set mirrors the archive/compressed
                // branches in `extract.rs::process_entry`.
                let is_link = match std::fs::symlink_metadata(p) {
                    Ok(metadata) => metadata.file_type().is_symlink(),
                    Err(error) => {
                        tracing::warn!(
                            path = %p.display(),
                            %error,
                            "failed to classify explicitly included path without following links; refusing the include"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        source_errors.push(SourceError::Other(format!(
                            "failed to inspect explicitly included path '{}': {error}; path was not scanned",
                            p.display()
                        )));
                        continue;
                    }
                };
                if !is_link {
                    allowed.push(p.canonicalize().unwrap_or_else(|_| p.clone())); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
                    continue;
                }
                let path_is_expandable = is_expandable_path(p);
                let target = match p.canonicalize() {
                    Ok(target) => target,
                    Err(error) if path_is_expandable => {
                        tracing::warn!(
                            path = %p.display(),
                            %error,
                            "failed to canonicalize archive symlink target; refusing by link name"
                        );
                        p.clone()
                    }
                    Err(error) => {
                        tracing::warn!(
                            path = %p.display(),
                            %error,
                            "failed to canonicalize symlink include target"
                        );
                        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                        source_errors.push(symlink_target_classification_error(p, &error));
                        continue;
                    }
                };
                if path_is_expandable || is_expandable_path(&target) {
                    tracing::warn!(
                        path = %p.display(),
                        target = %target.display(),
                        "refusing --include of an archive symlink - prevents the link-swap exfiltration class"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    source_errors.push(SourceError::Other(format!(
                        "refusing to scan explicitly included archive symlink '{}': archive symlink expansion is blocked to prevent link-swap exfiltration",
                        p.display()
                    )));
                    continue;
                }
                allowed.push(target);
            }
            allowed.sort();
            allowed.dedup();
            let mut include_entries = Vec::new();
            for path in allowed {
                if path.is_dir() {
                    let (sub_entries, sub_errors) = sorted_entries(
                        &path,
                        &config,
                        &mut discovery_budget,
                        &self.discovery_limit_reached,
                        &self.discovery_tracker,
                    );
                    include_entries.extend(sub_entries);
                    source_errors.extend(sub_errors);
                    if self.discovery_limit_reached.load(Ordering::Relaxed) {
                        break;
                    }
                } else if path.is_file() {
                    match std::fs::metadata(&path) {
                        Ok(meta) => {
                            self.discovery_tracker.record_file_metadata(true);
                            include_entries.push(codewalk::FileEntry {
                                path,
                                size: meta.len(),
                                // `is_binary` is a walk-time hint codewalk fills for
                                // directory walks. For an EXPLICITLY-included single
                                // file the user asked us to scan, leave it false:
                                // keyhog never reads this field (it does its own
                                // null-byte binary check at read time in this same
                                // file), so the hint is inert and `false` keeps the
                                // requested file in the scan set.
                                is_binary: false,
                            });
                        }
                        // Law 10: the user EXPLICITLY --include'd this file but
                        // `stat` failed (permission / I/O / race-delete). A
                        // silent `empty()` here drops a requested file while the
                        // scan still prints "0 secrets", reading as a clean bill
                        // of health for a file we never read. Count it as
                        // unreadable so `report_skip_summary` surfaces the gap
                        // (the same counter the archive-symlink refusal above uses).
                        Err(e) => {
                            self.discovery_tracker.record_file_metadata(false);
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "explicitly --include'd file could not be stat'd; NOT scanned"
                            );
                            let _event =
                                crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                            source_errors.push(SourceError::Other(format!(
                                "failed to scan explicitly included path '{}': stat failed ({e}); path was not scanned",
                                path.display()
                            )));
                        }
                    }
                } else {
                    // Explicitly --include'd path that is neither a file nor a
                    // directory: a broken symlink, a special file (socket /
                    // device / fifo), or it vanished between include-admission
                    // and this walk. The user named it, so a silent drop would
                    // again read as "clean", count it unreadable so the gap is
                    // surfaced rather than swallowed (Law 10).
                    self.discovery_tracker.record_error();
                    tracing::warn!(
                        path = %path.display(),
                        "explicitly --include'd path is neither a file nor a directory; NOT scanned"
                    );
                    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
                    source_errors.push(SourceError::Other(format!(
                        "failed to scan explicitly included path '{}': path is neither a file nor a directory; path was not scanned",
                        path.display()
                    )));
                }
            }
            // Real discovery counts for the include-restricted admission set.
            crate::profile::add_input_units(include_entries.len() as u64);
            crate::profile::add_input_bytes(
                include_entries.iter().map(|entry| entry.size).sum::<u64>(),
            );
            Box::new(include_entries.into_iter())
        } else {
            source_errors.extend(collect_walk_archive_symlink_errors(
                &self.root,
                self.respect_default_excludes,
                self.discovery_byte_limit,
            ));
            if self.discovery_byte_limit.is_some() {
                let (walk_entries, walk_errors) = sorted_entries(
                    &self.root,
                    &config,
                    &mut discovery_budget,
                    &self.discovery_limit_reached,
                    &self.discovery_tracker,
                );
                source_errors.extend(walk_errors);
                crate::profile::add_input_units(walk_entries.len() as u64);
                crate::profile::add_input_bytes(
                    walk_entries.iter().map(|entry| entry.size).sum::<u64>(),
                );
                Box::new(walk_entries.into_iter())
            } else {
                let (walk_entries, walk_errors, input_units, input_bytes) =
                    discovery::collect_unbounded_sorted(
                        &self.root,
                        &config,
                        !self.ignore_paths.is_empty(),
                        &self.discovery_tracker,
                    );
                source_errors.extend(walk_errors);
                crate::profile::add_input_units(input_units as u64);
                crate::profile::add_input_bytes(input_bytes);
                Box::new(walk_entries)
            }
        };

        let merkle = self.merkle.clone();
        let skipped = self.skipped.clone();
        let window_size = self.window_size;
        let window_overlap = self.window_overlap;
        let respect_default_excludes = self.respect_default_excludes;
        let reader_threads = self.reader_threads;

        let rx = reader::spawn_chunk_producer(
            entries,
            merkle,
            skipped,
            self.root.clone(),
            max_size,
            window_size,
            window_overlap,
            respect_default_excludes,
            reader_threads,
            scan_lease.clone(),
        );
        crate::attach_scan_lease(
            scan_lease,
            Box::new(source_errors.into_iter().map(Err).chain(rx)),
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn chunk_identities_are_contiguous(&self) -> bool {
        true
    }
}
