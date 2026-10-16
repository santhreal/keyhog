//! Crate-internal test facade wrappers for filesystem reader and extractor primitives.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use keyhog_core::{Chunk, MerkleIndex, SourceError};
use super::{extract, read, reader, FilesystemSource};

/// Crate-visible read of the walker's default window size for the limits
/// ordering guard. `reader::DEFAULT_WINDOW_SIZE` is `pub(in crate::filesystem)`,
/// so a test outside this module cannot see it directly, and the guard has to
/// compare it against the scanner's decode ceiling.
pub(crate) fn default_window_size_for_test() -> usize {
    reader::DEFAULT_WINDOW_SIZE
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

