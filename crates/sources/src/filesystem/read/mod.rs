//! File-reading primitives used by the filesystem source: safe `open`,
//! buffered reads, mmap, windowed mmap, base64-aware decode, and the
//! `FileBytes` wrapper for the compressed-input pipeline.
//!
//! Split into focused submodules by file-read responsibility:
//!
//!   * [`raw`]      - safe `open`, buffered read, mmap whole-file.
//!   * [`bytes`]    - [`FileBytes`] enum + compressed-input mmap.
//!   * [`window`]   - overlapping-window slicer for big files.
//!   * [`decode`]   - text decoding: UTF-8 fast path, UTF-16 BOM, lossy fallback, binary rejection.
//!
//! All public entry points re-exported from this `mod.rs` so the
//! consumer (`super::filesystem`) imports them through one path.

mod bytes;
mod decode;
mod raw;
mod window;

pub(super) use bytes::read_file_for_compressed_input;
/// Re-export the canonical text decoder so non-walker entry points (e.g.
/// `keyhog watch`) can decode a single file's bytes IDENTICALLY to the scan
/// walker, rather than each one inventing its own weaker read (Law 10 recall
/// parity + no-duplication).
pub(crate) use decode::decode_text_file;
pub(in crate::filesystem) use decode::looks_binary_prefix;
pub(super) use raw::{
    open_file_safe, read_file_buffered, read_file_mmap, read_file_prefix_safe, read_file_safe,
    BufferedFileRead,
};
pub(super) use window::for_each_file_windowed_mmap;

/// Cap on any mmap-based read. The walker already enforces the user's
/// `max_file_size` based on a stat before scheduling; this is the
/// post-open re-stat ceiling that defeats a walker-stat-then-grow
/// TOCTOU race. 2 GiB chosen because every legitimate text file the
/// scanner cares about (source, configs, JSON dumps) fits comfortably
/// under it; anything larger is either binary or attacker-grown.
pub(super) const MMAP_TOCTOU_SANITY_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(crate) fn max_buffered_read_bytes_for_test() -> u64 {
    raw::MAX_BUFFERED_READ_BYTES
}

pub(crate) fn mmap_toctou_sanity_cap_bytes_for_test() -> u64 {
    MMAP_TOCTOU_SANITY_CAP_BYTES
}

pub(crate) fn read_file_safe_capped_for_test(
    path: &std::path::Path,
    cap: u64,
) -> std::io::Result<Vec<u8>> {
    raw::read_file_safe(path, cap)
}

pub(crate) fn read_file_mmap_for_test(path: &std::path::Path) -> Option<String> {
    match raw::read_file_mmap(path) {
        Some(raw::BufferedFileRead::Text(text)) => Some(text),
        _ => None,
    }
}

pub(crate) fn read_file_for_compressed_input_for_test(
    path: &std::path::Path,
    size_cap: u64,
) -> Option<Vec<u8>> {
    bytes::read_file_for_compressed_input(path, size_cap).map(|bytes| bytes.as_slice().to_vec())
}

pub(crate) fn read_file_windowed_mmap_len_for_test(
    path: &std::path::Path,
    window_size: usize,
    overlap: usize,
) -> Option<usize> {
    window::read_file_windowed_mmap(path, window_size, overlap).map(|windows| windows.len())
}

pub(crate) fn slice_into_windows_for_test(
    bytes: &[u8],
    window_size: usize,
    overlap: usize,
) -> Vec<String> {
    window::slice_into_windows(bytes, window_size, overlap)
        .into_iter()
        .map(|window| window.text)
        .collect()
}

pub(crate) fn decode_utf16_for_test(bytes: &[u8]) -> Option<String> {
    decode::decode_utf16(bytes)
}

pub(crate) fn looks_binary_for_test(bytes: &[u8]) -> bool {
    decode::looks_binary(bytes)
}

#[cfg(test)]
mod tests;
