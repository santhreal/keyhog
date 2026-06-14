//! File-reading primitives used by the filesystem source: safe `open`,
//! buffered reads, mmap, windowed mmap, base64-aware decode, and the
//! `FileBytes` wrapper for the compressed-input pipeline.
//!
//! Split into focused submodules so no single file exceeds the
//! 500-line cap:
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
pub(super) use raw::{read_file_buffered, read_file_mmap, read_file_safe};
pub(super) use window::read_file_windowed_mmap;
/// Re-export the canonical text decoder so non-walker entry points (e.g.
/// `keyhog watch`) can decode a single file's bytes IDENTICALLY to the scan
/// walker, rather than each one inventing its own weaker read (Law 10 recall
/// parity + no-duplication).
pub(crate) use decode::decode_text_file;

/// Cap on any mmap-based read. The walker already enforces the user's
/// `max_file_size` based on a stat before scheduling; this is the
/// post-open re-stat ceiling that defeats a walker-stat-then-grow
/// TOCTOU race. 2 GiB chosen because every legitimate text file the
/// scanner cares about (source, configs, JSON dumps) fits comfortably
/// under it; anything larger is either binary or attacker-grown.
pub(super) const MMAP_TOCTOU_SANITY_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[cfg(test)]
mod tests;
