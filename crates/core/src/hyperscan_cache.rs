//! Shared Hyperscan serialized-database cache header contract.

/// Filename prefix of every KeyHog Hyperscan shard cache file (`hs-<sha256>.db`).
/// Single owner shared by the hardening lockdown gate (which strips it to
/// recognise a trusted compiled-pattern cache) and the scanner shard writer
/// (which builds the name), so the two can never disagree.
pub const HYPERSCAN_CACHE_PREFIX: &str = "hs-";

/// Filename suffix of every KeyHog Hyperscan shard cache file. See
/// [`HYPERSCAN_CACHE_PREFIX`].
pub const HYPERSCAN_CACHE_SUFFIX: &str = ".db";

/// Magic bytes at the front of every KeyHog Hyperscan shard cache file.
pub const HYPERSCAN_CACHE_MAGIC: &[u8; 4] = b"KHHS";

/// KeyHog-owned cache header version for serialized Hyperscan shard files.
pub const HYPERSCAN_CACHE_VERSION: u32 = 2;

/// Byte length of the KeyHog Hyperscan cache header: magic plus little-endian version.
pub const HYPERSCAN_CACHE_HEADER_LEN: usize = 8;

/// Hard cap for one serialized Hyperscan shard cache file, including the KeyHog header.
///
/// This is a performance-cache bound, not a detector correctness bound. Files above
/// this cap are not loaded or persisted; the scanner compiles from detector patterns
/// instead. The cap is intentionally owned in core so read-side validation and
/// write-side persistence cannot drift.
pub const HYPERSCAN_CACHE_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Return true when `header` is exactly the current KeyHog Hyperscan cache header.
pub fn hyperscan_cache_header_is_valid(header: &[u8]) -> bool {
    if header.len() != HYPERSCAN_CACHE_HEADER_LEN {
        return false;
    }
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    &header[..4] == HYPERSCAN_CACHE_MAGIC && version == HYPERSCAN_CACHE_VERSION
}

/// Append the current KeyHog Hyperscan cache header to a serialized-cache buffer.
pub fn write_hyperscan_cache_header(output: &mut Vec<u8>) {
    output.extend_from_slice(HYPERSCAN_CACHE_MAGIC);
    output.extend_from_slice(&HYPERSCAN_CACHE_VERSION.to_le_bytes());
}

/// Build the on-disk filename of a KeyHog Hyperscan shard cache file from its
/// content `shard_key`: `hs-<shard_key>.db`. Single owner of the name FORMAT,
/// shared by the scanner shard writer (which persists the file) and the
/// hardening lockdown gate (which recognises/strips it via
/// [`HYPERSCAN_CACHE_PREFIX`]/[`HYPERSCAN_CACHE_SUFFIX`]), so writer and reader
/// can never disagree on the shard filename. Previously the writer re-inlined
/// the `hs-`/`.db` affixes in a `format!`, a latent drift from this owner.
#[must_use]
pub fn hyperscan_cache_filename(shard_key: &str) -> String {
    format!("{HYPERSCAN_CACHE_PREFIX}{shard_key}{HYPERSCAN_CACHE_SUFFIX}")
}
