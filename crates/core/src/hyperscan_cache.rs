//! Shared Hyperscan serialized-database cache header contract.

/// Magic bytes at the front of every Keyhog Hyperscan shard cache file.
pub const HYPERSCAN_CACHE_MAGIC: &[u8; 4] = b"KHHS";

/// Keyhog-owned cache header version for serialized Hyperscan shard files.
pub const HYPERSCAN_CACHE_VERSION: u32 = 1;

/// Byte length of the Keyhog Hyperscan cache header: magic plus little-endian version.
pub const HYPERSCAN_CACHE_HEADER_LEN: usize = 8;

/// Return true when `header` is exactly the current Keyhog Hyperscan cache header.
pub fn hyperscan_cache_header_is_valid(header: &[u8]) -> bool {
    if header.len() != HYPERSCAN_CACHE_HEADER_LEN {
        return false;
    }
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    &header[..4] == HYPERSCAN_CACHE_MAGIC && version == HYPERSCAN_CACHE_VERSION
}

/// Append the current Keyhog Hyperscan cache header to a serialized-cache buffer.
pub fn write_hyperscan_cache_header(output: &mut Vec<u8>) {
    output.extend_from_slice(HYPERSCAN_CACHE_MAGIC);
    output.extend_from_slice(&HYPERSCAN_CACHE_VERSION.to_le_bytes());
}
