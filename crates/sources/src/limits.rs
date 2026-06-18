//! Shared source byte/count limits.
//!
//! These are Tier-A operational limits: compiled defaults live here, the CLI
//! merges `.keyhog.toml` and flags into this struct, and each source receives
//! the resolved value through its constructor/builder. Source modules must not
//! define their own private byte-cap constants.

/// Compiled source-limit defaults used when no TOML or CLI override is set.
pub const DEFAULT_SOURCE_LIMITS: SourceLimits = SourceLimits {
    stdin_bytes: 10 * 1024 * 1024,
    web_response_bytes: 10 * 1024 * 1024,
    s3_object_bytes: 10 * 1024 * 1024,
    gcs_object_bytes: 10 * 1024 * 1024,
    azure_blob_bytes: 10 * 1024 * 1024,
    docker_tar_entry_bytes: 128 * 1024 * 1024,
    docker_image_config_bytes: 16 * 1024 * 1024,
    docker_tar_total_bytes: 8 * 1024 * 1024 * 1024,
    git_line_bytes: 10 * 1024 * 1024,
    git_total_bytes: 256 * 1024 * 1024,
    git_blob_bytes: 10 * 1024 * 1024,
    git_chunk_count: 500_000,
    binary_read_bytes: 64 * 1024 * 1024,
    binary_decompiled_bytes: 50 * 1024 * 1024,
};

/// Resolved limits for all source backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceLimits {
    pub stdin_bytes: usize,
    pub web_response_bytes: usize,
    pub s3_object_bytes: u64,
    pub gcs_object_bytes: u64,
    pub azure_blob_bytes: u64,
    pub docker_tar_entry_bytes: u64,
    pub docker_image_config_bytes: u64,
    pub docker_tar_total_bytes: u64,
    pub git_line_bytes: usize,
    pub git_total_bytes: usize,
    pub git_blob_bytes: u64,
    pub git_chunk_count: usize,
    pub binary_read_bytes: usize,
    pub binary_decompiled_bytes: u64,
}

impl Default for SourceLimits {
    fn default() -> Self {
        DEFAULT_SOURCE_LIMITS
    }
}
