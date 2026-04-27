//! Tiered runtime cache primitives.

pub(crate) mod pipeline;

pub use buffer_pool::{BufferPool, PooledBuffer};
pub use disk::{DeviceFingerprint, DiskPipelineCache};
pub use lru::AccessTracker;
pub use tiered_cache::{AccessStats, CacheEntry, CacheError, CacheTier, LruPolicy, TieredCache};

/// Reusable GPU buffer pooling.
pub mod buffer_pool;
/// On-disk compiled-pipeline cache (content-addressed, device-fingerprinted).
pub mod disk;
/// LRU tracking.
pub mod lru;
/// Multi-tier cache storage, policy, and errors.
pub mod tiered_cache;

/// Backwards-compatible cache entry path.
pub mod cache_entry {
    pub use super::CacheEntry;
}

/// Backwards-compatible cache tier path.
pub mod cache_tier {
    pub use super::CacheTier;
}

/// Backwards-compatible tier policy path.
pub mod tier {
    pub use super::{AccessStats, CacheError, LruPolicy};
}

/// Cache test suites.
#[cfg(test)]
pub mod tests;
