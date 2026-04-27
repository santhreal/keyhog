//! Bounded LRU cache for WGPU pipeline artifacts.

use crate::pipeline::CachedPipelineArtifact;
use moka::sync::Cache;
use std::sync::Arc;

/// Bounded LRU cache for WGPU pipeline artifacts.
pub(crate) struct LruPipelineCache {
    artifacts: Cache<[u8; 32], Arc<CachedPipelineArtifact>>,
}

impl std::fmt::Debug for LruPipelineCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LruPipelineCache")
            .field("entries", &self.len())
            .finish_non_exhaustive()
    }
}

impl LruPipelineCache {
    /// Create a cache capped at `max_entries`.
    pub(crate) fn new(max_entries: u32) -> Self {
        let max_capacity = u64::from(max_entries.max(1));
        Self {
            artifacts: Cache::builder().max_capacity(max_capacity).build(),
        }
    }

    /// Retrieve an artifact and update its recency.
    pub(crate) fn get(&self, fingerprint: &[u8; 32]) -> Option<Arc<CachedPipelineArtifact>> {
        self.artifacts.get(fingerprint)
    }

    /// Insert an artifact, evicting cold entries until capacity is available.
    pub(crate) fn insert(&self, fingerprint: [u8; 32], artifact: Arc<CachedPipelineArtifact>) {
        self.artifacts.insert(fingerprint, artifact);
    }

    /// Remove every cached artifact.
    pub(crate) fn clear(&self) {
        self.artifacts.invalidate_all();
        self.artifacts.run_pending_tasks();
    }

    /// Number of cached artifact keys.
    pub(crate) fn len(&self) -> usize {
        self.artifacts.run_pending_tasks();
        self.artifacts.entry_count() as usize
    }
}
