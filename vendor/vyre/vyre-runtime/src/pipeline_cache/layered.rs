//! [`LayeredPipelineCache`]  -  composite store that reads from every
//! backend in order and writes only to the first.

use std::io;
use std::sync::Arc;

use super::fingerprint::PipelineFingerprint;
use super::metrics::PipelineCacheMetrics;
use super::store::PipelineCacheStore;

/// Composite store that reads from every backend and writes to
/// the first. Lets callers compose `[RamStore, DiskStore, RemoteStore]`
/// so a miss at the fast layer falls through to slower layers.
pub struct LayeredPipelineCache {
    layers: Vec<Arc<dyn PipelineCacheStore>>,
}

impl LayeredPipelineCache {
    /// Construct from an ordered list (fastest-first). Lookups
    /// consult every layer in order; writes land in the first layer
    /// only  -  downstream layers are expected to be populated
    /// independently (e.g., from a pre-compiled blob bundle).
    #[must_use]
    pub fn new(layers: Vec<Arc<dyn PipelineCacheStore>>) -> Self {
        Self { layers }
    }
}

impl PipelineCacheStore for LayeredPipelineCache {
    fn get(&self, fp: &PipelineFingerprint) -> Option<Vec<u8>> {
        self.get_arc(fp).map(|artifact| (*artifact).clone())
    }

    /// V7-PERF-009: forward through to each layer's zero-clone path so
    /// the hit propagates without an intermediate `Vec<u8>` allocation.
    fn get_arc(&self, fp: &PipelineFingerprint) -> Option<Arc<Vec<u8>>> {
        for layer in &self.layers {
            if let Some(arc) = layer.get_arc(fp) {
                return Some(arc);
            }
        }
        None
    }

    fn put(&self, fp: PipelineFingerprint, artifact: Vec<u8>) {
        if let Some(first) = self.layers.first() {
            first.put(fp, artifact);
        }
    }

    fn flush(&self) -> io::Result<()> {
        for layer in &self.layers {
            layer.flush()?;
        }
        Ok(())
    }

    fn metrics(&self) -> PipelineCacheMetrics {
        self.layers
            .iter()
            .fold(PipelineCacheMetrics::default(), |acc, layer| {
                acc.checked_add(layer.metrics())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline_cache::test_helpers::tiny_program;
    use crate::pipeline_cache::InMemoryPipelineCache;

    #[test]
    fn layered_cache_prefers_first_hit() {
        let fast = Arc::new(InMemoryPipelineCache::new());
        let slow = Arc::new(InMemoryPipelineCache::new());
        let fp = PipelineFingerprint::of(&tiny_program());
        slow.put(fp, b"fallback".to_vec());
        let cache = LayeredPipelineCache::new(vec![fast.clone(), slow]);
        // Miss in fast, hit in slow.
        assert_eq!(cache.get(&fp).unwrap(), b"fallback".to_vec());
        // Put lands in fast only.
        cache.put(fp, b"warmed".to_vec());
        assert_eq!(fast.get(&fp).unwrap(), b"warmed".to_vec());
    }

    #[test]
    fn layered_cache_metrics_aggregate_layers() {
        let fast = Arc::new(InMemoryPipelineCache::new());
        let slow = Arc::new(InMemoryPipelineCache::new());
        let fp = PipelineFingerprint::of(&tiny_program());
        slow.put(fp, b"slow".to_vec());
        let cache = LayeredPipelineCache::new(vec![fast, slow]);

        assert_eq!(cache.get(&fp).unwrap(), b"slow".to_vec());
        let metrics = cache.metrics();
        assert_eq!(metrics.lookups, 2);
        assert_eq!(metrics.hits, 1);
        assert_eq!(metrics.misses, 1);
    }
}
