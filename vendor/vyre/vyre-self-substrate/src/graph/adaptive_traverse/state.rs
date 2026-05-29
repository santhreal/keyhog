use crate::graph::plan_cache::GraphPlanCache;
use crate::graph::resident_handles::free_unique_resident_handles;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};
use vyre_primitives::graph::adaptive_traverse::AdaptiveTraversalPlanCacheKey;

pub(super) use vyre_primitives::graph::adaptive_traverse::{
    adaptive_four_russians_graph_content_hash as adaptive_four_russians_layout_hash,
    adaptive_traversal_graph_content_hash as adaptive_traversal_layout_hash,
};

/// Reusable resident frontier/count scratch for adaptive traversal.
#[derive(Debug, Default)]
pub struct AdaptiveTraversalResidentScratch {
    pub(super) handles: Option<[u64; 3]>,
    pub(super) queue_handle: Option<u64>,
    pub(super) frontier_bytes: usize,
    pub(super) queue_bytes: usize,
    pub(super) frontier_in_bytes: Vec<u8>,
    pub(super) readbacks: Vec<Vec<u8>>,
    pub(super) plan_cache: AdaptiveTraversalPlanCache,
}

impl AdaptiveTraversalResidentScratch {
    /// Snapshot plan-cache counters for repeated adaptive traversal tests.
    #[must_use]
    pub fn plan_cache_snapshot(&self) -> AdaptiveTraversalPlanCacheSnapshot {
        let snapshot = self.plan_cache.snapshot();
        AdaptiveTraversalPlanCacheSnapshot {
            entries: snapshot.entries,
            hits: snapshot.hits,
            misses: snapshot.misses,
        }
    }

    /// Free resident frontier/output/count buffers owned by this scratch.
    ///
    /// # Errors
    ///
    /// Returns the first backend free failure after attempting all handles.
    pub fn free(&mut self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        let Some(handles) = self.handles.take() else {
            if let Some(queue_handle) = self.queue_handle.take() {
                self.queue_bytes = 0;
                return free_unique_resident_handles(
                    dispatcher,
                    &[queue_handle],
                    "resident adaptive traversal scratch",
                );
            }
            return Ok(());
        };
        self.frontier_bytes = 0;
        if let Some(queue_handle) = self.queue_handle.take() {
            self.queue_bytes = 0;
            let all_handles = [handles[0], handles[1], handles[2], queue_handle];
            return free_unique_resident_handles(
                dispatcher,
                &all_handles,
                "resident adaptive traversal scratch",
            );
        }
        free_unique_resident_handles(dispatcher, &handles, "resident adaptive traversal scratch")
    }
}

/// Adaptive traversal plan-cache counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdaptiveTraversalPlanCacheSnapshot {
    /// Number of cached Programs.
    pub entries: usize,
    /// Number of lookups served from cache.
    pub hits: u64,
    /// Number of Programs built and inserted.
    pub misses: u64,
}

pub(super) type AdaptiveTraversalPlanCache = GraphPlanCache<AdaptiveTraversalPlanCacheKey>;
