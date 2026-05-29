//! Resident CSR frontier-queue execution.
//!
//! This module owns the reusable device-resident graph and scratch protocol for
//! sparse dataflow-dependent traversal: upload CSR graph buffers once, then run
//! repeated frontier queries by refreshing only frontier/scratch/output state.

mod query;
mod upload;

#[cfg(test)]
mod tests;

pub use query::run_resident_csr_queue_query_into;
pub use upload::upload_resident_csr_queue_graph;

use vyre_foundation::ir::Program;

use crate::graph::resident_handles::free_unique_resident_handles;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Device-resident CSR graph for queue-driven sparse traversal.
#[derive(Debug, Clone)]
pub struct ResidentCsrQueueGraph {
    node_count: u32,
    edge_count: u32,
    words: usize,
    edge_offsets_handle: u64,
    edge_targets_handle: u64,
    edge_kind_mask_handle: u64,
}

impl ResidentCsrQueueGraph {
    /// Number of graph nodes.
    #[must_use]
    pub fn node_count(&self) -> u32 {
        self.node_count
    }

    /// Number of physical CSR edges.
    #[must_use]
    pub fn edge_count(&self) -> u32 {
        self.edge_count
    }

    /// Number of u32 words in each frontier bitset.
    #[must_use]
    pub fn words(&self) -> usize {
        self.words
    }

    /// Resident edge-offset buffer handle.
    #[must_use]
    pub fn edge_offsets_handle(&self) -> u64 {
        self.edge_offsets_handle
    }

    /// Resident edge-target buffer handle.
    #[must_use]
    pub fn edge_targets_handle(&self) -> u64 {
        self.edge_targets_handle
    }

    /// Resident edge-kind-mask buffer handle.
    #[must_use]
    pub fn edge_kind_mask_handle(&self) -> u64 {
        self.edge_kind_mask_handle
    }

    /// Free graph-resident buffers.
    pub fn free(self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        free_unique_resident_handles(
            dispatcher,
            &[
                self.edge_offsets_handle,
                self.edge_targets_handle,
                self.edge_kind_mask_handle,
            ],
            "resident CSR queue graph",
        )
    }
}

/// Reusable resident scratch for CSR queue traversal queries.
#[derive(Debug, Default)]
pub struct ResidentCsrQueueScratch {
    handles: Option<ResidentCsrQueueScratchHandles>,
    frontier_bytes: Vec<u8>,
    readbacks: Vec<Vec<u8>>,
    queue_len_init_program: Option<Program>,
    clear_frontier_out_program: Option<Program>,
    queue_program: Option<Program>,
    traverse_program: Option<Program>,
    cached_shape: Option<ResidentCsrQueueProgramShape>,
}

impl ResidentCsrQueueScratch {
    /// Free scratch-resident buffers.
    pub fn free(&mut self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        let Some(handles) = self.handles.take() else {
            return Ok(());
        };
        self.frontier_bytes.clear();
        self.readbacks.clear();
        self.queue_len_init_program = None;
        self.clear_frontier_out_program = None;
        self.queue_program = None;
        self.traverse_program = None;
        self.cached_shape = None;
        free_unique_resident_handles(
            dispatcher,
            &[
                handles.frontier,
                handles.active_queue,
                handles.queue_len,
                handles.frontier_out,
            ],
            "resident CSR queue scratch",
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentCsrQueueScratchHandles {
    frontier: u64,
    active_queue: u64,
    queue_len: u64,
    frontier_out: u64,
    queue_capacity: u32,
    frontier_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentCsrQueueProgramShape {
    node_count: u32,
    edge_count: u32,
    queue_capacity: u32,
    allow_mask: u32,
}
