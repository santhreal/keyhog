//! Batched resident CSR frontier-queue execution.
//!
//! This module owns multi-query sparse traversal over one resident CSR graph:
//! each query gets resident scratch slots, all frontiers are uploaded together,
//! all queue/traverse kernels are submitted as one resident sequence, and all
//! frontier outputs are compactly read back at the end.

mod dispatch;

#[cfg(test)]
mod tests;

pub use dispatch::{run_resident_csr_queue_batch_budgeted_into, run_resident_csr_queue_batch_into};

use vyre_foundation::ir::Program;

use crate::graph::resident_handles::free_unique_resident_handles;
use crate::hardware::scratch::reserve_vec as reserve_graph_vec;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher, ResidentReadRange};

/// Reusable resident scratch for batched CSR queue traversal queries.
#[derive(Debug, Default)]
pub struct ResidentCsrQueueBatchScratch {
    handles: Vec<ResidentCsrQueueBatchQueryHandles>,
    shape: Option<ResidentCsrQueueBatchShape>,
    queue_len_init_program: Option<Program>,
    clear_frontier_out_program: Option<Program>,
    queue_program: Option<Program>,
    traverse_program: Option<Program>,
    frontier_payloads: Vec<Vec<u8>>,
    readbacks: Vec<Vec<u8>>,
    queue_len_init_handle_sets: Vec<[u64; 1]>,
    clear_handle_sets: Vec<[u64; 1]>,
    queue_handle_sets: Vec<[u64; 3]>,
    traverse_handle_sets: Vec<[u64; 6]>,
    read_ranges: Vec<ResidentReadRange>,
}

impl ResidentCsrQueueBatchScratch {
    /// Number of resident per-query scratch slots currently retained.
    #[must_use]
    pub fn resident_query_slots(&self) -> usize {
        self.handles.len()
    }

    /// Total host staging capacity retained for frontier uploads.
    #[must_use]
    pub fn frontier_payload_capacity(&self) -> usize {
        self.frontier_payloads.iter().map(Vec::capacity).sum()
    }

    /// Free all batch scratch resident buffers.
    pub fn free(&mut self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        let handle_slots = self.handles.len().checked_mul(4).ok_or_else(|| {
            DispatchError::BackendError(
                "Fix: resident CSR queue batch scratch free handle count overflowed.".to_string(),
            )
        })?;
        let mut handles_to_free = Vec::new();
        reserve_graph_vec(
            &mut handles_to_free,
            handle_slots,
            "resident CSR queue batch scratch free handles",
        )?;
        for handles in self.handles.drain(..) {
            handles_to_free.extend([
                handles.frontier,
                handles.active_queue,
                handles.queue_len,
                handles.frontier_out,
            ]);
        }
        let free_result = free_unique_resident_handles(
            dispatcher,
            &handles_to_free,
            "resident CSR queue batch scratch",
        );
        self.shape = None;
        self.queue_len_init_program = None;
        self.clear_frontier_out_program = None;
        self.queue_program = None;
        self.traverse_program = None;
        self.frontier_payloads.clear();
        self.readbacks.clear();
        self.queue_len_init_handle_sets.clear();
        self.clear_handle_sets.clear();
        self.queue_handle_sets.clear();
        self.traverse_handle_sets.clear();
        self.read_ranges.clear();
        free_result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentCsrQueueBatchQueryHandles {
    frontier: u64,
    active_queue: u64,
    queue_len: u64,
    frontier_out: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResidentCsrQueueBatchShape {
    batch_len: usize,
    frontier_bytes: usize,
    queue_capacity: u32,
    allow_mask: u32,
    node_count: u32,
    edge_count: u32,
}
