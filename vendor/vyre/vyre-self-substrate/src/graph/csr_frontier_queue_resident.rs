//! Resident CSR frontier-queue execution.
//!
//! This module owns the reusable device-resident graph and scratch protocol for
//! sparse dataflow-dependent traversal: upload CSR graph buffers once, then run
//! repeated frontier queries by refreshing only frontier/scratch/output state.

use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse, frontier_to_queue, validate_csr_queue_graph,
    validate_frontier_queue_query,
};

use crate::dispatch_buffers::{
    u32_slice_to_le_bytes, u32_word_bytes, write_u32_slice_or_zero_words, write_zero_bytes,
    write_zero_u32_words,
};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

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
        free_all(
            dispatcher,
            &[
                self.edge_offsets_handle,
                self.edge_targets_handle,
                self.edge_kind_mask_handle,
            ],
        )
    }
}

/// Reusable resident scratch for CSR queue traversal queries.
#[derive(Debug, Default)]
pub struct ResidentCsrQueueScratch {
    handles: Option<ResidentCsrQueueScratchHandles>,
    frontier_bytes: Vec<u8>,
    queue_len_zero: Vec<u8>,
    frontier_out_zero: Vec<u8>,
    readbacks: Vec<Vec<u8>>,
    queue_program: Option<vyre_foundation::ir::Program>,
    traverse_program: Option<vyre_foundation::ir::Program>,
    cached_shape: Option<ResidentCsrQueueProgramShape>,
}

impl ResidentCsrQueueScratch {
    /// Free scratch-resident buffers.
    pub fn free(&mut self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        let Some(handles) = self.handles.take() else {
            return Ok(());
        };
        self.frontier_bytes.clear();
        self.queue_len_zero.clear();
        self.frontier_out_zero.clear();
        self.readbacks.clear();
        self.queue_program = None;
        self.traverse_program = None;
        self.cached_shape = None;
        free_all(
            dispatcher,
            &[
                handles.frontier,
                handles.active_queue,
                handles.queue_len,
                handles.frontier_out,
            ],
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

/// Upload a CSR graph into resident device buffers once.
pub fn upload_resident_csr_queue_graph(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> Result<ResidentCsrQueueGraph, DispatchError> {
    let layout = validate_csr_queue_graph(node_count, edge_offsets, edge_targets, edge_kind_mask)
        .map_err(DispatchError::BadInputs)?;
    let edge_offsets_bytes = u32_slice_to_le_bytes(edge_offsets);
    let mut edge_targets_bytes = Vec::new();
    write_u32_slice_or_zero_words(
        &mut edge_targets_bytes,
        edge_targets,
        layout.edge_storage_words,
        "resident CSR queue graph edge_targets",
    )?;
    let mut edge_kind_bytes = Vec::new();
    write_u32_slice_or_zero_words(
        &mut edge_kind_bytes,
        edge_kind_mask,
        layout.edge_storage_words,
        "resident CSR queue graph edge_kind_mask",
    )?;
    let edge_offsets_handle = dispatcher.alloc_resident(edge_offsets_bytes.len())?;
    let edge_targets_handle = dispatcher.alloc_resident(edge_targets_bytes.len())?;
    let edge_kind_mask_handle = dispatcher.alloc_resident(edge_kind_bytes.len())?;
    if let Err(error) = dispatcher.upload_resident_many(&[
        (edge_offsets_handle, edge_offsets_bytes.as_slice()),
        (edge_targets_handle, edge_targets_bytes.as_slice()),
        (edge_kind_mask_handle, edge_kind_bytes.as_slice()),
    ]) {
        let _ = free_all(
            dispatcher,
            &[
                edge_offsets_handle,
                edge_targets_handle,
                edge_kind_mask_handle,
            ],
        );
        return Err(error);
    }
    Ok(ResidentCsrQueueGraph {
        node_count: layout.node_count,
        edge_count: layout.edge_count,
        words: layout.words,
        edge_offsets_handle,
        edge_targets_handle,
        edge_kind_mask_handle,
    })
}

/// Run one sparse frontier query over a resident CSR graph.
pub fn run_resident_csr_queue_query_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentCsrQueueGraph,
    scratch: &mut ResidentCsrQueueScratch,
    frontier_words: &[u32],
    queue_capacity: u32,
    allow_mask: u32,
    output: &mut Vec<u8>,
) -> Result<(), DispatchError> {
    validate_frontier_queue_query(graph.node_count, frontier_words, queue_capacity)
        .map_err(DispatchError::BadInputs)?;
    ensure_scratch(dispatcher, scratch, graph.words, queue_capacity)?;
    ensure_programs(scratch, graph, queue_capacity, allow_mask);
    scratch.frontier_bytes.clear();
    scratch
        .frontier_bytes
        .extend(frontier_words.iter().flat_map(|word| word.to_le_bytes()));
    write_zero_u32_words(
        &mut scratch.queue_len_zero,
        1,
        "resident CSR queue query queue_len",
    )?;
    let frontier_bytes = u32_word_bytes(graph.words, "resident CSR queue query frontier")?;
    write_zero_bytes(&mut scratch.frontier_out_zero, frontier_bytes);
    let handles = scratch
        .handles
        .expect("Fix: resident CSR queue scratch handles must exist after ensure_scratch.");
    let queue_handles = [handles.frontier, handles.active_queue, handles.queue_len];
    let traverse_handles = [
        handles.active_queue,
        handles.queue_len,
        graph.edge_offsets_handle,
        graph.edge_targets_handle,
        graph.edge_kind_mask_handle,
        handles.frontier_out,
    ];
    let queue_program = scratch
        .queue_program
        .as_ref()
        .expect("Fix: resident CSR queue program must exist after ensure_programs.");
    let traverse_program = scratch
        .traverse_program
        .as_ref()
        .expect("Fix: resident CSR queue traverse program must exist after ensure_programs.");
    let steps = [
        ResidentDispatchStep {
            program: queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([graph.node_count.div_ceil(256).max(1), 1, 1]),
        },
        ResidentDispatchStep {
            program: traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        },
    ];
    let read_ranges = [ResidentReadRange {
        handle_id: handles.frontier_out,
        byte_offset: 0,
        byte_len: frontier_bytes,
    }];
    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &[
            (handles.frontier, scratch.frontier_bytes.as_slice()),
            (handles.queue_len, scratch.queue_len_zero.as_slice()),
            (handles.frontier_out, scratch.frontier_out_zero.as_slice()),
        ],
        &steps,
        &read_ranges,
        &mut scratch.readbacks,
    )?;
    output.clear();
    output.extend_from_slice(&scratch.readbacks[0]);
    Ok(())
}

fn ensure_scratch(
    dispatcher: &dyn OptimizerDispatcher,
    scratch: &mut ResidentCsrQueueScratch,
    words: usize,
    queue_capacity: u32,
) -> Result<(), DispatchError> {
    let frontier_bytes = u32_word_bytes(words, "resident CSR queue scratch frontier")?;
    if matches!(
        scratch.handles,
        Some(handles)
            if handles.frontier_bytes == frontier_bytes && handles.queue_capacity == queue_capacity
    ) {
        return Ok(());
    }
    scratch.free(dispatcher)?;
    let frontier = dispatcher.alloc_resident(frontier_bytes)?;
    let active_queue = dispatcher.alloc_resident(u32_word_bytes(
        queue_capacity as usize,
        "resident CSR queue scratch active_queue",
    )?)?;
    let queue_len =
        dispatcher.alloc_resident(u32_word_bytes(1, "resident CSR queue scratch queue_len")?)?;
    let frontier_out = dispatcher.alloc_resident(frontier_bytes)?;
    scratch.handles = Some(ResidentCsrQueueScratchHandles {
        frontier,
        active_queue,
        queue_len,
        frontier_out,
        queue_capacity,
        frontier_bytes,
    });
    Ok(())
}

fn ensure_programs(
    scratch: &mut ResidentCsrQueueScratch,
    graph: &ResidentCsrQueueGraph,
    queue_capacity: u32,
    allow_mask: u32,
) {
    let shape = ResidentCsrQueueProgramShape {
        node_count: graph.node_count,
        edge_count: graph.edge_count,
        queue_capacity,
        allow_mask,
    };
    if scratch.cached_shape == Some(shape) {
        return;
    }
    scratch.queue_program = Some(frontier_to_queue(
        "frontier",
        "active_queue",
        "queue_len",
        graph.node_count,
        queue_capacity,
    ));
    scratch.traverse_program = Some(csr_queue_forward_traverse(
        "active_queue",
        "queue_len",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "frontier_out",
        graph.node_count,
        graph.edge_count,
        queue_capacity,
        allow_mask,
    ));
    scratch.cached_shape = Some(shape);
}

fn free_all(dispatcher: &dyn OptimizerDispatcher, handles: &[u64]) -> Result<(), DispatchError> {
    let mut first_error = None;
    for &handle in handles {
        if let Err(error) = dispatcher.free_resident(handle) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use vyre_foundation::ir::Program;

    #[derive(Default)]
    struct RecordingResidentDispatcher {
        next_handle: Cell<u64>,
        allocs: RefCell<Vec<usize>>,
        uploads: RefCell<Vec<Vec<u8>>>,
    }

    impl OptimizerDispatcher for RecordingResidentDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            Err(DispatchError::Rejected(
                "Fix: resident queue tests should not use non-resident dispatch.".to_string(),
            ))
        }

        fn alloc_resident(&self, byte_len: usize) -> Result<u64, DispatchError> {
            self.allocs.borrow_mut().push(byte_len);
            let handle = self.next_handle.get() + 1;
            self.next_handle.set(handle);
            Ok(handle)
        }

        fn upload_resident_many(&self, uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
            self.uploads
                .borrow_mut()
                .extend(uploads.iter().map(|(_, bytes)| bytes.to_vec()));
            Ok(())
        }

        fn free_resident(&self, _handle: u64) -> Result<(), DispatchError> {
            Ok(())
        }
    }

    #[test]
    fn zero_edge_graph_uploads_padded_resident_edge_buffers() {
        let dispatcher = RecordingResidentDispatcher::default();
        let graph = upload_resident_csr_queue_graph(&dispatcher, 3, &[0, 0, 0, 0], &[], &[])
            .expect("zero-edge resident CSR graph is valid");

        assert_eq!(graph.edge_count(), 0);
        assert_eq!(*dispatcher.allocs.borrow(), vec![16, 4, 4]);
        assert_eq!(
            *dispatcher.uploads.borrow(),
            vec![vec![0; 16], vec![0; 4], vec![0; 4]]
        );
    }

    #[test]
    fn resident_upload_uses_primitive_csr_validation() {
        let dispatcher = RecordingResidentDispatcher::default();
        let err = upload_resident_csr_queue_graph(&dispatcher, 2, &[0, 1, 1], &[5], &[1])
            .expect_err("out-of-range targets must be rejected before upload");
        assert!(
            matches!(err, DispatchError::BadInputs(message) if message.contains("outside node_count"))
        );
        assert!(dispatcher.allocs.borrow().is_empty());
        assert!(dispatcher.uploads.borrow().is_empty());
    }
}
