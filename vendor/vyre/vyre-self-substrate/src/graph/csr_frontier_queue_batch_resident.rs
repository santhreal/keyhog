//! Batched resident CSR frontier-queue execution.
//!
//! This module owns multi-query sparse traversal over one resident CSR graph:
//! each query gets resident scratch slots, all frontiers are uploaded together,
//! all queue/traverse kernels are submitted as one resident sequence, and all
//! frontier outputs are compactly read back at the end.

use vyre_foundation::ir::Program;
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse, frontier_to_queue, validate_frontier_queue_batch,
};

use crate::csr_frontier_queue_batch_memory::{
    plan_resident_csr_queue_batch_memory, ResidentCsrQueueBatchMemoryPlan,
};
use crate::csr_frontier_queue_resident::ResidentCsrQueueGraph;
use crate::dispatch_buffers::{u32_word_bytes, write_zero_bytes, write_zero_u32_words};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

/// Reusable resident scratch for batched CSR queue traversal queries.
#[derive(Debug, Default)]
pub struct ResidentCsrQueueBatchScratch {
    handles: Vec<ResidentCsrQueueBatchQueryHandles>,
    shape: Option<ResidentCsrQueueBatchShape>,
    queue_program: Option<Program>,
    traverse_program: Option<Program>,
    frontier_payloads: Vec<Vec<u8>>,
    queue_len_zero: Vec<u8>,
    frontier_out_zero: Vec<u8>,
    readbacks: Vec<Vec<u8>>,
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
        let mut first_error = None;
        for handles in self.handles.drain(..) {
            if let Err(error) = free_all(
                dispatcher,
                &[
                    handles.frontier,
                    handles.active_queue,
                    handles.queue_len,
                    handles.frontier_out,
                ],
            ) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        self.shape = None;
        self.queue_program = None;
        self.traverse_program = None;
        self.frontier_payloads.clear();
        self.queue_len_zero.clear();
        self.frontier_out_zero.clear();
        self.readbacks.clear();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
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

/// Run many sparse frontier queries over one resident CSR graph.
pub fn run_resident_csr_queue_batch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentCsrQueueGraph,
    scratch: &mut ResidentCsrQueueBatchScratch,
    frontiers: &[&[u32]],
    queue_capacity: u32,
    allow_mask: u32,
    outputs: &mut Vec<Vec<u8>>,
) -> Result<(), DispatchError> {
    validate_frontier_queue_batch(graph.node_count(), frontiers, queue_capacity)
        .map_err(DispatchError::BadInputs)?;
    ensure_batch_scratch(
        dispatcher,
        graph,
        scratch,
        frontiers.len(),
        queue_capacity,
        allow_mask,
    )?;

    let frontier_bytes = u32_word_bytes(graph.words(), "resident CSR queue batch frontier")?;
    write_zero_u32_words(
        &mut scratch.queue_len_zero,
        1,
        "resident CSR queue batch queue_len",
    )?;
    write_zero_bytes(&mut scratch.frontier_out_zero, frontier_bytes);
    if scratch.frontier_payloads.len() < frontiers.len() {
        scratch
            .frontier_payloads
            .resize_with(frontiers.len(), Vec::new);
    }
    scratch.frontier_payloads.truncate(frontiers.len());
    for (payload, frontier) in scratch.frontier_payloads.iter_mut().zip(frontiers) {
        payload.clear();
        payload.extend(frontier.iter().flat_map(|word| word.to_le_bytes()));
    }
    let mut upload_refs = Vec::with_capacity(frontiers.len() * 3);
    for query_index in 0..frontiers.len() {
        let handles = scratch.handles[query_index];
        upload_refs.push((
            handles.frontier,
            scratch.frontier_payloads[query_index].as_slice(),
        ));
        upload_refs.push((handles.queue_len, scratch.queue_len_zero.as_slice()));
        upload_refs.push((handles.frontier_out, scratch.frontier_out_zero.as_slice()));
    }

    let queue_program = scratch
        .queue_program
        .as_ref()
        .expect("Fix: batch CSR queue program must exist after ensure_batch_scratch.");
    let traverse_program = scratch
        .traverse_program
        .as_ref()
        .expect("Fix: batch CSR traverse program must exist after ensure_batch_scratch.");
    let mut queue_handle_sets = Vec::with_capacity(frontiers.len());
    let mut traverse_handle_sets = Vec::with_capacity(frontiers.len());
    for handles in &scratch.handles {
        queue_handle_sets.push([handles.frontier, handles.active_queue, handles.queue_len]);
        traverse_handle_sets.push([
            handles.active_queue,
            handles.queue_len,
            graph.edge_offsets_handle(),
            graph.edge_targets_handle(),
            graph.edge_kind_mask_handle(),
            handles.frontier_out,
        ]);
    }

    let mut steps = Vec::with_capacity(frontiers.len() * 2);
    for query_index in 0..frontiers.len() {
        steps.push(ResidentDispatchStep {
            program: queue_program,
            handle_ids: &queue_handle_sets[query_index],
            grid_override: Some([graph.node_count().div_ceil(256).max(1), 1, 1]),
        });
        steps.push(ResidentDispatchStep {
            program: traverse_program,
            handle_ids: &traverse_handle_sets[query_index],
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        });
    }

    let read_ranges: Vec<ResidentReadRange> = scratch
        .handles
        .iter()
        .take(frontiers.len())
        .map(|handles| ResidentReadRange {
            handle_id: handles.frontier_out,
            byte_offset: 0,
            byte_len: frontier_bytes,
        })
        .collect();

    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &upload_refs,
        &steps,
        &read_ranges,
        &mut scratch.readbacks,
    )?;

    if outputs.len() < frontiers.len() {
        outputs.resize_with(frontiers.len(), Vec::new);
    }
    outputs.truncate(frontiers.len());
    for (output, readback) in outputs.iter_mut().zip(&scratch.readbacks) {
        output.clear();
        output.extend_from_slice(readback);
    }
    Ok(())
}

/// Run many sparse frontier queries, sharded by resident scratch budget.
pub fn run_resident_csr_queue_batch_budgeted_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentCsrQueueGraph,
    scratch: &mut ResidentCsrQueueBatchScratch,
    frontiers: &[&[u32]],
    queue_capacity: u32,
    allow_mask: u32,
    max_scratch_bytes: usize,
    outputs: &mut Vec<Vec<u8>>,
) -> Result<ResidentCsrQueueBatchMemoryPlan, DispatchError> {
    let plan = plan_resident_csr_queue_batch_memory(
        frontiers.len(),
        graph.words(),
        queue_capacity,
        max_scratch_bytes,
    )
    .map_err(|error| DispatchError::BadInputs(error.to_string()))?;
    if outputs.len() < frontiers.len() {
        outputs.resize_with(frontiers.len(), Vec::new);
    }
    outputs.truncate(frontiers.len());

    let mut chunk_outputs = Vec::new();
    for (chunk_index, frontier_chunk) in frontiers.chunks(plan.max_queries_per_dispatch).enumerate()
    {
        run_resident_csr_queue_batch_into(
            dispatcher,
            graph,
            scratch,
            frontier_chunk,
            queue_capacity,
            allow_mask,
            &mut chunk_outputs,
        )?;
        let offset = chunk_index * plan.max_queries_per_dispatch;
        for (target, source) in outputs[offset..offset + frontier_chunk.len()]
            .iter_mut()
            .zip(&chunk_outputs)
        {
            target.clear();
            target.extend_from_slice(source);
        }
    }

    Ok(plan)
}

fn ensure_batch_scratch(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentCsrQueueGraph,
    scratch: &mut ResidentCsrQueueBatchScratch,
    batch_len: usize,
    queue_capacity: u32,
    allow_mask: u32,
) -> Result<(), DispatchError> {
    let frontier_bytes =
        u32_word_bytes(graph.words(), "resident CSR queue batch scratch frontier")?;
    let queue_bytes = u32_word_bytes(
        queue_capacity as usize,
        "resident CSR queue batch scratch active_queue",
    )?;
    let queue_len_bytes = u32_word_bytes(1, "resident CSR queue batch scratch queue_len")?;
    let shape = ResidentCsrQueueBatchShape {
        batch_len,
        frontier_bytes,
        queue_capacity,
        allow_mask,
        node_count: graph.node_count(),
        edge_count: graph.edge_count(),
    };
    if matches!(
        scratch.shape,
        Some(existing)
            if existing.batch_len >= batch_len
                && existing.frontier_bytes == frontier_bytes
                && existing.queue_capacity == queue_capacity
                && existing.allow_mask == allow_mask
                && existing.node_count == graph.node_count()
                && existing.edge_count == graph.edge_count()
    ) {
        return Ok(());
    }
    if scratch.shape == Some(shape) {
        return Ok(());
    }

    scratch.free(dispatcher)?;
    for _ in 0..batch_len {
        scratch.handles.push(ResidentCsrQueueBatchQueryHandles {
            frontier: dispatcher.alloc_resident(frontier_bytes)?,
            active_queue: dispatcher.alloc_resident(queue_bytes)?,
            queue_len: dispatcher.alloc_resident(queue_len_bytes)?,
            frontier_out: dispatcher.alloc_resident(frontier_bytes)?,
        });
    }
    scratch.queue_program = Some(frontier_to_queue(
        "frontier",
        "active_queue",
        "queue_len",
        graph.node_count(),
        queue_capacity,
    ));
    scratch.traverse_program = Some(csr_queue_forward_traverse(
        "active_queue",
        "queue_len",
        "edge_offsets",
        "edge_targets",
        "edge_kind_mask",
        "frontier_out",
        graph.node_count(),
        graph.edge_count(),
        queue_capacity,
        allow_mask,
    ));
    scratch.shape = Some(shape);
    Ok(())
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
