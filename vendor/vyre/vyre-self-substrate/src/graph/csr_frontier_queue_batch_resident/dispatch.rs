use super::{
    ResidentCsrQueueBatchQueryHandles, ResidentCsrQueueBatchScratch, ResidentCsrQueueBatchShape,
};
use vyre_primitives::bitset::zero::bitset_zero;
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse, frontier_queue_len_init, frontier_to_queue,
    validate_frontier_queue_batch,
};

use crate::csr_frontier_queue_batch_memory::{
    plan_resident_csr_queue_batch_memory, ResidentCsrQueueBatchMemoryPlan,
};
use crate::csr_frontier_queue_resident::ResidentCsrQueueGraph;
use crate::dispatch_buffers::u32_word_bytes;
use crate::graph::dispatch_bridge::alloc_resident_buffers;
use crate::hardware::scratch::reserve_vec as reserve_graph_vec;
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

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
    if scratch.frontier_payloads.len() < frontiers.len() {
        scratch
            .frontier_payloads
            .resize_with(frontiers.len(), Vec::new);
    }
    scratch.frontier_payloads.truncate(frontiers.len());
    for (payload, frontier) in scratch.frontier_payloads.iter_mut().zip(frontiers) {
        payload.clear();
        vyre_primitives::wire::append_u32_slice_le_bytes(frontier, payload);
    }
    prepare_batch_sequence_tables(graph, scratch, frontiers.len(), frontier_bytes)?;

    let mut upload_refs = Vec::new();
    reserve_graph_vec(
        &mut upload_refs,
        frontiers.len(),
        "resident CSR queue batch uploads",
    )?;
    for query_index in 0..frontiers.len() {
        let handles = scratch.handles[query_index];
        upload_refs.push((
            handles.frontier,
            scratch.frontier_payloads[query_index].as_slice(),
        ));
    }

    let queue_len_init_program = scratch.queue_len_init_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "batch CSR queue length init program is missing after ensure_batch_scratch. Fix: rebuild batch scratch before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let clear_frontier_out_program = scratch.clear_frontier_out_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "batch CSR queue output clear program is missing after ensure_batch_scratch. Fix: rebuild batch scratch before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let queue_program = scratch.queue_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "batch CSR queue program is missing after ensure_batch_scratch. Fix: rebuild batch scratch before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let traverse_program = scratch.traverse_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "batch CSR traverse program is missing after ensure_batch_scratch. Fix: rebuild batch scratch before resident CSR traverse dispatch.".to_string(),
        )
    })?;

    let mut steps = Vec::new();
    reserve_graph_vec(
        &mut steps,
        frontiers
            .len()
            .checked_mul(4)
            .ok_or_else(|| DispatchError::BackendError(
                "Fix: resident CSR queue batch step count overflowed while reserving dispatch sequence slots."
                    .to_string(),
            ))?,
        "resident CSR queue batch steps",
    )?;
    for query_index in 0..frontiers.len() {
        steps.push(ResidentDispatchStep {
            program: queue_len_init_program,
            handle_ids: &scratch.queue_len_init_handle_sets[query_index],
            grid_override: Some([1, 1, 1]),
        });
        steps.push(ResidentDispatchStep {
            program: clear_frontier_out_program,
            handle_ids: &scratch.clear_handle_sets[query_index],
            grid_override: Some([(graph.words() as u32).div_ceil(256).max(1), 1, 1]),
        });
        steps.push(ResidentDispatchStep {
            program: queue_program,
            handle_ids: &scratch.queue_handle_sets[query_index],
            grid_override: Some([1, 1, 1]),
        });
        steps.push(ResidentDispatchStep {
            program: traverse_program,
            handle_ids: &scratch.traverse_handle_sets[query_index],
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        });
    }

    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &upload_refs,
        &steps,
        &scratch.read_ranges,
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

fn prepare_batch_sequence_tables(
    graph: &ResidentCsrQueueGraph,
    scratch: &mut ResidentCsrQueueBatchScratch,
    batch_len: usize,
    frontier_bytes: usize,
) -> Result<(), DispatchError> {
    scratch.queue_len_init_handle_sets.clear();
    scratch.clear_handle_sets.clear();
    scratch.queue_handle_sets.clear();
    scratch.traverse_handle_sets.clear();
    scratch.read_ranges.clear();

    reserve_graph_vec(
        &mut scratch.queue_len_init_handle_sets,
        batch_len,
        "resident CSR queue batch queue-len init handles",
    )?;
    reserve_graph_vec(
        &mut scratch.clear_handle_sets,
        batch_len,
        "resident CSR queue batch output clear handles",
    )?;
    reserve_graph_vec(
        &mut scratch.queue_handle_sets,
        batch_len,
        "resident CSR queue batch queue handles",
    )?;
    reserve_graph_vec(
        &mut scratch.traverse_handle_sets,
        batch_len,
        "resident CSR queue batch traverse handles",
    )?;
    reserve_graph_vec(
        &mut scratch.read_ranges,
        batch_len,
        "resident CSR queue batch read ranges",
    )?;

    for handles in scratch.handles.iter().take(batch_len) {
        scratch.queue_len_init_handle_sets.push([handles.queue_len]);
        scratch.clear_handle_sets.push([handles.frontier_out]);
        scratch
            .queue_handle_sets
            .push([handles.frontier, handles.active_queue, handles.queue_len]);
        scratch.traverse_handle_sets.push([
            handles.active_queue,
            handles.queue_len,
            graph.edge_offsets_handle(),
            graph.edge_targets_handle(),
            graph.edge_kind_mask_handle(),
            handles.frontier_out,
        ]);
        scratch.read_ranges.push(ResidentReadRange {
            handle_id: handles.frontier_out,
            byte_offset: 0,
            byte_len: frontier_bytes,
        });
    }

    Ok(())
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
    reserve_graph_vec(
        &mut scratch.handles,
        batch_len,
        "resident CSR queue batch scratch handles",
    )?;
    for _ in 0..batch_len {
        let [frontier, active_queue, queue_len, frontier_out] = match alloc_resident_buffers(
            dispatcher,
            [frontier_bytes, queue_bytes, queue_len_bytes, frontier_bytes],
            "resident CSR queue batch scratch query",
        ) {
            Ok(handles) => handles,
            Err(error) => {
                if let Err(free_error) = scratch.free(dispatcher) {
                    return Err(DispatchError::BackendError(format!(
                        "Fix: resident CSR queue batch scratch allocation failed and cleanup also failed: allocation={error}; cleanup={free_error}."
                    )));
                }
                return Err(error);
            }
        };
        scratch.handles.push(ResidentCsrQueueBatchQueryHandles {
            frontier,
            active_queue,
            queue_len,
            frontier_out,
        });
    }
    scratch.queue_len_init_program = Some(frontier_queue_len_init("queue_len"));
    scratch.clear_frontier_out_program = Some(bitset_zero("frontier_out", graph.words() as u32));
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
