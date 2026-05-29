use super::{
    ResidentCsrQueueGraph, ResidentCsrQueueProgramShape, ResidentCsrQueueScratch,
    ResidentCsrQueueScratchHandles,
};
use vyre_primitives::bitset::zero::bitset_zero;
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse, frontier_queue_len_init, frontier_to_queue,
    validate_frontier_queue_query,
};

use crate::dispatch_buffers::u32_word_bytes;
use crate::graph::dispatch_bridge::alloc_resident_buffers;
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

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
    vyre_primitives::wire::append_u32_slice_le_bytes(frontier_words, &mut scratch.frontier_bytes);
    let frontier_bytes = u32_word_bytes(graph.words, "resident CSR queue query frontier")?;
    let handles = scratch.handles.ok_or_else(|| {
        DispatchError::BackendError(
            "resident CSR queue scratch handles are missing after ensure_scratch. Fix: rebuild scratch before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let queue_len_init_handles = [handles.queue_len];
    let clear_handles = [handles.frontier_out];
    let queue_handles = [handles.frontier, handles.active_queue, handles.queue_len];
    let traverse_handles = [
        handles.active_queue,
        handles.queue_len,
        graph.edge_offsets_handle,
        graph.edge_targets_handle,
        graph.edge_kind_mask_handle,
        handles.frontier_out,
    ];
    let queue_program = scratch.queue_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "resident CSR queue program is missing after ensure_programs. Fix: rebuild programs before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let queue_len_init_program = scratch.queue_len_init_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "resident CSR queue length init program is missing after ensure_programs. Fix: rebuild programs before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let clear_frontier_out_program = scratch.clear_frontier_out_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "resident CSR queue output clear program is missing after ensure_programs. Fix: rebuild programs before resident CSR queue dispatch.".to_string(),
        )
    })?;
    let traverse_program = scratch.traverse_program.as_ref().ok_or_else(|| {
        DispatchError::BackendError(
            "resident CSR queue traverse program is missing after ensure_programs. Fix: rebuild programs before resident CSR traverse dispatch.".to_string(),
        )
    })?;
    let steps = [
        ResidentDispatchStep {
            program: queue_len_init_program,
            handle_ids: &queue_len_init_handles,
            grid_override: Some([1, 1, 1]),
        },
        ResidentDispatchStep {
            program: clear_frontier_out_program,
            handle_ids: &clear_handles,
            grid_override: Some([(graph.words as u32).div_ceil(256).max(1), 1, 1]),
        },
        ResidentDispatchStep {
            program: queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([1, 1, 1]),
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
        &[(handles.frontier, scratch.frontier_bytes.as_slice())],
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
    let [frontier, active_queue, queue_len, frontier_out] = alloc_resident_buffers(
        dispatcher,
        [
            frontier_bytes,
            u32_word_bytes(
                queue_capacity as usize,
                "resident CSR queue scratch active_queue",
            )?,
            u32_word_bytes(1, "resident CSR queue scratch queue_len")?,
            frontier_bytes,
        ],
        "resident CSR queue scratch",
    )?;
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
    scratch.queue_len_init_program = Some(frontier_queue_len_init("queue_len"));
    scratch.clear_frontier_out_program = Some(bitset_zero("frontier_out", graph.words as u32));
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
