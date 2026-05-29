use super::state::AdaptiveTraversalResidentScratch;
use super::{
    AdaptiveTraversalMode, ResidentAdaptiveFourRussiansDenseGraph, ResidentAdaptiveTraversalGraph,
};

use crate::dispatch_buffers::write_u32_slice_le_bytes;
use crate::graph::dispatch_bridge::{
    alloc_resident_buffers, resident_sequence_single_u32_output_into,
};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};
use vyre_primitives::bitset::zero::bitset_zero;
use vyre_primitives::graph::adaptive_traverse::{
    adaptive_four_russians_dense_step as primitive_adaptive_four_russians_dense_step,
    adaptive_sparse_dense_step as primitive_adaptive_sparse_dense_step,
    plan_adaptive_resident_auto_step, plan_adaptive_resident_frontier_step,
    plan_adaptive_resident_sparse_queue_step, AdaptiveResidentFrontierPlan,
    AdaptiveTraversalPlanCacheKey,
};
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse as primitive_csr_queue_forward_traverse, frontier_queue_len_init,
    frontier_to_queue as primitive_frontier_to_queue,
};
use vyre_primitives::reduce::count::reduce_count;

/// Run one adaptive sparse/dense traversal step over resident graph buffers.
///
/// # Errors
///
/// Propagates resident dispatch failures and malformed frontier/readback shapes.
#[allow(clippy::too_many_arguments)]
pub fn adaptive_traverse_resident_graph_step_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentAdaptiveTraversalGraph,
    frontier_in: &[u32],
    allow_mask: u32,
    dense_threshold_pct: u32,
    scratch: &mut AdaptiveTraversalResidentScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let resident_plan = plan_adaptive_resident_frontier_step(graph.node_count, frontier_in)
        .map_err(DispatchError::BadInputs)?;
    if !resident_plan.work.has_active_bits {
        write_zero_frontier_result(resident_plan.work.layout.words, frontier_out);
        return Ok(());
    }
    let handles = ensure_frontier_handles(dispatcher, scratch, &resident_plan)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_in);

    let words_u32 = resident_plan.work.layout.words_u32;
    let device_features = dispatcher.device_feature_cache_key();
    let popcount_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::popcount(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            device_features,
        ),
        || reduce_count("frontier_in", "frontier_popcount", words_u32),
    );
    let traverse_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::sparse_dense(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            allow_mask,
            dense_threshold_pct,
            device_features,
        ),
        || {
            primitive_adaptive_sparse_dense_step(
                "frontier_in",
                "frontier_out",
                "frontier_popcount",
                "edge_offsets",
                "edge_targets",
                "edge_kind_mask",
                "adj_rows_dense",
                graph.node_count,
                graph.edge_count,
                allow_mask,
                dense_threshold_pct,
            )
        },
    );
    let clear_frontier_out_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::clear_frontier_out(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            device_features,
        ),
        || bitset_zero("frontier_out", words_u32),
    );
    let graph_handles = graph.handles;
    let clear_handles = [handles[1]];
    let count_handles = [handles[0], handles[2]];
    let traverse_handles = [
        handles[0],
        handles[1],
        handles[2],
        graph_handles[0],
        graph_handles[1],
        graph_handles[2],
        graph_handles[3],
    ];
    let uploads = [(handles[0], scratch.frontier_in_bytes.as_slice())];
    let steps = [
        ResidentDispatchStep {
            program: &clear_frontier_out_program,
            handle_ids: &clear_handles,
            grid_override: Some(resident_plan.frontier_word_grid),
        },
        ResidentDispatchStep {
            program: &popcount_program,
            handle_ids: &count_handles,
            grid_override: Some([1, 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some(resident_plan.node_grid),
        },
    ];
    resident_sequence_single_u32_output_into(
        dispatcher,
        &uploads,
        &steps,
        ResidentReadRange {
            handle_id: handles[1],
            byte_offset: 0,
            byte_len: resident_plan.frontier_bytes,
        },
        &mut scratch.readbacks,
        resident_plan.work.layout.words,
        "adaptive_traverse_resident_graph_step frontier_out",
        frontier_out,
    )
}

/// Run one Four-Russians dense traversal step over a resident dense LUT.
///
/// # Errors
///
/// Propagates resident dispatch failures and malformed frontier/readback shapes.
pub fn adaptive_traverse_resident_graph_four_russians_dense_step_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentAdaptiveFourRussiansDenseGraph,
    frontier_in: &[u32],
    scratch: &mut AdaptiveTraversalResidentScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let resident_plan = plan_adaptive_resident_frontier_step(graph.node_count, frontier_in)
        .map_err(DispatchError::BadInputs)?;
    if !resident_plan.work.has_active_bits {
        write_zero_frontier_result(resident_plan.work.layout.words, frontier_out);
        return Ok(());
    }
    let handles = ensure_frontier_handles(dispatcher, scratch, &resident_plan)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_in);

    let words_u32 = resident_plan.work.layout.words_u32;
    let device_features = dispatcher.device_feature_cache_key();
    let dense_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::four_russians_dense(
            graph.layout_hash,
            graph.node_count,
            words_u32,
            device_features,
        ),
        || {
            primitive_adaptive_four_russians_dense_step(
                "frontier_in",
                "four_russians_tile_lut",
                "frontier_out",
                graph.node_count,
            )
        },
    );
    let dense_handles = [handles[0], graph.lut_handle, handles[1]];
    let uploads = [(handles[0], scratch.frontier_in_bytes.as_slice())];
    let steps = [ResidentDispatchStep {
        program: &dense_program,
        handle_ids: &dense_handles,
        grid_override: Some(resident_plan.frontier_word_grid),
    }];
    resident_sequence_single_u32_output_into(
        dispatcher,
        &uploads,
        &steps,
        ResidentReadRange {
            handle_id: handles[1],
            byte_offset: 0,
            byte_len: resident_plan.frontier_bytes,
        },
        &mut scratch.readbacks,
        resident_plan.work.layout.words,
        "adaptive_traverse_resident_graph_four_russians_dense_step frontier_out",
        frontier_out,
    )
}

/// Run one queue-driven sparse traversal step over resident graph buffers.
///
/// The active queue is built and consumed on the GPU. The host uploads the
/// input frontier and reads only `frontier_out`; active source ids and queue
/// length remain device-resident.
///
/// # Errors
///
/// Propagates resident dispatch failures and malformed frontier/readback shapes.
#[allow(clippy::too_many_arguments)]
pub fn adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentAdaptiveTraversalGraph,
    frontier_in: &[u32],
    allow_mask: u32,
    scratch: &mut AdaptiveTraversalResidentScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let sparse_plan = plan_adaptive_resident_sparse_queue_step(graph.node_count, frontier_in)
        .map_err(DispatchError::BadInputs)?;
    if !sparse_plan.frontier.work.has_active_bits {
        write_zero_frontier_result(sparse_plan.frontier.work.layout.words, frontier_out);
        return Ok(());
    }
    let handles = ensure_frontier_handles(dispatcher, scratch, &sparse_plan.frontier)?;
    let queue_handle = ensure_queue_handle(dispatcher, scratch, sparse_plan.queue_bytes)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_in);

    let words_u32 = sparse_plan.frontier.work.layout.words_u32;
    let queue_capacity = sparse_plan.queue_capacity;
    let device_features = dispatcher.device_feature_cache_key();
    let queue_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::frontier_to_queue(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            queue_capacity,
            device_features,
        ),
        || {
            primitive_frontier_to_queue(
                "frontier_in",
                "active_queue",
                "queue_len",
                graph.node_count,
                queue_capacity,
            )
        },
    );
    let traverse_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::queue_forward(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            queue_capacity,
            allow_mask,
            device_features,
        ),
        || {
            primitive_csr_queue_forward_traverse(
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
            )
        },
    );
    let queue_len_init_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::queue_len_init(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            queue_capacity,
            device_features,
        ),
        || frontier_queue_len_init("queue_len"),
    );
    let clear_frontier_out_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanCacheKey::clear_frontier_out(
            graph.layout_hash,
            graph.node_count,
            graph.edge_count,
            words_u32,
            device_features,
        ),
        || bitset_zero("frontier_out", words_u32),
    );
    let graph_handles = graph.handles;
    let queue_len_init_handles = [handles[2]];
    let clear_handles = [handles[1]];
    let queue_handles = [handles[0], queue_handle, handles[2]];
    let traverse_handles = [
        queue_handle,
        handles[2],
        graph_handles[0],
        graph_handles[1],
        graph_handles[2],
        handles[1],
    ];
    let uploads = [(handles[0], scratch.frontier_in_bytes.as_slice())];
    let steps = [
        ResidentDispatchStep {
            program: &queue_len_init_program,
            handle_ids: &queue_len_init_handles,
            grid_override: Some([1, 1, 1]),
        },
        ResidentDispatchStep {
            program: &clear_frontier_out_program,
            handle_ids: &clear_handles,
            grid_override: Some(sparse_plan.frontier.frontier_word_grid),
        },
        ResidentDispatchStep {
            program: &queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([1, 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some(sparse_plan.queue_grid),
        },
    ];
    resident_sequence_single_u32_output_into(
        dispatcher,
        &uploads,
        &steps,
        ResidentReadRange {
            handle_id: handles[1],
            byte_offset: 0,
            byte_len: sparse_plan.frontier.frontier_bytes,
        },
        &mut scratch.readbacks,
        sparse_plan.frontier.work.layout.words,
        "adaptive_traverse_resident_graph_sparse_queue_step frontier_out",
        frontier_out,
    )
}

/// Run one adaptive traversal step using the runtime mode selector.
///
/// # Errors
///
/// Propagates resident dispatch failures and malformed frontier/readback shapes.
#[allow(clippy::too_many_arguments)]
pub fn adaptive_traverse_resident_graph_auto_step_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentAdaptiveTraversalGraph,
    frontier_in: &[u32],
    allow_mask: u32,
    dense_threshold_pct: u32,
    scratch: &mut AdaptiveTraversalResidentScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<AdaptiveTraversalMode, DispatchError> {
    let auto_plan = plan_adaptive_resident_auto_step(
        graph.node_count,
        graph.edge_count,
        frontier_in,
        dense_threshold_pct,
    )
    .map_err(DispatchError::BadInputs)?;
    if !auto_plan.frontier.work.has_active_bits {
        write_zero_frontier_result(auto_plan.frontier.work.layout.words, frontier_out);
        return Ok(AdaptiveTraversalMode::SparseQueue);
    }
    let mode = auto_plan.mode;
    match mode {
        AdaptiveTraversalMode::SparseQueue => {
            adaptive_traverse_resident_graph_sparse_queue_step_with_scratch_into(
                dispatcher,
                graph,
                frontier_in,
                allow_mask,
                scratch,
                frontier_out,
            )?;
        }
        AdaptiveTraversalMode::SparseDense => {
            adaptive_traverse_resident_graph_step_with_scratch_into(
                dispatcher,
                graph,
                frontier_in,
                allow_mask,
                dense_threshold_pct,
                scratch,
                frontier_out,
            )?;
        }
    }
    Ok(mode)
}

fn write_zero_frontier_result(words: usize, frontier_out: &mut Vec<u32>) {
    frontier_out.clear();
    frontier_out.resize(words, 0);
}

fn ensure_frontier_handles(
    dispatcher: &dyn OptimizerDispatcher,
    scratch: &mut AdaptiveTraversalResidentScratch,
    plan: &AdaptiveResidentFrontierPlan,
) -> Result<[u64; 3], DispatchError> {
    let frontier_bytes = plan.frontier_bytes;
    if scratch.frontier_bytes == frontier_bytes {
        if let Some(handles) = scratch.handles {
            return Ok(handles);
        }
    }
    scratch.free(dispatcher)?;
    let handles = alloc_resident_buffers(
        dispatcher,
        [frontier_bytes, frontier_bytes, plan.popcount_bytes],
        "adaptive traversal frontier scratch",
    )?;
    scratch.handles = Some(handles);
    scratch.frontier_bytes = frontier_bytes;
    Ok(handles)
}

fn ensure_queue_handle(
    dispatcher: &dyn OptimizerDispatcher,
    scratch: &mut AdaptiveTraversalResidentScratch,
    queue_bytes: usize,
) -> Result<u64, DispatchError> {
    if scratch.queue_bytes == queue_bytes {
        if let Some(handle) = scratch.queue_handle {
            return Ok(handle);
        }
    }
    if let Some(handle) = scratch.queue_handle.take() {
        dispatcher.free_resident(handle)?;
    }
    let [handle] = alloc_resident_buffers(
        dispatcher,
        [queue_bytes],
        "adaptive traversal queue scratch",
    )?;
    scratch.queue_handle = Some(handle);
    scratch.queue_bytes = queue_bytes;
    Ok(handle)
}
