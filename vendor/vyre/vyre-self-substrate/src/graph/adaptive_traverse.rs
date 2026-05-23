//! Resident adaptive sparse/dense graph traversal.
//!
//! This module wires `reduce_count` and
//! `graph::adaptive_traverse::adaptive_sparse_dense_step` into one resident
//! CUDA-ready sequence. The frontier popcount is produced into a resident
//! one-word buffer and consumed by the traversal kernel without a host
//! selector readback.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use crate::dispatch_buffers::{
    decode_u32_output_exact, u32_word_bytes, write_u32_slice_le_bytes,
    write_u32_slice_or_zero_words, write_zero_bytes, write_zero_u32_words,
};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};
#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::adaptive_traverse::cpu_sparse_dense_step as reference_adaptive_sparse_dense_step;
use vyre_primitives::graph::adaptive_traverse::{
    adaptive_sparse_dense_step as primitive_adaptive_sparse_dense_step, validate_adaptive_frontier,
    validate_adaptive_traversal_layout,
};
pub use vyre_primitives::graph::adaptive_traverse::{
    select_adaptive_traversal_mode, AdaptiveTraversalMode,
};
use vyre_primitives::graph::csr_frontier_queue::{
    csr_queue_forward_traverse as primitive_csr_queue_forward_traverse,
    frontier_to_queue as primitive_frontier_to_queue,
};
use vyre_primitives::reduce::count::reduce_count;

/// Device-resident graph layouts for adaptive sparse/dense traversal.
#[derive(Debug, Clone)]
pub struct ResidentAdaptiveTraversalGraph {
    node_count: u32,
    edge_count: u32,
    words: usize,
    layout_hash: u64,
    handles: [u64; 4],
}

impl ResidentAdaptiveTraversalGraph {
    /// Number of graph nodes.
    #[must_use]
    pub fn node_count(&self) -> u32 {
        self.node_count
    }

    /// Number of logical CSR edges.
    #[must_use]
    pub fn edge_count(&self) -> u32 {
        self.edge_count
    }

    /// Number of u32 words per frontier bitset.
    #[must_use]
    pub fn words(&self) -> usize {
        self.words
    }

    /// Stable in-session hash of CSR and dense graph layouts.
    #[must_use]
    pub fn layout_hash(&self) -> u64 {
        self.layout_hash
    }

    /// Resident handles in adaptive traversal order:
    /// edge_offsets, edge_targets, edge_kind_mask, adj_rows_dense.
    #[must_use]
    pub fn handles(&self) -> [u64; 4] {
        self.handles
    }

    /// Free graph-resident buffers.
    ///
    /// # Errors
    ///
    /// Returns the first backend free failure after attempting all handles.
    pub fn free(self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        let mut first_err = None;
        for handle in self.handles {
            if let Err(err) = dispatcher.free_resident(handle) {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

/// Reusable resident frontier/count scratch for adaptive traversal.
#[derive(Debug, Default)]
pub struct AdaptiveTraversalResidentScratch {
    handles: Option<[u64; 3]>,
    queue_handle: Option<u64>,
    frontier_bytes: usize,
    queue_bytes: usize,
    frontier_in_bytes: Vec<u8>,
    frontier_out_zero_bytes: Vec<u8>,
    popcount_zero_bytes: Vec<u8>,
    queue_zero_bytes: Vec<u8>,
    readbacks: Vec<Vec<u8>>,
    plan_cache: AdaptiveTraversalPlanCache,
}

impl AdaptiveTraversalResidentScratch {
    /// Snapshot plan-cache counters for repeated adaptive traversal tests.
    #[must_use]
    pub fn plan_cache_snapshot(&self) -> AdaptiveTraversalPlanCacheSnapshot {
        self.plan_cache.snapshot()
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
                return dispatcher.free_resident(queue_handle);
            }
            return Ok(());
        };
        self.frontier_bytes = 0;
        let mut first_err = None;
        for handle in handles {
            if let Err(err) = dispatcher.free_resident(handle) {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        if let Some(queue_handle) = self.queue_handle.take() {
            self.queue_bytes = 0;
            if let Err(err) = dispatcher.free_resident(queue_handle) {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum AdaptiveTraversalPlanKind {
    Popcount,
    SparseDense,
    FrontierToQueue,
    QueueForward,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct AdaptiveTraversalPlanKey {
    layout_hash: u64,
    node_count: u32,
    edge_count: u32,
    words: u32,
    queue_capacity: u32,
    allow_mask: u32,
    dense_threshold_pct: u32,
    device_features: u64,
    kind: AdaptiveTraversalPlanKind,
}

#[derive(Debug, Default)]
struct AdaptiveTraversalPlanCache {
    entries: HashMap<AdaptiveTraversalPlanKey, vyre_foundation::ir::Program>,
    hits: u64,
    misses: u64,
}

impl AdaptiveTraversalPlanCache {
    fn get_or_build(
        &mut self,
        key: AdaptiveTraversalPlanKey,
        build: impl FnOnce() -> vyre_foundation::ir::Program,
    ) -> vyre_foundation::ir::Program {
        if let Some(program) = self.entries.get(&key) {
            self.hits = self.hits.saturating_add(1);
            return program.clone();
        }
        self.misses = self.misses.saturating_add(1);
        let program = build();
        let cached = program.clone();
        self.entries.insert(key, cached);
        program
    }

    fn snapshot(&self) -> AdaptiveTraversalPlanCacheSnapshot {
        AdaptiveTraversalPlanCacheSnapshot {
            entries: self.entries.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }
}

/// CPU reference for one adaptive sparse/dense graph step.
#[must_use]
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn adaptive_traverse_step(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    adj_rows_dense: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    dense_threshold_pct: u32,
) -> Vec<u32> {
    let frontier_popcount = frontier_in
        .iter()
        .fold(0u32, |acc, word| acc.saturating_add(word.count_ones()));
    reference_adaptive_sparse_dense_step(
        frontier_in,
        frontier_popcount,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        adj_rows_dense,
        node_count,
        allow_mask,
        dense_threshold_pct,
    )
}

/// Upload CSR plus dense reverse-adjacency rows once into resident buffers.
///
/// # Errors
///
/// Rejects malformed graph layouts or dispatchers without resident support.
pub fn upload_resident_adaptive_traversal_graph(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    adj_rows_dense: &[u32],
) -> Result<ResidentAdaptiveTraversalGraph, DispatchError> {
    let layout = validate_adaptive_traversal_layout(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        adj_rows_dense,
    )
    .map_err(DispatchError::BadInputs)?;

    let mut offset_bytes = Vec::new();
    let mut target_bytes = Vec::new();
    let mut mask_bytes = Vec::new();
    let mut dense_bytes = Vec::new();
    write_u32_slice_le_bytes(&mut offset_bytes, edge_offsets);
    write_u32_slice_or_zero_words(
        &mut target_bytes,
        edge_targets,
        layout.edge_storage_words,
        "resident adaptive traversal edge_targets",
    )?;
    write_u32_slice_or_zero_words(
        &mut mask_bytes,
        edge_kind_mask,
        layout.edge_storage_words,
        "resident adaptive traversal edge_kind_mask",
    )?;
    write_u32_slice_le_bytes(&mut dense_bytes, adj_rows_dense);

    let payloads = [
        offset_bytes.as_slice(),
        target_bytes.as_slice(),
        mask_bytes.as_slice(),
        dense_bytes.as_slice(),
    ];
    let handles = [
        dispatcher.alloc_resident(payloads[0].len())?,
        dispatcher.alloc_resident(payloads[1].len())?,
        dispatcher.alloc_resident(payloads[2].len())?,
        dispatcher.alloc_resident(payloads[3].len())?,
    ];
    let uploads = [
        (handles[0], payloads[0]),
        (handles[1], payloads[1]),
        (handles[2], payloads[2]),
        (handles[3], payloads[3]),
    ];
    if let Err(err) = dispatcher.upload_resident_many(&uploads) {
        for handle in handles {
            let _ = dispatcher.free_resident(handle);
        }
        return Err(err);
    }

    Ok(ResidentAdaptiveTraversalGraph {
        node_count,
        edge_count: layout.edge_count,
        words: layout.words,
        layout_hash: adaptive_traversal_layout_hash(
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            adj_rows_dense,
        ),
        handles,
    })
}

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
    let frontier_layout = validate_adaptive_frontier(graph.node_count, frontier_in)
        .map_err(DispatchError::BadInputs)?;
    let frontier_bytes = u32_word_bytes(
        frontier_layout.words,
        "adaptive_traverse_resident_graph_step frontier",
    )?;
    let handles = ensure_frontier_handles(dispatcher, scratch, frontier_bytes)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_in);
    write_zero_bytes(&mut scratch.frontier_out_zero_bytes, frontier_bytes);
    write_zero_u32_words(
        &mut scratch.popcount_zero_bytes,
        1,
        "adaptive_traverse_resident_graph_step popcount",
    )?;

    let words_u32 = frontier_layout.words_u32;
    let device_features = dispatcher.device_feature_cache_key();
    let popcount_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanKey {
            layout_hash: graph.layout_hash,
            node_count: graph.node_count,
            edge_count: graph.edge_count,
            words: words_u32,
            queue_capacity: 0,
            allow_mask: 0,
            dense_threshold_pct: 0,
            device_features,
            kind: AdaptiveTraversalPlanKind::Popcount,
        },
        || reduce_count("frontier_in", "frontier_popcount", words_u32),
    );
    let traverse_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanKey {
            layout_hash: graph.layout_hash,
            node_count: graph.node_count,
            edge_count: graph.edge_count,
            words: words_u32,
            queue_capacity: 0,
            allow_mask,
            dense_threshold_pct,
            device_features,
            kind: AdaptiveTraversalPlanKind::SparseDense,
        },
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
    let graph_handles = graph.handles;
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
    let uploads = [
        (handles[0], scratch.frontier_in_bytes.as_slice()),
        (handles[1], scratch.frontier_out_zero_bytes.as_slice()),
        (handles[2], scratch.popcount_zero_bytes.as_slice()),
    ];
    let steps = [
        ResidentDispatchStep {
            program: &popcount_program,
            handle_ids: &count_handles,
            grid_override: Some([1, 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some([graph.node_count.max(1), 1, 1]),
        },
    ];
    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &uploads,
        &steps,
        &[ResidentReadRange {
            handle_id: handles[1],
            byte_offset: 0,
            byte_len: frontier_bytes,
        }],
        &mut scratch.readbacks,
    )?;
    if scratch.readbacks.len() != 1 {
        return Err(DispatchError::BackendError(format!(
            "Fix: adaptive_traverse_resident_graph_step expected 1 readback, got {}.",
            scratch.readbacks.len()
        )));
    }
    decode_u32_output_exact(
        &scratch.readbacks[0],
        graph.words,
        "adaptive_traverse_resident_graph_step frontier_out",
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
    let frontier_layout = validate_adaptive_frontier(graph.node_count, frontier_in)
        .map_err(DispatchError::BadInputs)?;
    let frontier_bytes = u32_word_bytes(
        frontier_layout.words,
        "adaptive_traverse_resident_graph_sparse_queue_step frontier",
    )?;
    let queue_capacity = graph.node_count.max(1);
    let queue_bytes = u32_word_bytes(
        queue_capacity as usize,
        "adaptive_traverse_resident_graph_sparse_queue_step queue",
    )?;
    let handles = ensure_frontier_handles(dispatcher, scratch, frontier_bytes)?;
    let queue_handle = ensure_queue_handle(dispatcher, scratch, queue_bytes)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_in);
    write_zero_bytes(&mut scratch.frontier_out_zero_bytes, frontier_bytes);
    write_zero_u32_words(
        &mut scratch.popcount_zero_bytes,
        1,
        "adaptive_traverse_resident_graph_sparse_queue_step popcount",
    )?;
    write_zero_bytes(&mut scratch.queue_zero_bytes, queue_bytes);

    let words_u32 = frontier_layout.words_u32;
    let device_features = dispatcher.device_feature_cache_key();
    let queue_program = scratch.plan_cache.get_or_build(
        AdaptiveTraversalPlanKey {
            layout_hash: graph.layout_hash,
            node_count: graph.node_count,
            edge_count: graph.edge_count,
            words: words_u32,
            queue_capacity,
            allow_mask: 0,
            dense_threshold_pct: 0,
            device_features,
            kind: AdaptiveTraversalPlanKind::FrontierToQueue,
        },
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
        AdaptiveTraversalPlanKey {
            layout_hash: graph.layout_hash,
            node_count: graph.node_count,
            edge_count: graph.edge_count,
            words: words_u32,
            queue_capacity,
            allow_mask,
            dense_threshold_pct: 0,
            device_features,
            kind: AdaptiveTraversalPlanKind::QueueForward,
        },
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
    let graph_handles = graph.handles;
    let queue_handles = [handles[0], queue_handle, handles[2]];
    let traverse_handles = [
        queue_handle,
        handles[2],
        graph_handles[0],
        graph_handles[1],
        graph_handles[2],
        handles[1],
    ];
    let uploads = [
        (handles[0], scratch.frontier_in_bytes.as_slice()),
        (handles[1], scratch.frontier_out_zero_bytes.as_slice()),
        (handles[2], scratch.popcount_zero_bytes.as_slice()),
        (queue_handle, scratch.queue_zero_bytes.as_slice()),
    ];
    let steps = [
        ResidentDispatchStep {
            program: &queue_program,
            handle_ids: &queue_handles,
            grid_override: Some([graph.node_count.div_ceil(256).max(1), 1, 1]),
        },
        ResidentDispatchStep {
            program: &traverse_program,
            handle_ids: &traverse_handles,
            grid_override: Some([queue_capacity.div_ceil(256).max(1), 1, 1]),
        },
    ];
    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &uploads,
        &steps,
        &[ResidentReadRange {
            handle_id: handles[1],
            byte_offset: 0,
            byte_len: frontier_bytes,
        }],
        &mut scratch.readbacks,
    )?;
    if scratch.readbacks.len() != 1 {
        return Err(DispatchError::BackendError(format!(
            "Fix: adaptive_traverse_resident_graph_sparse_queue_step expected 1 readback, got {}.",
            scratch.readbacks.len()
        )));
    }
    decode_u32_output_exact(
        &scratch.readbacks[0],
        graph.words,
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
    let mut frontier_popcount = 0u32;
    for &word in frontier_in {
        frontier_popcount = frontier_popcount.checked_add(word.count_ones()).ok_or_else(|| {
            DispatchError::BadInputs(format!(
                "Fix: adaptive_traverse_resident_graph_auto_step frontier popcount exceeds u32::MAX for {} frontier words.",
                frontier_in.len()
            ))
        })?;
    }
    let mode = select_adaptive_traversal_mode(
        graph.node_count,
        graph.edge_count,
        frontier_popcount,
        dense_threshold_pct,
    );
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

fn ensure_frontier_handles(
    dispatcher: &dyn OptimizerDispatcher,
    scratch: &mut AdaptiveTraversalResidentScratch,
    frontier_bytes: usize,
) -> Result<[u64; 3], DispatchError> {
    if scratch.frontier_bytes == frontier_bytes {
        if let Some(handles) = scratch.handles {
            return Ok(handles);
        }
    }
    scratch.free(dispatcher)?;
    let handles = [
        dispatcher.alloc_resident(frontier_bytes)?,
        dispatcher.alloc_resident(frontier_bytes)?,
        dispatcher.alloc_resident(u32_word_bytes(1, "adaptive traversal popcount resident")?)?,
    ];
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
    let handle = dispatcher.alloc_resident(queue_bytes)?;
    scratch.queue_handle = Some(handle);
    scratch.queue_bytes = queue_bytes;
    Ok(handle)
}

fn adaptive_traversal_layout_hash(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    adj_rows_dense: &[u32],
) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    node_count.hash(&mut hasher);
    edge_offsets.hash(&mut hasher);
    edge_targets.hash(&mut hasher);
    edge_kind_mask.hash(&mut hasher);
    adj_rows_dense.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_uses_queue_for_tiny_sparse_frontier() {
        assert_eq!(
            select_adaptive_traversal_mode(1_000, 10_000, 3, 25),
            AdaptiveTraversalMode::SparseQueue
        );
    }

    #[test]
    fn selector_uses_sparse_dense_at_dense_cutover() {
        assert_eq!(
            select_adaptive_traversal_mode(1_000, 10_000, 250, 25),
            AdaptiveTraversalMode::SparseDense
        );
    }

    #[test]
    fn selector_uses_sparse_dense_for_mid_density_low_degree_graph() {
        assert_eq!(
            select_adaptive_traversal_mode(1_000, 1_000, 100, 25),
            AdaptiveTraversalMode::SparseDense
        );
    }

    #[test]
    fn layout_hash_distinguishes_dense_rows() {
        let offsets = [0, 0];
        let targets = [];
        let masks = [];
        let a = adaptive_traversal_layout_hash(1, &offsets, &targets, &masks, &[1]);
        let b = adaptive_traversal_layout_hash(1, &offsets, &targets, &masks, &[2]);
        assert_ne!(a, b);
    }

    #[test]
    fn matches_primitive_directly_by_wiring_release_programs() {
        let source = include_str!("adaptive_traverse.rs");
        let release_path = source
            .split("pub fn upload_resident_adaptive_traversal_graph")
            .nth(1)
            .and_then(|section| section.split("\n#[cfg(test)]\nmod tests").next())
            .expect("adaptive traversal release wiring must be source-visible");

        for primitive_call in [
            "primitive_adaptive_sparse_dense_step(",
            "primitive_frontier_to_queue(",
            "primitive_csr_queue_forward_traverse(",
            "validate_adaptive_traversal_layout(",
            "validate_adaptive_frontier(",
        ] {
            assert!(
                release_path.contains(primitive_call),
                "adaptive traversal self-substrate path must call primitive authority {primitive_call} directly"
            );
        }
        for fork_signal in [
            "reference_adaptive_sparse_dense_step",
            "cpu_sparse_dense",
            "for neighbor",
            "while let Some",
        ] {
            assert!(
                !release_path.contains(fork_signal),
                "adaptive traversal self-substrate path must not fork primitive traversal logic via {fork_signal}"
            );
        }
    }

    #[test]
    fn release_resident_paths_do_not_call_cpu_or_local_saturating_helpers() {
        let source = include_str!("adaptive_traverse.rs");
        let start = source
            .find("pub fn upload_resident_adaptive_traversal_graph")
            .expect("resident path marker must exist");
        let end = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must exist");
        let release_path = &source[start..end];
        assert!(!release_path.contains("reference_adaptive_sparse_dense_step"));
        assert!(!release_path.contains("reference_"));
        assert!(!release_path.contains("cpu_sparse_dense"));
        assert!(!release_path.contains("saturating_add"));
        assert!(!release_path.contains("saturating_mul"));
        assert!(!release_path.contains("std::mem::size_of::<u32>()"));
        assert!(release_path.contains("adaptive traversal popcount resident"));
        assert!(!release_path.contains("fill_"));
    }
}
