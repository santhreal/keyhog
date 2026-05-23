//! Multi-step BFS frontier expansion substrate consumer.
//!
//! Wires `vyre_primitives::graph::persistent_bfs` so the optimizer can
//! compute multi-step reachability in a single primitive call instead
//! of looping `csr_forward_traverse` by hand. The primitive accumulates
//! into `frontier_out` via OR and reports a sticky changed-flag, so the
//! caller knows whether any new nodes were added across all steps.

#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::persistent_bfs::cpu_ref as reference_persistent_bfs;
use vyre_primitives::graph::persistent_bfs::{
    persistent_bfs as primitive_persistent_bfs,
    persistent_bfs_batch as primitive_persistent_bfs_batch,
    persistent_bfs_layout_hash as primitive_persistent_bfs_layout_hash,
    validate_persistent_bfs_batch_frontiers, validate_persistent_bfs_frontier,
    validate_persistent_bfs_graph_layout, validate_persistent_bfs_inputs,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use std::collections::HashMap;

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, u32_word_bytes, write_u32_slice_le_bytes,
    write_u32_slice_or_zero_words, write_zero_bytes, write_zero_u32_words,
};
use crate::optimizer::dispatcher::{
    DispatchError, OptimizerDispatcher, ResidentDispatchStep, ResidentReadRange,
};

/// Caller-owned GPU dispatch scratch for persistent BFS expansion.
#[derive(Debug, Default)]
pub struct PersistentBfsGpuScratch {
    nodes: Vec<u32>,
    node_tags: Vec<u32>,
    edge_targets: Vec<u32>,
    edge_kind_mask: Vec<u32>,
    inputs: Vec<Vec<u8>>,
    changed: Vec<u32>,
    plan_cache: PersistentBfsPlanCache,
}

/// Device-resident CSR graph for repeated persistent-BFS/dataflow queries.
#[derive(Debug, Clone)]
pub struct ResidentBfsGraph {
    node_count: u32,
    edge_count: u32,
    words: usize,
    words_u32: u32,
    layout_hash: u64,
    handles: [u64; 5],
}

impl ResidentBfsGraph {
    /// Number of graph nodes represented by this resident CSR.
    #[must_use]
    pub fn node_count(&self) -> u32 {
        self.node_count
    }

    /// Number of logical CSR edges represented by this resident CSR.
    #[must_use]
    pub fn edge_count(&self) -> u32 {
        self.edge_count
    }

    /// Number of u32 words in each frontier bitset.
    #[must_use]
    pub fn words(&self) -> usize {
        self.words
    }

    /// Stable in-session hash of the CSR graph layout and edge masks.
    #[must_use]
    pub fn layout_hash(&self) -> u64 {
        self.layout_hash
    }

    /// Resident handles in ProgramGraph buffer order:
    /// nodes, edge_offsets, edge_targets, edge_kind_mask, node_tags.
    #[must_use]
    pub fn handles(&self) -> [u64; 5] {
        self.handles
    }

    /// Free the resident graph buffers.
    ///
    /// # Errors
    ///
    /// Returns the first backend free failure, after attempting every handle.
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

/// Caller-owned resident scratch for repeated BFS queries over a resident graph.
#[derive(Debug, Default)]
pub struct PersistentBfsResidentScratch {
    frontier_handles: Option<[u64; 3]>,
    frontier_bytes: usize,
    changed_bytes: usize,
    frontier_in_bytes: Vec<u8>,
    frontier_zero_bytes: Vec<u8>,
    changed_zero_bytes: Vec<u8>,
    readbacks: Vec<Vec<u8>>,
    changed: Vec<u32>,
    plan_cache: PersistentBfsPlanCache,
}

impl PersistentBfsResidentScratch {
    /// Snapshot plan-cache counters for residency and repeated-query tests.
    #[must_use]
    pub fn plan_cache_snapshot(&self) -> PersistentBfsPlanCacheSnapshot {
        self.plan_cache.snapshot()
    }

    /// Free resident frontier/change buffers owned by this scratch object.
    ///
    /// # Errors
    ///
    /// Returns the first backend free failure, after attempting every handle.
    pub fn free(&mut self, dispatcher: &dyn OptimizerDispatcher) -> Result<(), DispatchError> {
        let Some(handles) = self.frontier_handles.take() else {
            return Ok(());
        };
        self.frontier_bytes = 0;
        self.changed_bytes = 0;
        let mut first_err = None;
        for handle in handles {
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

/// Persistent BFS plan-cache counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PersistentBfsPlanCacheSnapshot {
    /// Number of cached resident/non-resident BFS plans.
    pub entries: usize,
    /// Number of lookups served from the cache.
    pub hits: u64,
    /// Number of lookups that built and inserted a new plan.
    pub misses: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum PersistentBfsPlanKind {
    Single,
    Batch,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PersistentBfsPlanKey {
    layout_hash: u64,
    node_count: u32,
    edge_count: u32,
    words: u32,
    query_count: u32,
    allow_mask: u32,
    max_iters: u32,
    device_features: u64,
    kind: PersistentBfsPlanKind,
}

#[derive(Debug, Default)]
struct PersistentBfsPlanCache {
    entries: HashMap<PersistentBfsPlanKey, vyre_foundation::ir::Program>,
    hits: u64,
    misses: u64,
}

impl PersistentBfsPlanCache {
    fn get_or_build(
        &mut self,
        key: PersistentBfsPlanKey,
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

    fn snapshot(&self) -> PersistentBfsPlanCacheSnapshot {
        PersistentBfsPlanCacheSnapshot {
            entries: self.entries.len(),
            hits: self.hits,
            misses: self.misses,
        }
    }
}

/// Run up to `max_iters` BFS steps starting from `frontier_in`,
/// returning the saturated frontier and a sticky changed-flag (1 if
/// any iteration added new bits, 0 if the seed was already
/// saturated). Bumps the dataflow-fixpoint substrate counter.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn bfs_expand(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> (Vec<u32>, u32) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reference_persistent_bfs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        max_iters,
    )
}

/// Convenience: compute the forward-reachable set of `seed` under
/// `allow_mask` with a generous iteration budget. Returns just the
/// frontier; callers wanting the changed-flag should use
/// [`bfs_expand`] directly.
#[must_use]
#[cfg(test)]
pub fn forward_reach(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    let (out, _changed) = bfs_expand(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        node_count,
    );
    out
}

/// Dispatcher-backed persistent BFS expansion. Returns the saturated frontier
/// and sticky changed-flag.
///
/// # Errors
///
/// Propagates dispatch failures and rejects malformed CSR/frontier
/// shapes or truncated readback.
#[allow(clippy::too_many_arguments)]
pub fn bfs_expand_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Result<(Vec<u32>, u32), DispatchError> {
    let mut frontier = Vec::new();
    let changed = bfs_expand_via_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        max_iters,
        &mut frontier,
    )?;
    Ok((frontier, changed))
}

/// Dispatcher-backed persistent BFS expansion into caller-owned frontier storage.
#[allow(clippy::too_many_arguments)]
pub fn bfs_expand_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
    frontier_out: &mut Vec<u32>,
) -> Result<u32, DispatchError> {
    let mut scratch = PersistentBfsGpuScratch::default();
    bfs_expand_via_with_scratch_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        max_iters,
        &mut scratch,
        frontier_out,
    )
}

/// Dispatcher-backed persistent BFS expansion into caller-owned frontier and dispatch scratch.
#[allow(clippy::too_many_arguments)]
pub fn bfs_expand_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
    scratch: &mut PersistentBfsGpuScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<u32, DispatchError> {
    let layout = validate_persistent_bfs_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
    )
    .map_err(DispatchError::BadInputs)?;
    let words = layout.words;
    if layout.node_count == 0 {
        frontier_out.clear();
        return Ok(0);
    }
    scratch.nodes.clear();
    scratch.nodes.resize(layout.node_words, 0);
    scratch.node_tags.clear();
    scratch.node_tags.resize(layout.node_words, 0);
    let layout_hash = primitive_persistent_bfs_layout_hash(
        layout.node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
    );

    scratch.edge_targets.clear();
    scratch.edge_targets.extend_from_slice(edge_targets);
    scratch.edge_targets.resize(layout.edge_storage_words, 0);
    scratch.edge_kind_mask.clear();
    scratch.edge_kind_mask.extend_from_slice(edge_kind_mask);
    scratch.edge_kind_mask.resize(layout.edge_storage_words, 0);
    let key = PersistentBfsPlanKey {
        layout_hash,
        node_count: layout.node_count,
        edge_count: layout.edge_count,
        words: layout.words_u32,
        query_count: 1,
        allow_mask,
        max_iters,
        device_features: dispatcher.device_feature_cache_key(),
        kind: PersistentBfsPlanKind::Single,
    };
    let program = scratch.plan_cache.get_or_build(key, || {
        primitive_persistent_bfs(
            ProgramGraphShape::new(layout.node_count, layout.edge_count.max(1)),
            "frontier_in",
            "frontier_out",
            allow_mask,
            max_iters,
        )
    });
    let frontier_bytes = u32_word_bytes(words, "bfs_expand_via frontier")?;
    ensure_input_slots(&mut scratch.inputs, 8);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], &scratch.nodes);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], edge_offsets);
    write_u32_slice_le_bytes(&mut scratch.inputs[2], &scratch.edge_targets);
    write_u32_slice_le_bytes(&mut scratch.inputs[3], &scratch.edge_kind_mask);
    write_u32_slice_le_bytes(&mut scratch.inputs[4], &scratch.node_tags);
    write_u32_slice_le_bytes(&mut scratch.inputs[5], frontier_in);
    write_zero_bytes(&mut scratch.inputs[6], frontier_bytes);
    write_zero_u32_words(&mut scratch.inputs[7], 1, "bfs_expand_via changed")?;
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([1, 1, 1]))?;
    if outputs.len() != 2 {
        return Err(DispatchError::BackendError(format!(
            "Fix: bfs_expand_via expected exactly 2 output buffers (frontier_out, changed), got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        words,
        "bfs_expand_via frontier_out",
        frontier_out,
    )?;
    decode_u32_output_exact(
        &outputs[1],
        1,
        "bfs_expand_via changed",
        &mut scratch.changed,
    )?;
    Ok(scratch.changed[0])
}

/// Upload CSR graph topology once into resident device buffers.
///
/// Use the returned [`ResidentBfsGraph`] with
/// [`bfs_expand_resident_graph_with_scratch_into`] for repeated dataflow
/// queries that share the same graph topology.
///
/// # Errors
///
/// Rejects malformed CSR shapes or dispatchers without resident-buffer support.
pub fn upload_resident_bfs_graph(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
) -> Result<ResidentBfsGraph, DispatchError> {
    let layout = validate_persistent_bfs_graph_layout(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
    )
    .map_err(DispatchError::BadInputs)?;

    let mut nodes_bytes = Vec::new();
    let mut edge_offsets_bytes = Vec::new();
    let mut edge_targets_bytes = Vec::new();
    let mut edge_kind_bytes = Vec::new();
    let mut node_tags_bytes = Vec::new();
    write_zero_u32_words(
        &mut nodes_bytes,
        layout.node_words,
        "resident BFS graph nodes",
    )?;
    write_u32_slice_le_bytes(&mut edge_offsets_bytes, edge_offsets);
    write_u32_slice_or_zero_words(
        &mut edge_targets_bytes,
        edge_targets,
        layout.edge_storage_words,
        "resident BFS graph edge_targets",
    )?;
    write_u32_slice_or_zero_words(
        &mut edge_kind_bytes,
        edge_kind_mask,
        layout.edge_storage_words,
        "resident BFS graph edge_kind_mask",
    )?;
    write_zero_u32_words(
        &mut node_tags_bytes,
        layout.node_words,
        "resident BFS graph node_tags",
    )?;

    let payloads = [
        nodes_bytes.as_slice(),
        edge_offsets_bytes.as_slice(),
        edge_targets_bytes.as_slice(),
        edge_kind_bytes.as_slice(),
        node_tags_bytes.as_slice(),
    ];
    let handles = [
        dispatcher.alloc_resident(payloads[0].len())?,
        dispatcher.alloc_resident(payloads[1].len())?,
        dispatcher.alloc_resident(payloads[2].len())?,
        dispatcher.alloc_resident(payloads[3].len())?,
        dispatcher.alloc_resident(payloads[4].len())?,
    ];
    let uploads = [
        (handles[0], payloads[0]),
        (handles[1], payloads[1]),
        (handles[2], payloads[2]),
        (handles[3], payloads[3]),
        (handles[4], payloads[4]),
    ];
    if let Err(err) = dispatcher.upload_resident_many(&uploads) {
        for handle in handles {
            let _ = dispatcher.free_resident(handle);
        }
        return Err(err);
    }

    Ok(ResidentBfsGraph {
        node_count: layout.node_count,
        edge_count: layout.edge_count,
        words: layout.words,
        words_u32: layout.words_u32,
        layout_hash: primitive_persistent_bfs_layout_hash(
            layout.node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
        ),
        handles,
    })
}

/// Run persistent BFS over an already-resident graph.
///
/// The graph buffers are not re-uploaded. The scratch object owns resident
/// frontier/change buffers and reuses them across calls when the frontier byte
/// width is unchanged.
#[allow(clippy::too_many_arguments)]
pub fn bfs_expand_resident_graph_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentBfsGraph,
    frontier_in: &[u32],
    allow_mask: u32,
    max_iters: u32,
    scratch: &mut PersistentBfsResidentScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<u32, DispatchError> {
    let frontier_layout = validate_persistent_bfs_frontier(graph.words, frontier_in)
        .map_err(DispatchError::BadInputs)?;
    let frontier_bytes =
        u32_word_bytes(frontier_layout.words, "bfs_expand_resident_graph frontier")?;
    let frontier_handles = ensure_resident_frontier_handles(dispatcher, scratch, frontier_bytes)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_in);
    write_zero_bytes(&mut scratch.frontier_zero_bytes, frontier_bytes);
    write_zero_u32_words(
        &mut scratch.changed_zero_bytes,
        1,
        "bfs_expand_resident_graph changed",
    )?;

    let uploads = [
        (frontier_handles[0], scratch.frontier_in_bytes.as_slice()),
        (frontier_handles[1], scratch.frontier_zero_bytes.as_slice()),
        (frontier_handles[2], scratch.changed_zero_bytes.as_slice()),
    ];
    let key = PersistentBfsPlanKey {
        layout_hash: graph.layout_hash,
        node_count: graph.node_count,
        edge_count: graph.edge_count,
        words: frontier_layout.words_u32,
        query_count: 1,
        allow_mask,
        max_iters,
        device_features: dispatcher.device_feature_cache_key(),
        kind: PersistentBfsPlanKind::Single,
    };
    let program = scratch.plan_cache.get_or_build(key, || {
        primitive_persistent_bfs(
            ProgramGraphShape::new(graph.node_count, graph.edge_count.max(1)),
            "frontier_in",
            "frontier_out",
            allow_mask,
            max_iters,
        )
    });
    let graph_handles = graph.handles;
    let handles = [
        graph_handles[0],
        graph_handles[1],
        graph_handles[2],
        graph_handles[3],
        graph_handles[4],
        frontier_handles[0],
        frontier_handles[1],
        frontier_handles[2],
    ];
    let steps = [ResidentDispatchStep {
        program: &program,
        handle_ids: &handles,
        grid_override: Some([1, 1, 1]),
    }];
    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &uploads,
        &steps,
        &[
            ResidentReadRange {
                handle_id: frontier_handles[1],
                byte_offset: 0,
                byte_len: frontier_bytes,
            },
            ResidentReadRange {
                handle_id: frontier_handles[2],
                byte_offset: 0,
                byte_len: 4,
            },
        ],
        &mut scratch.readbacks,
    )?;
    if scratch.readbacks.len() != 2 {
        return Err(DispatchError::BackendError(format!(
            "Fix: bfs_expand_resident_graph expected exactly 2 readbacks, got {}.",
            scratch.readbacks.len()
        )));
    }
    decode_u32_output_exact(
        &scratch.readbacks[0],
        graph.words,
        "bfs_expand_resident_graph frontier_out",
        frontier_out,
    )?;
    decode_u32_output_exact(
        &scratch.readbacks[1],
        1,
        "bfs_expand_resident_graph changed",
        &mut scratch.changed,
    )?;
    Ok(scratch.changed[0])
}

/// Run many persistent-BFS queries over one resident graph.
///
/// `frontier_inputs` is a flat array of `query_count * graph.words()` u32
/// words. Outputs are written flat in the same order. This keeps graph topology
/// resident and reuses the scratch-owned frontier/change handles across all
/// queries, so the only per-query H2D payload is the seed frontier plus zeroed
/// output/change state.
#[allow(clippy::too_many_arguments)]
pub fn bfs_expand_resident_graph_batch_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    graph: &ResidentBfsGraph,
    frontier_inputs: &[u32],
    query_count: usize,
    allow_mask: u32,
    max_iters: u32,
    scratch: &mut PersistentBfsResidentScratch,
    frontier_outputs: &mut Vec<u32>,
    changed_outputs: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let batch_layout =
        validate_persistent_bfs_batch_frontiers(graph.words, frontier_inputs, query_count)
            .map_err(DispatchError::BadInputs)?;
    if query_count == 0 {
        frontier_outputs.clear();
        changed_outputs.clear();
        return Ok(());
    }

    let frontier_bytes = u32_word_bytes(
        batch_layout.total_words,
        "bfs_expand_resident_graph_batch frontier",
    )?;
    let changed_bytes = u32_word_bytes(query_count, "bfs_expand_resident_graph_batch changed")?;
    let frontier_handles =
        ensure_resident_query_handles(dispatcher, scratch, frontier_bytes, changed_bytes)?;
    write_u32_slice_le_bytes(&mut scratch.frontier_in_bytes, frontier_inputs);
    write_zero_bytes(&mut scratch.frontier_zero_bytes, frontier_bytes);
    write_zero_bytes(&mut scratch.changed_zero_bytes, changed_bytes);

    let uploads = [
        (frontier_handles[0], scratch.frontier_in_bytes.as_slice()),
        (frontier_handles[1], scratch.frontier_zero_bytes.as_slice()),
        (frontier_handles[2], scratch.changed_zero_bytes.as_slice()),
    ];
    let key = PersistentBfsPlanKey {
        layout_hash: graph.layout_hash,
        node_count: graph.node_count,
        edge_count: graph.edge_count,
        words: graph.words_u32,
        query_count: batch_layout.query_count,
        allow_mask,
        max_iters,
        device_features: dispatcher.device_feature_cache_key(),
        kind: PersistentBfsPlanKind::Batch,
    };
    let program = scratch.plan_cache.get_or_build(key, || {
        primitive_persistent_bfs_batch(
            ProgramGraphShape::new(graph.node_count, graph.edge_count.max(1)),
            "frontier_in",
            "frontier_out",
            "changed",
            batch_layout.query_count,
            allow_mask,
            max_iters,
        )
    });
    let graph_handles = graph.handles;
    let handles = [
        graph_handles[0],
        graph_handles[1],
        graph_handles[2],
        graph_handles[3],
        graph_handles[4],
        frontier_handles[0],
        frontier_handles[1],
        frontier_handles[2],
    ];
    let steps = [ResidentDispatchStep {
        program: &program,
        handle_ids: &handles,
        grid_override: Some([1, batch_layout.query_count.max(1), 1]),
    }];
    dispatcher.upload_resident_many_sequence_read_ranges_into(
        &uploads,
        &steps,
        &[
            ResidentReadRange {
                handle_id: frontier_handles[1],
                byte_offset: 0,
                byte_len: frontier_bytes,
            },
            ResidentReadRange {
                handle_id: frontier_handles[2],
                byte_offset: 0,
                byte_len: changed_bytes,
            },
        ],
        &mut scratch.readbacks,
    )?;
    if scratch.readbacks.len() != 2 {
        return Err(DispatchError::BackendError(format!(
            "Fix: bfs_expand_resident_graph_batch expected exactly 2 readbacks, got {}.",
            scratch.readbacks.len()
        )));
    }
    decode_u32_output_exact(
        &scratch.readbacks[0],
        batch_layout.total_words,
        "bfs_expand_resident_graph_batch frontier_out",
        frontier_outputs,
    )?;
    decode_u32_output_exact(
        &scratch.readbacks[1],
        query_count,
        "bfs_expand_resident_graph_batch changed",
        changed_outputs,
    )?;
    Ok(())
}

fn ensure_resident_frontier_handles(
    dispatcher: &dyn OptimizerDispatcher,
    scratch: &mut PersistentBfsResidentScratch,
    frontier_bytes: usize,
) -> Result<[u64; 3], DispatchError> {
    ensure_resident_query_handles(dispatcher, scratch, frontier_bytes, 4)
}

fn ensure_resident_query_handles(
    dispatcher: &dyn OptimizerDispatcher,
    scratch: &mut PersistentBfsResidentScratch,
    frontier_bytes: usize,
    changed_bytes: usize,
) -> Result<[u64; 3], DispatchError> {
    if let Some(handles) = scratch.frontier_handles {
        if scratch.frontier_bytes == frontier_bytes && scratch.changed_bytes == changed_bytes {
            return Ok(handles);
        }
        scratch.free(dispatcher)?;
    }
    let handles = [
        dispatcher.alloc_resident(frontier_bytes)?,
        dispatcher.alloc_resident(frontier_bytes)?,
        dispatcher.alloc_resident(changed_bytes)?,
    ];
    scratch.frontier_handles = Some(handles);
    scratch.frontier_bytes = frontier_bytes;
    scratch.changed_bytes = changed_bytes;
    Ok(handles)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use std::cell::{Cell, RefCell};
    use vyre_foundation::ir::Program;

    struct PersistentBfsDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for PersistentBfsDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([1, 1, 1]));
            if inputs.len() != 8 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: persistent BFS test dispatcher expected 8 inputs, got {}.",
                    inputs.len()
                )));
            }
            Ok(self.outputs.clone())
        }
    }

    #[derive(Default)]
    struct ResidentPersistentBfsDispatcher {
        next_handle: RefCell<u64>,
        device_features: Cell<u64>,
        alloc_sizes: RefCell<Vec<usize>>,
        topology_upload_batch_sizes: RefCell<Vec<usize>>,
        query_upload_batch_sizes: RefCell<Vec<usize>>,
        step_handle_sets: RefCell<Vec<Vec<u64>>>,
        freed: RefCell<Vec<u64>>,
    }

    impl ResidentPersistentBfsDispatcher {
        fn new() -> Self {
            Self {
                next_handle: RefCell::new(10),
                ..Self::default()
            }
        }
    }

    impl OptimizerDispatcher for ResidentPersistentBfsDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            Err(DispatchError::Rejected(
                "Fix: resident persistent BFS test dispatcher only supports resident APIs."
                    .to_string(),
            ))
        }

        fn supports_persistent(&self) -> bool {
            true
        }

        fn device_feature_cache_key(&self) -> u64 {
            self.device_features.get()
        }

        fn alloc_resident(&self, byte_len: usize) -> Result<u64, DispatchError> {
            let mut next = self.next_handle.borrow_mut();
            let handle = *next;
            *next += 1;
            self.alloc_sizes.borrow_mut().push(byte_len);
            Ok(handle)
        }

        fn upload_resident_many(&self, uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
            self.topology_upload_batch_sizes
                .borrow_mut()
                .push(uploads.len());
            Ok(())
        }

        fn upload_resident_many_sequence_read_ranges_into(
            &self,
            uploads: &[(u64, &[u8])],
            steps: &[ResidentDispatchStep<'_>],
            read_ranges: &[ResidentReadRange],
            outputs: &mut Vec<Vec<u8>>,
        ) -> Result<(), DispatchError> {
            assert_eq!(uploads.len(), 3);
            assert_eq!(steps.len(), 1);
            assert_eq!(read_ranges.len(), 2);
            assert_eq!(read_ranges[0].byte_len, uploads[1].1.len());
            assert_eq!(read_ranges[1].byte_len, uploads[2].1.len());
            self.query_upload_batch_sizes
                .borrow_mut()
                .push(uploads.len());
            self.step_handle_sets
                .borrow_mut()
                .push(steps[0].handle_ids.to_vec());
            outputs.clear();
            let frontier_words = uploads[1].1.len() / std::mem::size_of::<u32>();
            let changed_words = uploads[2].1.len() / std::mem::size_of::<u32>();
            outputs.push(u32_slice_to_le_bytes(&vec![0b1111; frontier_words]));
            outputs.push(u32_slice_to_le_bytes(&vec![1; changed_words]));
            Ok(())
        }

        fn free_resident(&self, handle: u64) -> Result<(), DispatchError> {
            self.freed.borrow_mut().push(handle);
            Ok(())
        }
    }

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn expand_chain_saturates() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 8);
        assert_eq!(out, vec![0b1111]);
        assert_eq!(changed, 1);
    }

    #[test]
    fn empty_seed_yields_empty_with_no_change() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF, 4);
        assert_eq!(out, vec![0u32]);
        assert_eq!(changed, 0);
    }

    #[test]
    fn saturated_seed_reports_no_change() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b1111], 0xFFFF_FFFF, 4);
        assert_eq!(out, vec![0b1111]);
        assert_eq!(changed, 0);
    }

    /// Closure-bar: substrate output equals primitive output exactly.
    #[test]
    fn matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = vec![0b0001];
        let via_substrate = bfs_expand(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
        let via_primitive = reference_persistent_bfs(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: max_iters bound is honored even on a chain
    /// longer than the budget. With 1 iter on a 4-chain from {0},
    /// only {0, 1} should be flagged (not the full chain).
    #[test]
    fn max_iters_bound_honored() {
        let (off, tgt, msk) = linear_graph();
        let (out, _) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 1);
        assert_eq!(out[0] & 0b1111, 0b0011);
    }

    /// Adversarial: allow_mask with kind bit not present in any
    /// edge must report no change, no expansion.
    #[test]
    fn allow_mask_filters_all_edges() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) = bfs_expand(4, &off, &tgt, &msk, &[0b0001], 0b0010, 4);
        // No edges of kind 1 → seed only.
        assert_eq!(out, vec![0b0001]);
        assert_eq!(changed, 0);
    }

    /// forward_reach helper saturates with an n-iteration budget on
    /// a chain shorter than n.
    #[test]
    fn forward_reach_saturates_chain() {
        let (off, tgt, msk) = linear_graph();
        let out = forward_reach(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
        assert_eq!(out, vec![0b1111]);
    }

    #[test]
    fn via_into_decodes_exact_outputs_into_reused_frontier() {
        let dispatcher = PersistentBfsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[1]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let mut frontier = Vec::with_capacity(4);
        let ptr = frontier.as_ptr();
        let changed = bfs_expand_via_into(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            4,
            &mut frontier,
        )
        .expect("dispatch succeeds");
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(changed, 1);
        assert_eq!(frontier.as_ptr(), ptr);
    }

    #[test]
    fn via_with_scratch_reuses_dispatch_storage() {
        let dispatcher = PersistentBfsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[1]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let mut scratch = PersistentBfsGpuScratch::default();
        let mut frontier = Vec::with_capacity(1);

        let changed = bfs_expand_via_with_scratch_into(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontier,
        )
        .expect("dispatch succeeds");
        assert_eq!(changed, 1);
        assert_eq!(frontier, vec![0b1111]);
        let node_capacity = scratch.nodes.capacity();
        let target_capacity = scratch.edge_targets.capacity();
        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let frontier_capacity = frontier.capacity();

        let changed = bfs_expand_via_with_scratch_into(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0011],
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontier,
        )
        .expect("dispatch succeeds");
        assert_eq!(changed, 1);
        assert_eq!(scratch.nodes.capacity(), node_capacity);
        assert_eq!(scratch.edge_targets.capacity(), target_capacity);
        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(frontier.capacity(), frontier_capacity);
    }

    #[test]
    fn resident_graph_uploads_topology_once_and_reuses_frontier_handles() {
        let dispatcher = ResidentPersistentBfsDispatcher::new();
        let (off, tgt, msk) = linear_graph();
        let graph =
            upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("resident upload");
        assert_eq!(
            dispatcher.topology_upload_batch_sizes.borrow().as_slice(),
            &[5]
        );
        assert_eq!(dispatcher.alloc_sizes.borrow().len(), 5);

        let graph_handles = graph.handles();
        let mut scratch = PersistentBfsResidentScratch::default();
        let mut frontier = Vec::with_capacity(4);
        let frontier_ptr = frontier.as_ptr();
        let changed = bfs_expand_resident_graph_with_scratch_into(
            &dispatcher,
            &graph,
            &[0b0001],
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontier,
        )
        .expect("first resident query");
        assert_eq!(changed, 1);
        assert_eq!(frontier, vec![0b1111]);
        assert_eq!(frontier.as_ptr(), frontier_ptr);
        assert_eq!(dispatcher.alloc_sizes.borrow().len(), 8);

        let changed = bfs_expand_resident_graph_with_scratch_into(
            &dispatcher,
            &graph,
            &[0b0011],
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontier,
        )
        .expect("second resident query");
        assert_eq!(changed, 1);
        assert_eq!(dispatcher.alloc_sizes.borrow().len(), 8);
        assert_eq!(
            dispatcher.query_upload_batch_sizes.borrow().as_slice(),
            &[3, 3]
        );
        assert_eq!(
            scratch.plan_cache_snapshot(),
            PersistentBfsPlanCacheSnapshot {
                entries: 1,
                hits: 1,
                misses: 1,
            }
        );

        let step_handles = dispatcher.step_handle_sets.borrow();
        assert_eq!(step_handles.len(), 2);
        assert_eq!(&step_handles[0][0..5], &graph_handles);
        assert_eq!(&step_handles[1][0..5], &graph_handles);
        assert_eq!(
            &step_handles[0][5..8],
            &step_handles[1][5..8],
            "frontier/change resident buffers must be reused across queries"
        );

        scratch.free(&dispatcher).expect("scratch free");
        graph.free(&dispatcher).expect("graph free");
        assert_eq!(dispatcher.freed.borrow().len(), 8);
    }

    #[test]
    fn resident_graph_batch_reuses_topology_and_frontier_handles() {
        let dispatcher = ResidentPersistentBfsDispatcher::new();
        let (off, tgt, msk) = linear_graph();
        let graph =
            upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("resident upload");
        assert_eq!(graph.words(), 1);

        let mut scratch = PersistentBfsResidentScratch::default();
        let mut frontiers = Vec::with_capacity(4);
        let frontiers_ptr = frontiers.as_ptr();
        let mut changed = Vec::with_capacity(4);
        let changed_ptr = changed.as_ptr();
        bfs_expand_resident_graph_batch_with_scratch_into(
            &dispatcher,
            &graph,
            &[0b0001, 0b0011, 0b0111],
            3,
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontiers,
            &mut changed,
        )
        .expect("resident batch query");

        assert_eq!(frontiers, vec![0b1111, 0b1111, 0b1111]);
        assert_eq!(changed, vec![1, 1, 1]);
        assert_eq!(frontiers.as_ptr(), frontiers_ptr);
        assert_eq!(changed.as_ptr(), changed_ptr);
        assert_eq!(
            dispatcher.topology_upload_batch_sizes.borrow().as_slice(),
            &[5]
        );
        assert_eq!(
            dispatcher.query_upload_batch_sizes.borrow().as_slice(),
            &[3]
        );
        assert_eq!(dispatcher.alloc_sizes.borrow().len(), 8);
        assert_eq!(
            scratch.plan_cache_snapshot(),
            PersistentBfsPlanCacheSnapshot {
                entries: 1,
                hits: 0,
                misses: 1,
            }
        );

        let step_handles = dispatcher.step_handle_sets.borrow();
        assert_eq!(step_handles.len(), 1);

        scratch.free(&dispatcher).expect("scratch free");
        graph.free(&dispatcher).expect("graph free");
    }

    #[test]
    fn resident_plan_cache_keys_include_device_features() {
        let dispatcher = ResidentPersistentBfsDispatcher::new();
        let (off, tgt, msk) = linear_graph();
        let graph =
            upload_resident_bfs_graph(&dispatcher, 4, &off, &tgt, &msk).expect("resident upload");
        let mut scratch = PersistentBfsResidentScratch::default();
        let mut frontier = Vec::new();

        dispatcher.device_features.set(0x10);
        bfs_expand_resident_graph_with_scratch_into(
            &dispatcher,
            &graph,
            &[0b0001],
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontier,
        )
        .expect("first feature-keyed query");
        dispatcher.device_features.set(0x20);
        bfs_expand_resident_graph_with_scratch_into(
            &dispatcher,
            &graph,
            &[0b0001],
            0xFFFF_FFFF,
            4,
            &mut scratch,
            &mut frontier,
        )
        .expect("second feature-keyed query");

        assert_eq!(
            scratch.plan_cache_snapshot(),
            PersistentBfsPlanCacheSnapshot {
                entries: 2,
                hits: 0,
                misses: 2,
            },
            "plan cache key must include backend device/lowering features"
        );

        scratch.free(&dispatcher).expect("scratch free");
        graph.free(&dispatcher).expect("graph free");
    }

    #[test]
    fn via_rejects_extra_outputs() {
        let dispatcher = PersistentBfsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[1]),
                u32_slice_to_le_bytes(&[99]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let err = bfs_expand_via(&dispatcher, 4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 4)
            .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_rejects_trailing_changed_bytes() {
        let dispatcher = PersistentBfsDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1111]), vec![1, 0, 0, 0, 2]],
        };
        let (off, tgt, msk) = linear_graph();
        let err = bfs_expand_via(&dispatcher, 4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 4)
            .expect_err("trailing changed bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_rejects_mismatched_edge_arrays() {
        let dispatcher = PersistentBfsDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[1]),
            ],
        };
        let err = bfs_expand_via(
            &dispatcher,
            2,
            &[0, 1, 1],
            &[1],
            &[],
            &[0b01],
            0xFFFF_FFFF,
            1,
        )
        .expect_err("mismatched edge arrays must be rejected");
        assert!(matches!(err, DispatchError::BadInputs(_)));
    }

    #[test]
    fn release_via_path_does_not_call_cpu_or_local_saturating_helpers() {
        let source = include_str!("persistent_bfs.rs");
        let start = source
            .find("pub fn bfs_expand_via")
            .expect("via path marker must exist");
        let end = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must exist");
        let release_path = &source[start..end];
        assert!(!release_path.contains("reference_persistent_bfs"));
        assert!(!release_path.contains("reference_"));
        assert!(!release_path.contains("cpu_ref"));
        assert!(!release_path.contains("saturating_mul"));
        assert!(!release_path.contains("fill_"));
    }

    /// Adversarial: a self-loop must terminate (changed becomes 0
    /// once the seed includes the self-loop node).
    #[test]
    fn self_loop_terminates() {
        // 0 -> 0 (self-loop), 1 isolated.
        let off = vec![0, 1, 1];
        let tgt = vec![0];
        let msk = vec![1];
        let (out, _) = bfs_expand(2, &off, &tgt, &msk, &[0b01], 0xFFFF_FFFF, 50);
        assert_eq!(out, vec![0b01]);
    }
}
