//! Region-graph dominance-frontier substrate consumer.
//!
//! Wires `vyre_primitives::graph::dominator_frontier` into the dispatch
//! path. The dominator tree of a Region graph identifies which Region's
//! writes a Region depends on; the dominance frontier of a Region set
//! tells the optimizer where phi-style merges (or vyre's analogue:
//! per-Region buffer reconcile) must run.
//!
//! # The self-use
//!
//! Vyre's optimizer needs to know, for any seed set of Regions, the
//! Regions where their effects MUST be reconciled. The classic SSA
//! answer is the dominance frontier: where two paths from the seed
//! merge into a node not strictly dominated by any seed. Same query,
//! same primitive, different IR.
//!
//! # Composition
//!
//! [`compute_dominance_frontier`] takes CSR-encoded dominance closure,
//! predecessor lists, and a seed bitset, and returns the frontier
//! bitset. The CSR encoding matches the primitive's contract exactly,
//! so the substrate call is a one-liner that bumps the observability
//! counter and forwards.

#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::dominator_frontier::cpu_ref as reference_dominator_frontier;
use vyre_primitives::graph::dominator_frontier::{
    dominator_frontier as primitive_dominator_frontier, frontier_size as primitive_frontier_size,
    validate_dominator_frontier_inputs,
};

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, u32_word_bytes, write_u32_slice_le_bytes,
    write_zero_bytes,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned GPU dispatch scratch for dominance-frontier queries.
#[derive(Debug, Default)]
pub struct DominanceFrontierGpuScratch {
    dom_targets: Vec<u32>,
    pred_targets: Vec<u32>,
    inputs: Vec<Vec<u8>>,
}

/// Compute the dominance frontier for `seed` over the Region graph
/// described by the CSR dominance closure (`dom_offsets`/`dom_targets`,
/// row `n` = every Region dominated by `n` including `n`) and the CSR
/// predecessor list (`pred_offsets`/`pred_targets`, row `m` = Regions
/// with an edge into `m`). `seed` is the packed-u32 bitset of selected
/// nodes; `node_count` matches the bitset width.
///
/// Returns the frontier bitset: the set of Regions where seed
/// influence must be reconciled. Bumps the substrate-call counter so
/// observability dashboards can see the dispatch is exercising the
/// primitive.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn compute_dominance_frontier(
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reference_dominator_frontier(
        node_count,
        dom_offsets,
        dom_targets,
        pred_offsets,
        pred_targets,
        seed,
    )
}

/// Number of Regions flagged in the frontier bitset. Useful as a
/// dispatch-time telemetry value: a high frontier count on a small
/// seed indicates a wide-merge program shape that fusion passes
/// should leave alone.
#[must_use]
pub fn frontier_size(frontier: &[u32]) -> u32 {
    primitive_frontier_size(frontier)
}

/// Dispatcher-backed dominance-frontier query.
///
/// # Errors
///
/// Propagates dispatch failures and rejects malformed dominance or
/// predecessor CSR inputs.
#[allow(clippy::too_many_arguments)]
pub fn compute_dominance_frontier_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
) -> Result<Vec<u32>, DispatchError> {
    let mut out = Vec::new();
    compute_dominance_frontier_via_into(
        dispatcher,
        node_count,
        dom_offsets,
        dom_targets,
        pred_offsets,
        pred_targets,
        seed,
        &mut out,
    )?;
    Ok(out)
}

/// Dispatcher-backed dominance-frontier query into caller-owned storage.
#[allow(clippy::too_many_arguments)]
pub fn compute_dominance_frontier_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
    frontier_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = DominanceFrontierGpuScratch::default();
    compute_dominance_frontier_via_with_scratch_into(
        dispatcher,
        node_count,
        dom_offsets,
        dom_targets,
        pred_offsets,
        pred_targets,
        seed,
        &mut scratch,
        frontier_out,
    )
}

/// Dispatcher-backed dominance-frontier query with caller-owned scratch.
#[allow(clippy::too_many_arguments)]
pub fn compute_dominance_frontier_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    dom_offsets: &[u32],
    dom_targets: &[u32],
    pred_offsets: &[u32],
    pred_targets: &[u32],
    seed: &[u32],
    scratch: &mut DominanceFrontierGpuScratch,
    frontier_out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_dominator_frontier_inputs(
        node_count,
        dom_offsets,
        dom_targets,
        pred_offsets,
        pred_targets,
        seed,
    )
    .map_err(DispatchError::BadInputs)?;
    if node_count == 0 {
        frontier_out.clear();
        return Ok(());
    }

    if dom_targets.is_empty() {
        scratch.dom_targets.clear();
        scratch.dom_targets.push(0);
    } else {
        scratch.dom_targets.clear();
        scratch.dom_targets.extend_from_slice(dom_targets);
    }
    if pred_targets.is_empty() {
        scratch.pred_targets.clear();
        scratch.pred_targets.push(0);
    } else {
        scratch.pred_targets.clear();
        scratch.pred_targets.extend_from_slice(pred_targets);
    }
    let program = primitive_dominator_frontier(
        node_count,
        layout.dom_edge_count.max(1),
        layout.pred_edge_count.max(1),
        "seed",
        "frontier_out",
    );
    let output_bytes = u32_word_bytes(layout.words, "compute_dominance_frontier_via frontier")?;
    ensure_input_slots(&mut scratch.inputs, 6);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], dom_offsets);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], &scratch.dom_targets);
    write_u32_slice_le_bytes(&mut scratch.inputs[2], pred_offsets);
    write_u32_slice_le_bytes(&mut scratch.inputs[3], &scratch.pred_targets);
    write_u32_slice_le_bytes(&mut scratch.inputs[4], seed);
    write_zero_bytes(&mut scratch.inputs[5], output_bytes);
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([node_count, 1, 1]))?;
    if outputs.len() != 1 {
        return Err(DispatchError::BackendError(format!(
            "Fix: compute_dominance_frontier_via expected exactly one frontier_out output buffer, got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        layout.words,
        "compute_dominance_frontier_via frontier_out",
        frontier_out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

    struct DominatorDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for DominatorDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([4, 1, 1]));
            if inputs.len() != 6 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: dominator frontier test dispatcher expected 6 inputs, got {}.",
                    inputs.len()
                )));
            }
            Ok(self.outputs.clone())
        }
    }

    /// Linear chain 0 -> 1 -> 2 -> 3. Dominance closure: each node
    /// dominates itself and every successor. Predecessors: each
    /// non-zero node has the previous as its sole pred.
    /// Seed = {0}. Expected frontier: empty (every dominator
    /// strictly dominates the merge candidate).
    #[test]
    fn frontier_of_linear_chain_is_empty() {
        // dom CSR: row 0 = {0,1,2,3}; row 1 = {1,2,3}; row 2 = {2,3}; row 3 = {3}
        let dom_offsets = vec![0, 4, 7, 9, 10];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3, 2, 3, 3];
        // pred CSR: row 0 = {}; row 1 = {0}; row 2 = {1}; row 3 = {2}
        let pred_offsets = vec![0, 0, 1, 2, 3];
        let pred_targets = vec![0, 1, 2];
        let seed = vec![0b0001];
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(frontier, vec![0u32]);
        assert_eq!(frontier_size(&frontier), 0);
    }

    /// Diamond: 0 -> 1, 0 -> 2, 1 -> 3, 2 -> 3.
    /// Dominators: 0 dominates {0,1,2,3}; 1,2 dominate themselves;
    /// 3 dominates itself.
    /// Seed = {1}: 1 dominates a predecessor of 3 (itself), but does
    /// not strictly dominate 3 (0 does, not 1). So frontier = {3}.
    #[test]
    fn frontier_of_diamond_seed_is_merge_node() {
        // dom CSR: 0 -> {0,1,2,3}; 1 -> {1}; 2 -> {2}; 3 -> {3}
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        // pred CSR: 0 -> {}; 1 -> {0}; 2 -> {0}; 3 -> {1, 2}
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0b0010]; // {1}
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        // Expect node 3 in the frontier.
        assert_eq!(frontier, vec![0b1000]);
        assert_eq!(frontier_size(&frontier), 1);
    }

    /// Closure-bar: substrate consumer must produce the same bitset
    /// as a direct primitive call. If the wiring drifts, this
    /// fails before any downstream consumer sees stale frontiers.
    #[test]
    fn matches_primitive_directly() {
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0b0011];
        let via_substrate = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        let via_primitive = reference_dominator_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: empty seed must yield an empty frontier. A naive
    /// implementation that ignores the seed bit and walks every
    /// Region would mark the entire bitset.
    #[test]
    fn empty_seed_yields_empty_frontier() {
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0u32];
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(frontier, vec![0u32]);
        assert_eq!(frontier_size(&frontier), 0);
    }

    /// Adversarial: seed that strictly dominates the entire graph
    /// must NOT include any node in its frontier (a node n is in
    /// the frontier of seed s only if s does NOT strictly dominate
    /// n).
    #[test]
    fn seed_dominating_everything_has_empty_frontier() {
        // 0 dominates {0,1,2,3}. Seed = {0} -> frontier should be {}.
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let seed = vec![0b0001];
        let frontier = compute_dominance_frontier(
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &seed,
        );
        assert_eq!(frontier, vec![0u32]);
    }

    /// frontier_size must return the popcount of the bitset.
    #[test]
    fn frontier_size_counts_set_bits() {
        assert_eq!(frontier_size(&[0u32]), 0);
        assert_eq!(frontier_size(&[0b1011u32]), 3);
        assert_eq!(frontier_size(&[0xFFFFFFFFu32, 0b1u32]), 33);
    }

    #[test]
    fn via_decodes_exact_frontier_into_reused_buffer() {
        let dispatcher = DominatorDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1000])],
        };
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let mut out = Vec::with_capacity(4);
        let ptr = out.as_ptr();
        compute_dominance_frontier_via_into(
            &dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
            &mut out,
        )
        .expect("dispatch succeeds");
        assert_eq!(out, vec![0b1000]);
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn via_with_scratch_reuses_dispatch_storage() {
        let dispatcher = DominatorDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1000])],
        };
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let mut scratch = DominanceFrontierGpuScratch::default();
        let mut out = Vec::with_capacity(1);

        compute_dominance_frontier_via_with_scratch_into(
            &dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
            &mut scratch,
            &mut out,
        )
        .expect("dispatch succeeds");
        assert_eq!(out, vec![0b1000]);
        let dom_target_capacity = scratch.dom_targets.capacity();
        let pred_target_capacity = scratch.pred_targets.capacity();
        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let out_capacity = out.capacity();

        compute_dominance_frontier_via_with_scratch_into(
            &dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0011],
            &mut scratch,
            &mut out,
        )
        .expect("dispatch succeeds");
        assert_eq!(scratch.dom_targets.capacity(), dom_target_capacity);
        assert_eq!(scratch.pred_targets.capacity(), pred_target_capacity);
        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(out.capacity(), out_capacity);
        assert_eq!(out, vec![0b1000]);
    }

    #[test]
    fn via_rejects_extra_outputs() {
        let dispatcher = DominatorDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1000]),
                u32_slice_to_le_bytes(&[0]),
            ],
        };
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let err = compute_dominance_frontier_via(
            &dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
        )
        .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_rejects_trailing_frontier_bytes() {
        let dispatcher = DominatorDispatcher {
            outputs: vec![vec![0, 0, 0, 0, 1]],
        };
        let dom_offsets = vec![0, 4, 5, 6, 7];
        let dom_targets = vec![0, 1, 2, 3, 1, 2, 3];
        let pred_offsets = vec![0, 0, 1, 2, 4];
        let pred_targets = vec![0, 0, 1, 2];
        let err = compute_dominance_frontier_via(
            &dispatcher,
            4,
            &dom_offsets,
            &dom_targets,
            &pred_offsets,
            &pred_targets,
            &[0b0010],
        )
        .expect_err("trailing frontier bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn release_via_path_does_not_call_cpu_or_local_saturating_helpers() {
        let source = include_str!("dominator_frontier.rs");
        let start = source
            .find("pub fn compute_dominance_frontier_via")
            .expect("via path marker must exist");
        let end = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must exist");
        let release_path = &source[start..end];
        assert!(!release_path.contains("reference_dominator_frontier"));
        assert!(!release_path.contains("reference_"));
        assert!(!release_path.contains("saturating_mul"));
        assert!(!release_path.contains("fill_"));
    }
}
