//! Region-graph bidirectional one-step reach substrate consumer.
//!
//! Wires `vyre_primitives::graph::csr_bidirectional` into the dispatch
//! path. One bidirectional BFS step is the right primitive when the
//! optimizer wants the "neighborhood" of a Region — both writers
//! (predecessors) and readers (successors) at once. Used by
//! alias-class merging and the buffer-residency planner.

#[cfg(test)]
use vyre_primitives::graph::csr_bidirectional::cpu_ref_closure as reference_csr_bidir_closure;
use vyre_primitives::graph::csr_bidirectional::csr_bidirectional as primitive_csr_bidirectional;
use vyre_primitives::graph::csr_bidirectional::merge_frontier_or_changed;
use vyre_primitives::graph::csr_bidirectional::validate_csr_inputs as validate_csr_bidirectional_inputs;
#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::csr_bidirectional::{
    cpu_ref as reference_csr_bidir,
    cpu_ref_closure_into_with_step_hook as reference_csr_bidir_closure_into_with_step_hook,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, u32_word_bytes, write_u32_slice_le_bytes,
    write_zero_bytes,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned GPU dispatch scratch for bidirectional CSR traversal.
#[derive(Debug, Default)]
pub struct BidirectionalGpuScratch {
    nodes: Vec<u32>,
    node_tags: Vec<u32>,
    edge_targets: Vec<u32>,
    edge_kind_mask: Vec<u32>,
    inputs: Vec<Vec<u8>>,
}

/// Compute one bidirectional BFS step over a CSR-encoded Region
/// graph: returns the bitset that includes every node reachable
/// in ≤1 forward edge OR ≤1 backward edge from `frontier_in`,
/// filtered by `allow_mask` over edge kinds.
///
/// `node_count` matches the bitset width; `edge_kind_mask` is
/// per-edge. Bumps the dataflow-fixpoint substrate counter so
/// observability picks up dispatch-time traffic.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_bidirectional_step(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Vec<u32> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    reference_csr_bidir(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
    )
}

/// Iterate `bidirectional_step` to fixpoint or `max_iters`. Returns
/// the connected-neighborhood bitset of `seed` under `allow_mask`.
/// Useful for alias-class queries (which Regions touch the same
/// buffer set transitively).
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_bidirectional_closure(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    reference_bidirectional_closure_into(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut current,
        &mut next,
    );
    current
}

/// Iterate `bidirectional_step` to fixpoint using caller-owned buffers.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_bidirectional_closure_into(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    reference_csr_bidir_closure_into_with_step_hook(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        current,
        next,
        || bump(&dataflow_fixpoint_calls),
    );
}

/// Dispatcher-backed bidirectional CSR step.
///
/// # Errors
///
/// Propagates dispatch failures and rejects malformed CSR/frontier
/// shapes or truncated readback.
pub fn bidirectional_step_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut out = Vec::new();
    bidirectional_step_via_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        &mut out,
    )?;
    Ok(out)
}

/// Dispatcher-backed bidirectional CSR step into caller-owned storage.
#[allow(clippy::too_many_arguments)]
pub fn bidirectional_step_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = BidirectionalGpuScratch::default();
    bidirectional_step_via_with_scratch_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
        allow_mask,
        &mut scratch,
        out,
    )
}

/// Dispatcher-backed bidirectional CSR step with caller-owned scratch.
#[allow(clippy::too_many_arguments)]
pub fn bidirectional_step_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier_in: &[u32],
    allow_mask: u32,
    scratch: &mut BidirectionalGpuScratch,
    out: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_csr_bidirectional_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier_in,
    )
    .map_err(DispatchError::BadInputs)?;
    if node_count == 0 {
        out.clear();
        return Ok(());
    }
    scratch.nodes.clear();
    scratch.nodes.resize(layout.node_words, 0);
    scratch.node_tags.clear();
    scratch.node_tags.resize(layout.node_words, 0);

    scratch.edge_targets.clear();
    scratch.edge_targets.extend_from_slice(edge_targets);
    scratch.edge_targets.resize(layout.edge_storage_words, 0);
    scratch.edge_kind_mask.clear();
    scratch.edge_kind_mask.extend_from_slice(edge_kind_mask);
    scratch.edge_kind_mask.resize(layout.edge_storage_words, 0);
    let program = primitive_csr_bidirectional(
        ProgramGraphShape::new(layout.node_count, layout.edge_count.max(1)),
        "frontier_in",
        "frontier_out",
        allow_mask,
    );
    let output_bytes = u32_word_bytes(layout.words, "bidirectional_step_via frontier")?;
    ensure_input_slots(&mut scratch.inputs, 7);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], &scratch.nodes);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], edge_offsets);
    write_u32_slice_le_bytes(&mut scratch.inputs[2], &scratch.edge_targets);
    write_u32_slice_le_bytes(&mut scratch.inputs[3], &scratch.edge_kind_mask);
    write_u32_slice_le_bytes(&mut scratch.inputs[4], &scratch.node_tags);
    write_u32_slice_le_bytes(&mut scratch.inputs[5], frontier_in);
    write_zero_bytes(&mut scratch.inputs[6], output_bytes);
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([node_count, 1, 1]))?;
    if outputs.len() != 1 {
        return Err(DispatchError::BackendError(format!(
            "Fix: bidirectional_step_via expected exactly one frontier_out output buffer, got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(
        &outputs[0],
        layout.words,
        "bidirectional_step_via frontier_out",
        out,
    )
}

/// Dispatcher-backed bidirectional closure.
///
/// # Errors
///
/// Propagates dispatch failures from each bidirectional step.
#[allow(clippy::too_many_arguments)]
pub fn bidirectional_closure_via(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    bidirectional_closure_via_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut current,
        &mut next,
    )?;
    Ok(current)
}

/// Dispatcher-backed bidirectional closure using caller-owned buffers.
#[allow(clippy::too_many_arguments)]
pub fn bidirectional_closure_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = BidirectionalGpuScratch::default();
    bidirectional_closure_via_with_scratch_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut scratch,
        current,
        next,
    )
}

/// Dispatcher-backed bidirectional closure with caller-owned dispatch scratch.
#[allow(clippy::too_many_arguments)]
pub fn bidirectional_closure_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    scratch: &mut BidirectionalGpuScratch,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    current.clear();
    current.extend_from_slice(seed);
    next.clear();
    for _ in 0..max_iters {
        bidirectional_step_via_with_scratch_into(
            dispatcher,
            node_count,
            edge_offsets,
            edge_targets,
            edge_kind_mask,
            current,
            allow_mask,
            scratch,
            next,
        )?;
        if !merge_frontier_or_changed(current, next) {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

    struct BidirDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for BidirDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([4, 1, 1]));
            if inputs.len() != 7 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: bidirectional test dispatcher expected 7 inputs, got {}.",
                    inputs.len()
                )));
            }
            Ok(self.outputs.clone())
        }
    }

    fn linear_graph() -> (Vec<u32>, Vec<u32>, Vec<u32>) {
        // 0 -> 1 -> 2 -> 3
        (vec![0, 1, 2, 3, 3], vec![1, 2, 3], vec![1, 1, 1])
    }

    #[test]
    fn step_includes_forward_and_backward_neighbors() {
        let (off, tgt, msk) = linear_graph();
        // Seed = {1}. Forward = {2}, backward = {0}. Union ⊇ {0, 2}.
        let out = reference_bidirectional_step(4, &off, &tgt, &msk, &[0b0010], 0xFFFF_FFFF);
        assert!(out[0] & 0b0001 != 0, "0 should be in backward step from 1");
        assert!(out[0] & 0b0100 != 0, "2 should be in forward step from 1");
    }

    #[test]
    fn empty_seed_yields_empty_step() {
        let (off, tgt, msk) = linear_graph();
        let out = reference_bidirectional_step(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF);
        assert_eq!(out, vec![0u32]);
    }

    /// Closure-bar: substrate call equals direct primitive call.
    #[test]
    fn matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = vec![0b0010];
        let via_substrate = reference_bidirectional_step(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        let via_primitive = reference_csr_bidir(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        assert_eq!(via_substrate, via_primitive);
    }

    /// Adversarial: kind-mask filter must reject edges whose kinds
    /// don't intersect `allow_mask`. The bidirectional step is a
    /// pure successor/predecessor union; with no matching edges,
    /// no neighbors are flagged (the primitive does not retain
    /// the seed in its output).
    #[test]
    fn allow_mask_filters_out_wrong_edge_kinds() {
        let off = vec![0, 1, 1];
        let tgt = vec![1];
        let msk = vec![0b0010]; // edge kind bit 1
        let out = reference_bidirectional_step(2, &off, &tgt, &msk, &[0b01], 0b0001);
        let direct = reference_csr_bidir(2, &off, &tgt, &msk, &[0b01], 0b0001);
        // Substrate output must match primitive directly.
        assert_eq!(out, direct);
        // And bit 1 (would-be neighbor via a kind-0 edge that doesn't
        // exist) must NOT be set in the result.
        assert_eq!(out[0] & 0b10, 0);
    }

    /// bidirectional_closure on a linear chain {0 -> 1 -> 2 -> 3} with
    /// seed {0} must reach every node within 3 iterations.
    #[test]
    fn closure_reaches_full_chain() {
        let (off, tgt, msk) = linear_graph();
        let out = reference_bidirectional_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        assert_eq!(out, vec![0b1111]);
    }

    #[test]
    fn closure_into_matches_owned_closure() {
        let (off, tgt, msk) = linear_graph();
        let owned = reference_bidirectional_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        let mut current = Vec::new();
        let mut next = Vec::new();
        reference_bidirectional_closure_into(
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            5,
            &mut current,
            &mut next,
        );
        assert_eq!(current, owned);
    }

    #[test]
    fn closure_matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = [0b0001];
        let via_substrate =
            reference_bidirectional_closure(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
        let via_primitive = reference_csr_bidir_closure(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF, 5);
        assert_eq!(via_substrate, via_primitive);
    }

    #[test]
    fn via_step_decodes_exact_output_into_reused_buffer() {
        let dispatcher = BidirDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1010])],
        };
        let (off, tgt, msk) = linear_graph();
        let mut out = Vec::with_capacity(4);
        let ptr = out.as_ptr();
        bidirectional_step_via_into(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0010],
            0xFFFF_FFFF,
            &mut out,
        )
        .expect("dispatch succeeds");
        assert_eq!(out, vec![0b1010]);
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn via_step_with_scratch_reuses_dispatch_storage() {
        let dispatcher = BidirDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1010])],
        };
        let (off, tgt, msk) = linear_graph();
        let mut scratch = BidirectionalGpuScratch::default();
        let mut out = Vec::with_capacity(1);

        bidirectional_step_via_with_scratch_into(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0010],
            0xFFFF_FFFF,
            &mut scratch,
            &mut out,
        )
        .expect("dispatch succeeds");
        assert_eq!(out, vec![0b1010]);
        let node_capacity = scratch.nodes.capacity();
        let target_capacity = scratch.edge_targets.capacity();
        let input_capacities = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let out_capacity = out.capacity();

        bidirectional_step_via_with_scratch_into(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0100],
            0xFFFF_FFFF,
            &mut scratch,
            &mut out,
        )
        .expect("dispatch succeeds");
        assert_eq!(scratch.nodes.capacity(), node_capacity);
        assert_eq!(scratch.edge_targets.capacity(), target_capacity);
        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_capacities
        );
        assert_eq!(out.capacity(), out_capacity);
        assert_eq!(out, vec![0b1010]);
    }

    #[test]
    fn via_step_rejects_extra_outputs() {
        let dispatcher = BidirDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1010]),
                u32_slice_to_le_bytes(&[0]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let err = bidirectional_step_via(&dispatcher, 4, &off, &tgt, &msk, &[0b0010], 0xFFFF_FFFF)
            .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_step_rejects_trailing_output_bytes() {
        let dispatcher = BidirDispatcher {
            outputs: vec![vec![0, 0, 0, 0, 1]],
        };
        let (off, tgt, msk) = linear_graph();
        let err = bidirectional_step_via(&dispatcher, 4, &off, &tgt, &msk, &[0b0010], 0xFFFF_FFFF)
            .expect_err("trailing output bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn via_step_rejects_mismatched_edge_arrays() {
        let dispatcher = BidirDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1010])],
        };
        let err =
            bidirectional_step_via(&dispatcher, 2, &[0, 1, 1], &[1], &[], &[0b01], 0xFFFF_FFFF)
                .expect_err("mismatched edge arrays must be rejected");
        assert!(matches!(err, DispatchError::BadInputs(_)));
    }

    #[test]
    fn via_step_empty_graph_is_validated_by_primitive_and_does_not_dispatch() {
        struct NoDispatch;

        impl OptimizerDispatcher for NoDispatch {
            fn dispatch(
                &self,
                _program: &Program,
                _inputs: &[Vec<u8>],
                _grid_override: Option<[u32; 3]>,
            ) -> Result<Vec<Vec<u8>>, DispatchError> {
                panic!("empty bidirectional graph must not dispatch");
            }
        }

        let mut out = vec![u32::MAX];
        bidirectional_step_via_into(&NoDispatch, 0, &[0], &[], &[], &[], u32::MAX, &mut out)
            .expect("canonical empty graph is valid");
        assert!(out.is_empty());
    }

    #[test]
    fn release_via_path_does_not_call_cpu_or_local_saturating_helpers() {
        let source = include_str!("csr_bidirectional.rs");
        let start = source
            .find("pub fn bidirectional_step_via")
            .expect("via path marker must exist");
        let end = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must exist");
        let release_path = &source[start..end];
        assert!(!release_path.contains("reference_csr_bidir"));
        assert!(!release_path.contains("reference_"));
        assert!(!release_path.contains("saturating_mul"));
        assert!(!release_path.contains("fill_"));
        assert!(!release_path.contains("fn merge_frontier_or_changed"));
    }

    /// Adversarial: closure on disjoint components must not bridge
    /// across components. Seed in component A must not flag B.
    #[test]
    fn closure_does_not_bridge_disjoint_components() {
        // Two-component CSR: 0 -> 1, 2 -> 3 (disjoint).
        let off = vec![0, 1, 1, 2, 2];
        let tgt = vec![1, 3];
        let msk = vec![1, 1];
        let out = reference_bidirectional_closure(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 5);
        // Reaches {0, 1} only.
        assert_eq!(out, vec![0b0011]);
    }

    /// Idempotence: running the step on a saturated bitset returns
    /// the same bitset.
    #[test]
    fn closure_is_idempotent_at_fixpoint() {
        let (off, tgt, msk) = linear_graph();
        let saturated = vec![0b1111];
        let out = reference_bidirectional_step(4, &off, &tgt, &msk, &saturated, 0xFFFF_FFFF);
        // Bidirectional step from saturated set keeps everything set.
        assert_eq!(out, saturated);
    }
}
