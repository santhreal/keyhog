//! In-place expand-with-change-flag substrate consumer.
//!
//! Wires `vyre_primitives::graph::csr_forward_or_changed` so iterative
//! dataflow loops can detect convergence in a single pass: the primitive returns the next
//! frontier AND a boolean changed-flag. Used by reachability /
//! liveness / reaching-defs fixpoint passes that previously had to
//! diff before/after states by hand.

use vyre_primitives::graph::csr_forward_or_changed::csr_forward_or_changed;
#[cfg(not(any(test, feature = "cpu-parity")))]
use vyre_primitives::graph::csr_forward_or_changed::validate_csr_inputs as validate_csr_forward_or_changed_inputs;
#[cfg(any(test, feature = "cpu-parity"))]
use vyre_primitives::graph::csr_forward_or_changed::{
    cpu_ref as csr_foc_cpu,
    cpu_ref_closure_into_with_step_hook as csr_foc_closure_into_with_step_hook,
    validate_csr_inputs as validate_csr_forward_or_changed_inputs,
};
use vyre_primitives::graph::program_graph::ProgramGraphShape;

use crate::dispatch_buffers::{
    decode_u32_output_exact, ensure_input_slots, write_u32_slice_le_bytes,
    write_u32_slice_or_zero_words, write_zero_u32_words,
};
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned GPU dispatch scratch for `csr_forward_or_changed` fixpoint loops.
#[derive(Debug, Default)]
pub struct ForwardChangedGpuScratch {
    inputs: Vec<Vec<u8>>,
    changed_out: Vec<u32>,
}

/// Run one in-place forward-expand step over the CSR graph and
/// return both the new frontier and a 0/1 changed flag. The
/// primitive's contract: bits added to the frontier flip the flag;
/// no new bits → flag stays 0 → caller's fixpoint loop terminates.
///
/// Bumps the dataflow-fixpoint substrate counter so observability
/// logs every change-detection step.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_forward_step_with_change_flag(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    frontier: &[u32],
    allow_mask: u32,
) -> (Vec<u32>, u32) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    csr_foc_cpu(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        frontier,
        allow_mask,
    )
}

/// Iterate `forward_step_with_change_flag` until the change flag
/// reads 0 or `max_iters` is reached. Returns the saturated
/// frontier.
///
/// This is the substrate path for "expand a Region set to its
/// forward-reachable closure" — the same fixpoint loop the
/// optimizer used to write by hand, now driven by the primitive's
/// own change flag.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_forward_closure_via_change_flag(
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Vec<u32> {
    let mut current = Vec::with_capacity(seed.len());
    let mut next = Vec::with_capacity(seed.len());
    reference_forward_closure_via_change_flag_into(
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

/// Iterate `forward_step_with_change_flag` using caller-owned scratch.
#[allow(clippy::too_many_arguments)]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_forward_closure_via_change_flag_into(
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
    csr_foc_closure_into_with_step_hook(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        current,
        next,
        |_| bump(&dataflow_fixpoint_calls),
    );
}

/// Dispatcher-backed closure: build the `csr_forward_or_changed` Program once,
/// then iterate dispatch + read the `changed` flag to detect fixpoint.
/// Terminates when no new bits land in the frontier or after `max_iters`.
/// Returns the saturated frontier.
///
/// Uses the supplied `OptimizerDispatcher` so callers can swap CUDA /
/// WGPU / reference backends without touching this layer.
///
/// # Errors
///
/// Propagates any [`DispatchError`] surfaced by the dispatcher.
#[allow(clippy::too_many_arguments)]
pub fn forward_closure_via_change_flag_gpu(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut frontier = Vec::with_capacity(seed.len().max(1));
    forward_closure_via_change_flag_gpu_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut frontier,
    )?;
    Ok(frontier)
}

/// Dispatcher-backed closure into caller-owned storage.
#[allow(clippy::too_many_arguments)]
pub fn forward_closure_via_change_flag_gpu_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    frontier: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = ForwardChangedGpuScratch::default();
    forward_closure_via_change_flag_gpu_with_scratch_into(
        dispatcher,
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
        seed,
        allow_mask,
        max_iters,
        &mut scratch,
        frontier,
    )
}

/// Dispatcher-backed closure using caller-owned dispatch scratch for the seven
/// input slots and changed flag.
#[allow(clippy::too_many_arguments)]
pub fn forward_closure_via_change_flag_gpu_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    node_count: u32,
    edge_offsets: &[u32],
    edge_targets: &[u32],
    edge_kind_mask: &[u32],
    seed: &[u32],
    allow_mask: u32,
    max_iters: u32,
    scratch: &mut ForwardChangedGpuScratch,
    frontier: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let layout = validate_csr_forward_or_changed_inputs(
        node_count,
        edge_offsets,
        edge_targets,
        edge_kind_mask,
    )
    .map_err(DispatchError::BadInputs)?;
    let shape = ProgramGraphShape::new(layout.node_count, layout.shape_edge_count);
    let program = csr_forward_or_changed(shape, "frontier_out", "changed", allow_mask);

    ensure_input_slots(&mut scratch.inputs, 7);
    write_zero_u32_words(
        &mut scratch.inputs[0],
        layout.node_words,
        "csr_forward_or_changed source scratch",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[1],
        edge_offsets,
        layout.edge_offset_words,
        "csr_forward_or_changed edge_offsets",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[2],
        edge_targets,
        layout.edge_storage_words,
        "csr_forward_or_changed edge_targets",
    )?;
    write_u32_slice_or_zero_words(
        &mut scratch.inputs[3],
        edge_kind_mask,
        layout.edge_storage_words,
        "csr_forward_or_changed edge_kind_mask",
    )?;
    write_zero_u32_words(
        &mut scratch.inputs[4],
        layout.node_words,
        "csr_forward_or_changed frontier seed scratch",
    )?;
    write_zero_u32_words(
        &mut scratch.inputs[6],
        1,
        "csr_forward_or_changed changed scratch",
    )?;

    frontier.clear();
    frontier.extend_from_slice(seed);
    frontier.resize(layout.frontier_words, 0);

    for _ in 0..max_iters {
        use crate::observability::{bump, dataflow_fixpoint_calls};
        bump(&dataflow_fixpoint_calls);

        write_u32_slice_le_bytes(&mut scratch.inputs[5], frontier);
        let outputs = dispatcher.dispatch(&program, &scratch.inputs, None)?;
        if outputs.len() != 2 {
            return Err(DispatchError::BackendError(format!(
                "Fix: csr_forward_or_changed dispatch expected exactly two outputs (frontier_out, changed), got {}.",
                outputs.len()
            )));
        }
        decode_u32_output_exact(
            &outputs[0],
            layout.frontier_words,
            "csr_forward_or_changed frontier_out",
            frontier,
        )?;
        decode_u32_output_exact(
            &outputs[1],
            1,
            "csr_forward_or_changed changed",
            &mut scratch.changed_out,
        )?;
        if scratch.changed_out[0] == 0 {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use vyre_foundation::ir::Program;

    struct CsrChangedDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for CsrChangedDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            if inputs.len() != 7 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: csr_forward_or_changed test dispatcher expected 7 inputs, got {}.",
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
    fn step_flips_change_flag_when_new_bits_added() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) =
            reference_forward_step_with_change_flag(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF);
        // Seed {0} expands to {0, 1}. New bit added → flag = 1.
        assert!(out[0] & 0b0010 != 0, "1 must be in expanded frontier");
        assert_eq!(changed, 1, "change flag must flip on new bit");
    }

    #[test]
    fn step_clears_change_flag_at_fixpoint() {
        let (off, tgt, msk) = linear_graph();
        // Saturated frontier: every node already set.
        let (_out, changed) =
            reference_forward_step_with_change_flag(4, &off, &tgt, &msk, &[0b1111], 0xFFFF_FFFF);
        assert_eq!(changed, 0, "no new bits → flag stays 0");
    }

    /// Closure-bar: substrate output equals primitive output exactly.
    #[test]
    fn matches_primitive_directly() {
        let (off, tgt, msk) = linear_graph();
        let seed = vec![0b0001];
        let via_substrate =
            reference_forward_step_with_change_flag(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        let via_primitive = csr_foc_cpu(4, &off, &tgt, &msk, &seed, 0xFFFF_FFFF);
        assert_eq!(via_substrate, via_primitive);
    }

    /// forward_closure_via_change_flag terminates at fixpoint and
    /// returns the full forward closure. On a chain 0->1->2->3
    /// from {0} → final = {0,1,2,3}.
    #[test]
    fn closure_reaches_full_chain_via_change_flag() {
        let (off, tgt, msk) = linear_graph();
        let out = reference_forward_closure_via_change_flag(
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            10,
        );
        assert_eq!(out, vec![0b1111]);
    }

    /// Adversarial: empty seed must yield empty closure with flag 0
    /// on the first iteration (no work).
    #[test]
    fn empty_seed_yields_empty_closure_no_change() {
        let (off, tgt, msk) = linear_graph();
        let (out, changed) =
            reference_forward_step_with_change_flag(4, &off, &tgt, &msk, &[0u32], 0xFFFF_FFFF);
        assert_eq!(out, vec![0u32]);
        assert_eq!(changed, 0);
    }

    /// Adversarial: closure must terminate before max_iters even on
    /// a graph with a self-loop (the change flag is the only
    /// termination signal we trust).
    #[test]
    fn closure_terminates_with_self_loop_under_max_iters() {
        // 0 -> 0 (self-loop), 1 isolated.
        let off = vec![0, 1, 1];
        let tgt = vec![0];
        let msk = vec![1];
        let out = reference_forward_closure_via_change_flag(
            2,
            &off,
            &tgt,
            &msk,
            &[0b01],
            0xFFFF_FFFF,
            50,
        );
        // Self-loop never adds new bits → terminates immediately.
        assert_eq!(out, vec![0b01]);
    }

    #[test]
    fn gpu_into_decodes_exact_outputs_into_reused_frontier() {
        let dispatcher = CsrChangedDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[0]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let mut frontier = Vec::with_capacity(4);
        let ptr = frontier.as_ptr();
        forward_closure_via_change_flag_gpu_into(
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
        assert_eq!(frontier.as_ptr(), ptr);
    }

    #[test]
    fn gpu_rejects_extra_outputs() {
        let dispatcher = CsrChangedDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[0]),
                u32_slice_to_le_bytes(&[99]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let err = forward_closure_via_change_flag_gpu(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            4,
        )
        .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn gpu_rejects_trailing_changed_bytes() {
        let dispatcher = CsrChangedDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[0b1111]), vec![0, 0, 0, 0, 1]],
        };
        let (off, tgt, msk) = linear_graph();
        let err = forward_closure_via_change_flag_gpu(
            &dispatcher,
            4,
            &off,
            &tgt,
            &msk,
            &[0b0001],
            0xFFFF_FFFF,
            4,
        )
        .expect_err("trailing changed bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn gpu_reuses_dispatch_input_buffers() {
        let dispatcher = CsrChangedDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[0]),
            ],
        };
        let (off, tgt, msk) = linear_graph();
        let mut scratch = ForwardChangedGpuScratch {
            inputs: vec![
                Vec::with_capacity(32),
                Vec::with_capacity(32),
                Vec::with_capacity(32),
                Vec::with_capacity(32),
                Vec::with_capacity(32),
                Vec::with_capacity(32),
                Vec::with_capacity(32),
            ],
            changed_out: Vec::with_capacity(1),
        };
        let mut frontier = Vec::with_capacity(4);
        let input_caps = scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>();
        let frontier_ptr = frontier.as_ptr();
        forward_closure_via_change_flag_gpu_with_scratch_into(
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
        .unwrap();
        assert_eq!(
            scratch.inputs.iter().map(Vec::capacity).collect::<Vec<_>>(),
            input_caps
        );
        assert_eq!(frontier.as_ptr(), frontier_ptr);
        assert_eq!(frontier, vec![0b1111]);
    }

    #[test]
    fn gpu_rejects_mismatched_edge_arrays() {
        let dispatcher = CsrChangedDispatcher {
            outputs: vec![
                u32_slice_to_le_bytes(&[0b1111]),
                u32_slice_to_le_bytes(&[0]),
            ],
        };
        let err = forward_closure_via_change_flag_gpu(
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
    fn release_gpu_path_does_not_call_cpu_or_local_saturating_helpers() {
        let source = include_str!("csr_forward_or_changed.rs");
        let start = source
            .find("pub fn forward_closure_via_change_flag_gpu")
            .expect("gpu path marker must exist");
        let end = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must exist");
        let release_path = &source[start..end];
        assert!(!release_path.contains("csr_foc_cpu"));
        assert!(!release_path.contains("reference_"));
        assert!(!release_path.contains("saturating_mul"));
        assert!(!release_path.contains("fill_"));
    }

    /// Adversarial: allow_mask filtering. Edges of the wrong kind
    /// must not propagate; the change flag must register no change.
    #[test]
    fn allow_mask_filters_step() {
        let off = vec![0, 1, 1];
        let tgt = vec![1];
        let msk = vec![0b0010]; // kind bit 1
        let (out, changed) = reference_forward_step_with_change_flag(
            2,
            &off,
            &tgt,
            &msk,
            &[0b01],
            0b0001, // demand kind 0
        );
        // No matching edges → frontier unchanged from seed, no change.
        assert_eq!(out[0] & 0b10, 0);
        assert_eq!(changed, 0);
    }
}
