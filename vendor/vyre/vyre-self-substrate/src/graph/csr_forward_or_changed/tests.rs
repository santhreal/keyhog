use super::*;
use crate::dispatch_buffers::u32_slice_to_le_bytes;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};
use std::sync::Mutex;
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
        if inputs.len() != 7 && inputs.len() != 8 {
            return Err(DispatchError::BadInputs(format!(
                "Fix: csr_forward_or_changed test dispatcher expected 7 legacy inputs or 8 changed-history inputs, got {}.",
                inputs.len()
            )));
        }
        Ok(self.outputs.clone())
    }
}

struct RecordingCsrChangedDispatcher {
    outputs: Vec<Vec<u8>>,
    frontier_inputs: Mutex<Vec<Vec<u32>>>,
}

impl OptimizerDispatcher for RecordingCsrChangedDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        self.frontier_inputs
            .lock()
            .expect("Fix: frontier recording mutex should not be poisoned")
            .push(crate::hardware::dispatch_buffers::read_u32s(&inputs[5]));
        Ok(self.outputs.clone())
    }
}

struct StaticCsrInputRecordingDispatcher {
    outputs: Vec<Vec<u8>>,
    edge_targets: Mutex<Vec<Vec<u32>>>,
}

impl OptimizerDispatcher for StaticCsrInputRecordingDispatcher {
    fn dispatch(
        &self,
        _program: &Program,
        inputs: &[Vec<u8>],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        self.edge_targets
            .lock()
            .expect("Fix: static input recording mutex should not be poisoned")
            .push(crate::hardware::dispatch_buffers::read_u32s(&inputs[2]));
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
    let out =
        reference_forward_closure_via_change_flag(4, &off, &tgt, &msk, &[0b0001], 0xFFFF_FFFF, 10);
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
    let out =
        reference_forward_closure_via_change_flag(2, &off, &tgt, &msk, &[0b01], 0xFFFF_FFFF, 50);
    // Self-loop never adds new bits → terminates immediately.
    assert_eq!(out, vec![0b01]);
}

#[test]
fn gpu_into_decodes_exact_outputs_into_reused_frontier() {
    let dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[0, 0, 0, 0]),
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
    .expect("Fix: dispatch succeeds");
    assert_eq!(frontier, vec![0b1111]);
    assert_eq!(frontier.as_ptr(), ptr);
}

#[test]
fn gpu_rejects_extra_outputs() {
    let dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[0, 0, 0, 0]),
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
fn gpu_rejects_non_boolean_changed_flag() {
    let dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[2]),
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
        1,
    )
    .expect_err("non-boolean changed flag must be rejected");
    assert!(
        matches!(err, DispatchError::BackendError(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn gpu_rejects_bad_seed_width_without_clobbering_frontier() {
    struct NoDispatch;

    impl OptimizerDispatcher for NoDispatch {
        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            panic!("bad seed width must be rejected before dispatch");
        }
    }

    let (off, tgt, msk) = linear_graph();
    let mut scratch = ForwardChangedGpuScratch::default();
    let mut frontier = vec![0xCAFE_BABEu32];
    let capacity = frontier.capacity();

    let err = forward_closure_via_change_flag_gpu_with_scratch_into(
        &NoDispatch,
        4,
        &off,
        &tgt,
        &msk,
        &[],
        0xFFFF_FFFF,
        5,
        &mut scratch,
        &mut frontier,
    )
    .expect_err("bad seed width must be rejected before mutating reusable frontier storage");

    assert!(matches!(err, DispatchError::BadInputs(_)));
    assert_eq!(frontier, vec![0xCAFE_BABEu32]);
    assert_eq!(frontier.capacity(), capacity);
    assert!(scratch.inputs.is_empty());
    assert_eq!(scratch.program_builds(), 0);
}

#[test]
fn gpu_reuses_dispatch_input_buffers() {
    let dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[0, 0, 0, 0]),
        ],
    };
    let (off, tgt, msk) = linear_graph();
    let mut scratch =
        ForwardChangedGpuScratch::with_input_capacities(&[32, 32, 32, 32, 32, 32, 32, 8], 1);
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
fn gpu_refreshes_static_inputs_when_same_shape_graph_content_changes() {
    let dispatcher = StaticCsrInputRecordingDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b0001]),
            u32_slice_to_le_bytes(&[0]),
        ],
        edge_targets: Mutex::new(Vec::new()),
    };
    let edge_offsets = vec![0, 1, 2, 3, 3];
    let first_targets = vec![1, 2, 3];
    let second_targets = vec![2, 3, 0];
    let edge_kind_mask = vec![1, 1, 1];
    let mut scratch = ForwardChangedGpuScratch::default();
    let mut frontier = Vec::new();

    forward_closure_via_change_flag_gpu_with_scratch_into(
        &dispatcher,
        4,
        &edge_offsets,
        &first_targets,
        &edge_kind_mask,
        &[0b0001],
        0xFFFF_FFFF,
        1,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: first same-shape dispatch should succeed");
    forward_closure_via_change_flag_gpu_with_scratch_into(
        &dispatcher,
        4,
        &edge_offsets,
        &second_targets,
        &edge_kind_mask,
        &[0b0001],
        0xFFFF_FFFF,
        1,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: second same-shape dispatch should refresh static CSR inputs");

    let recorded_targets = dispatcher
        .edge_targets
        .lock()
        .expect("Fix: static input recording mutex should not be poisoned");
    assert_eq!(
        recorded_targets.as_slice(),
        &[first_targets, second_targets]
    );
    assert_eq!(
        scratch.program_builds(),
        1,
        "Fix: same-shape graph content changes should refresh staged static inputs without rebuilding the primitive program."
    );
}

#[test]
fn gpu_reuses_cached_program_by_primitive_key() {
    let history_dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[0, 0, 0, 0]),
        ],
    };
    let legacy_dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[0]),
        ],
    };
    let (off, tgt, msk) = linear_graph();
    let mut scratch = ForwardChangedGpuScratch::default();
    let mut frontier = Vec::new();

    forward_closure_via_change_flag_gpu_with_scratch_into(
        &history_dispatcher,
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
    .expect("Fix: first changed-history dispatch should build one program");
    assert_eq!(scratch.program_builds(), 1);

    forward_closure_via_change_flag_gpu_with_scratch_into(
        &history_dispatcher,
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
    .expect("Fix: identical primitive key should reuse the cached program");
    assert_eq!(scratch.program_builds(), 1);

    forward_closure_via_change_flag_gpu_with_scratch_into(
        &history_dispatcher,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0001],
        0b0001,
        4,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: changed allow mask should rebuild the primitive program");
    assert_eq!(scratch.program_builds(), 2);

    forward_closure_via_change_flag_gpu_with_scratch_into(
        &legacy_dispatcher,
        4,
        &off,
        &tgt,
        &msk,
        &[0b0001],
        0b0001,
        65,
        &mut scratch,
        &mut frontier,
    )
    .expect("Fix: switching changed-history policy should rebuild the program");
    assert_eq!(scratch.program_builds(), 3);
}

#[test]

fn gpu_rejects_mismatched_edge_arrays() {
    let dispatcher = CsrChangedDispatcher {
        outputs: vec![
            u32_slice_to_le_bytes(&[0b1111]),
            u32_slice_to_le_bytes(&[0, 0, 0, 0]),
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
    let release_path = include_str!("dispatch.rs");
    assert!(!release_path.contains("csr_foc_cpu"));
    assert!(!release_path.contains("reference_"));
    assert!(!release_path.contains("saturating_mul"));
    assert!(!release_path.contains("fill_"));
    assert!(!release_path.contains("Vec::with_capacity"));
    assert!(release_path.contains("reserve_graph_vec"));
    assert!(release_path.contains("copy_csr_forward_seed_frontier_into"));
    assert!(!release_path.contains("fn reserve_forward_changed_vec"));
}

#[test]
fn release_gpu_path_uses_primitive_owned_static_input_key_and_changed_flag_validation() {
    let release_path = include_str!("dispatch.rs");

    assert!(release_path.contains("CsrForwardOrChangedStaticInputKey"));
    assert!(release_path.contains(".static_input_key(edge_offsets, edge_targets, edge_kind_mask)"));
    assert!(release_path.contains("validate_csr_forward_or_changed_flag"));
    assert!(!release_path.contains("struct ForwardChangedStaticInputKey"));
    assert!(!release_path.contains("fingerprint_u32_slice"));
    assert!(!release_path.contains("U32SliceFingerprint"));
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

#[test]
fn release_gpu_path_uses_parallel_primitive_and_node_grid() {
    let release_path = include_str!("dispatch.rs");

    assert!(
        release_path.contains("plan_csr_forward_or_changed_launch"),
        "Fix: CSR forward closure GPU path must use the primitive-owned launch plan."
    );
    assert!(
        !release_path.contains("plan_csr_forward_or_changed_dispatch"),
        "Fix: CSR forward closure GPU path must not rebuild an eager primitive dispatch plan when scratch caching is available."
    );
    assert!(
        !release_path.contains("let program = csr_forward_or_changed("),
        "Fix: CSR forward closure GPU path must not dispatch the serial single-invocation primitive."
    );
    assert!(
        release_path.contains("Some(plan.dispatch_grid())"),
        "Fix: CSR forward closure GPU path must launch with the primitive-owned node grid."
    );
    let program_build = release_path
        .find("program_cache.get_or_try_insert_with(")
        .expect(
        "Fix: CSR forward closure GPU path must populate the shared primitive program cache once.",
    );
    let loop_start = release_path
        .find("for iter in 0..max_iters")
        .expect("Fix: CSR forward closure GPU path must have an iteration loop.");
    assert!(
        program_build < loop_start,
        "Fix: CSR forward closure GPU path must cache the primitive program before the fixpoint loop."
    );
    assert!(
        !release_path[loop_start..].contains("plan.program()"),
        "Fix: CSR forward closure GPU path must not rebuild the primitive program on every fixpoint iteration."
    );
}

#[test]
fn release_gpu_path_uses_changed_history_for_short_fixpoints() {
    let release_path = include_str!("dispatch.rs");
    // The primitive was split into submodules (LAW7 module splits); the
    // dispatch plan, dynamic-slot kernel, and fast-path threshold now live
    // in plan.rs / program_parallel_batch_global.rs / layout.rs.
    let primitive_source = concat!(
        include_str!("../../../../vyre-primitives/src/graph/csr_forward_or_changed/plan.rs"),
        include_str!(
            "../../../../vyre-primitives/src/graph/csr_forward_or_changed/program_parallel_batch_global.rs"
        ),
        include_str!("../../../../vyre-primitives/src/graph/csr_forward_or_changed/layout.rs"),
    );

    assert!(
        primitive_source.contains("pub fn plan_csr_forward_or_changed_dispatch")
            && primitive_source
                .contains("try_csr_forward_or_changed_parallel_batch_global_dynamic_slot"),
        "Fix: short CSR fixpoint loops must use the primitive dynamic changed-slot kernel through the plan."
    );
    assert!(
        primitive_source.contains("CSR_FORWARD_OR_CHANGED_HISTORY_FAST_PATH_MAX_ITERS"),
        "Fix: changed-history readback must be bounded by a release-path threshold."
    );
    assert!(
        release_path.contains("changed history scratch")
            && release_path.contains("plan.changed_slot_value(iter)")
            && release_path.contains(".changed_read_index(iter)"),
        "Fix: changed history must be zeroed once and advanced/read through primitive-owned iteration policy."
    );
}

#[test]
fn generated_gpu_seed_copy_bounds_to_primitive_frontier_words() {
    for node_count in 1u32..=512 {
        let frontier_words = node_count.div_ceil(32) as usize;
        let edge_offsets = vec![0; node_count as usize + 1];
        for extra_words in 0..8usize {
            let seed_len = frontier_words + extra_words;
            let seed = (0..seed_len)
                .map(|idx| 0xA5A5_0000u32 ^ idx as u32 ^ node_count)
                .collect::<Vec<_>>();
            let dispatcher = RecordingCsrChangedDispatcher {
                outputs: vec![
                    u32_slice_to_le_bytes(&vec![0; frontier_words]),
                    u32_slice_to_le_bytes(&[0]),
                ],
                frontier_inputs: Mutex::new(Vec::new()),
            };
            let mut frontier = Vec::new();

            let result = forward_closure_via_change_flag_gpu_into(
                &dispatcher,
                node_count,
                &edge_offsets,
                &[],
                &[],
                &seed,
                0xFFFF_FFFF,
                1,
                &mut frontier,
            );

            if extra_words == 0 {
                result.expect("Fix: exact-width empty-edge generated CSR closure should dispatch");
                let observed = dispatcher
                    .frontier_inputs
                    .lock()
                    .expect("Fix: frontier recording mutex should not be poisoned");
                assert_eq!(
                    observed.len(),
                    1,
                    "node_count={node_count} extra_words={extra_words}"
                );
                assert_eq!(
                    observed[0],
                    seed[..frontier_words],
                    "node_count={node_count} extra_words={extra_words}"
                );
            } else {
                let err = result.expect_err(
                    "Fix: oversized generated seed must be rejected instead of silently truncated",
                );
                assert!(
                    matches!(err, DispatchError::BadInputs(_)),
                    "node_count={node_count} extra_words={extra_words} err={err:?}"
                );
                let observed = dispatcher
                    .frontier_inputs
                    .lock()
                    .expect("Fix: frontier recording mutex should not be poisoned");
                assert!(
                    observed.is_empty(),
                    "node_count={node_count} extra_words={extra_words}"
                );
            }
        }
    }
}

