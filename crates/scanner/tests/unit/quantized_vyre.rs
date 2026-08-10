use std::sync::Arc;

use crate::confidence::quantized::{
    model, QuantizedConfidenceError, QuantizedFeatureRow, MAX_CANDIDATES_PER_BATCH,
};
use crate::confidence::quantized_vyre::{
    build_program, decode_outputs, submit_rows, PendingQuantizedScores, RESULT_STRIDE,
};
use crate::ml_scorer::model_arch::INPUT_DIM;

fn empty_output(capacity: usize) -> Vec<Vec<u8>> {
    vec![vec![
        0;
        capacity * RESULT_STRIDE * std::mem::size_of::<i32>()
    ]]
}

#[test]
fn output_decoder_rejects_layout_and_score_overflow() {
    assert!(matches!(
        decode_outputs(&[vec![0; 4]], 1, 1),
        Err(QuantizedConfidenceError::BackendFailure(_))
    ));
    let valid = empty_output(1);
    let decoded = decode_outputs(&valid, 1, 1).expect("complete scorer output");
    assert_eq!(decoded[0].candidate_id, 0);
    assert_eq!(decoded[0].score.0, 0);

    let mut overflow = valid.clone();
    overflow[0][4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        decode_outputs(&overflow, 1, 1),
        Err(QuantizedConfidenceError::BackendFailure(_))
    ));

    assert!(matches!(
        decode_outputs(&empty_output(1), 2, 1),
        Err(QuantizedConfidenceError::BackendFailure(_))
    ));
}

/// WHY: expression-tree accumulation recursively duplicated every preceding MAC
/// during WGSL lowering, producing a 114 MB shader that no backend could compile.
/// Bounded IR loops keep every model member in one score dispatch without source
/// expansion; live backend gates prove compilation and bit-exact arithmetic.
#[test]
fn quantized_scorer_ir_is_bounded_and_valid() {
    let program = build_program(MAX_CANDIDATES_PER_BATCH).expect("bounded scorer program");
    program.validate().expect("valid scorer IR");
    let stats = program.stats();
    assert!(
        stats.has_node_loop(),
        "dense layers must remain bounded loops"
    );
    assert!(
        stats.node_count <= 64,
        "quantized scorer expanded to {} statement nodes",
        stats.node_count
    );
    assert!(
        stats.instruction_count <= 1_000,
        "quantized scorer expanded to {} estimated instructions",
        stats.instruction_count
    );
    assert_eq!(
        RESULT_STRIDE, 63,
        "the per-candidate scratch layout changed without an explicit memory decision"
    );
}

fn feature_bound_rows() -> Vec<QuantizedFeatureRow> {
    let mut rows = vec![
        QuantizedFeatureRow([0; INPUT_DIM]),
        QuantizedFeatureRow([i16::MAX; INPUT_DIM]),
        QuantizedFeatureRow([i16::MIN; INPUT_DIM]),
        QuantizedFeatureRow(std::array::from_fn(|index| {
            if index % 2 == 0 {
                i16::MIN
            } else {
                i16::MAX
            }
        })),
    ];
    for index in 0..INPUT_DIM {
        let mut positive = [0; INPUT_DIM];
        positive[index] = i16::MAX;
        rows.push(QuantizedFeatureRow(positive));
        let mut negative = [0; INPUT_DIM];
        negative[index] = i16::MIN;
        rows.push(QuantizedFeatureRow(negative));
    }
    rows
}

fn acquire_live(route: crate::hw_probe::ScanBackend) -> Arc<dyn vyre::VyreBackend> {
    let mut peers = crate::gpu::GpuBackendPeers::default();
    match route {
        crate::hw_probe::ScanBackend::GpuCuda => peers.cuda_available = true,
        crate::hw_probe::ScanBackend::GpuMetal => peers.metal_available = true,
        crate::hw_probe::ScanBackend::GpuWgpu => peers.wgpu_available = true,
        _ => panic!("live quantized score gate requires a GPU route"),
    }
    peers
        .get(route)
        .cloned()
        .unwrap_or_else(|| panic!("live {} backend is required", route.label()))
}

fn assert_live_backend_scores_bit_exactly(route: crate::hw_probe::ScanBackend) {
    let rows = feature_bound_rows();
    let backend = acquire_live(route);
    let actual = submit_rows(backend.as_ref(), &rows, None)
        .and_then(PendingQuantizedScores::await_scores)
        .unwrap_or_else(|error| panic!("cold {} scoring failed: {error}", route.label()));
    let abandoned = submit_rows(backend.as_ref(), &rows[..1], None)
        .unwrap_or_else(|error| panic!("{} abandoned scoring failed: {error}", route.label()));
    drop(abandoned);
    let replay = submit_rows(backend.as_ref(), &rows, None)
        .and_then(PendingQuantizedScores::await_scores)
        .unwrap_or_else(|error| panic!("warm {} scoring failed: {error}", route.label()));
    assert_eq!(actual, replay, "cold and warm dispatches must be identical");
    assert!(matches!(
        submit_rows(
            backend.as_ref(),
            &rows[..1],
            Some(std::time::Duration::ZERO),
        ),
        Err(QuantizedConfidenceError::BackendFailure(reason))
            if reason.contains("deadline elapsed")
    ));
    let oracle = model().expect("embedded quantized model");
    assert_eq!(actual.len(), rows.len());
    for (candidate_id, (actual, row)) in actual.iter().zip(&rows).enumerate() {
        assert_eq!(actual.candidate_id, candidate_id as u32);
        assert_eq!(
            actual.score,
            oracle.score(row),
            "{} fixed-point parity failed for candidate {candidate_id}",
            route.label(),
        );
    }
}

#[test]
#[ignore = "GPU-host gate; compares the live WGPU kernel with the fixed-point CPU oracle"]
fn live_wgpu_scores_every_feature_bound_bit_exactly() {
    assert_live_backend_scores_bit_exactly(crate::hw_probe::ScanBackend::GpuWgpu);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "GPU-host gate; compares the live CUDA kernel with the fixed-point CPU oracle"]
fn live_cuda_scores_every_feature_bound_bit_exactly() {
    assert_live_backend_scores_bit_exactly(crate::hw_probe::ScanBackend::GpuCuda);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "GPU-host gate; compares the live Metal kernel with the fixed-point CPU oracle"]
fn live_metal_scores_every_feature_bound_bit_exactly() {
    assert_live_backend_scores_bit_exactly(crate::hw_probe::ScanBackend::GpuMetal);
}

#[test]
#[ignore = "GPU-host stress gate; exercises the maximum bounded candidate batch"]
fn live_wgpu_scores_maximum_candidate_batch_bit_exactly() {
    let rows = vec![QuantizedFeatureRow([0; INPUT_DIM]); MAX_CANDIDATES_PER_BATCH];
    let backend = vyre_driver_wgpu::WgpuBackend::shared()
        .expect("live WGPU backend is required for this ignored gate");
    let actual = submit_rows(backend.as_ref(), &rows, None)
        .and_then(PendingQuantizedScores::await_scores)
        .expect("maximum live WGPU quantized scoring");
    let expected = model().expect("embedded quantized model").score(&rows[0]);
    assert_eq!(actual.len(), MAX_CANDIDATES_PER_BATCH);
    for (candidate_id, actual) in actual.iter().enumerate() {
        assert_eq!(actual.candidate_id, candidate_id as u32);
        assert_eq!(actual.score, expected);
    }
}
