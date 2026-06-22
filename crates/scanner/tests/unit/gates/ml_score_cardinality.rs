#[test]
fn ml_batch_score_cardinality_is_checked_at_every_boundary() {
    let ml_postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/scan_postprocess/ml.rs"
    ))
    .expect("scan_postprocess/ml.rs readable");
    let gpu = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu.rs"))
        .expect("gpu.rs readable");
    let backend =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/backend.rs"))
            .expect("gpu/backend.rs readable");

    assert!(
        ml_postprocess.contains("fn score_ml_pending_cpu")
            && ml_postprocess.contains("fn emit_finalized_pending_match")
            && ml_postprocess.contains("crate::ml_scorer::score_with_config(")
            && ml_postprocess.contains("scores.len() == pending_matches.len()")
            && ml_postprocess.contains(
                "ML score count mismatch; recomputing CPU MoE scores before confidence blending"
            )
            && ml_postprocess.contains("pending_matches.into_iter().zip(scores.into_iter())"),
        "postprocess ML scoring must preserve every pending finding when score cardinality drifts"
    );
    assert!(
        ml_postprocess.contains("self.emit_finalized_pending_match(scan_state, p, heuristic_conf)")
            && ml_postprocess.contains(
                "self.emit_finalized_pending_match(scan_state, pending, final_score)"
            )
            && ml_postprocess.contains("StageId::ChecksumInvalid")
            && ml_postprocess.contains("crate::adjudicate::final_emit_suppression_stage("),
        "every ML-pending drain path must pass through the report finalizer and adjudicator-owned rejection stages"
    );
    assert!(
        gpu.contains("let score_features_on_cpu = || -> Vec<f64>")
            && gpu.contains("scores.len() == candidates.len()")
            && gpu.contains(
                "GPU MoE score count mismatch; recomputing CPU MoE scores for this batch"
            ),
        "GPU MoE caller must reject malformed score vectors and score the same batch on CPU"
    );
    assert!(
        backend.contains("scores.len() != batch_size")
            && backend
                .contains("GPU MoE score count mismatch; routing batch to CPU MoE for this scan")
            && backend.contains("moe_runtime_degrade(\"score count mismatch\")"),
        "GPU MoE backend must validate readback cardinality before returning scores"
    );
}
