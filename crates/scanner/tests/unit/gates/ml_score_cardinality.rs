#[test]
fn ml_batch_score_cardinality_is_checked_at_every_boundary() {
    let postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/scan_postprocess.rs"
    ))
    .expect("scan_postprocess.rs readable");
    let gpu = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu.rs"))
        .expect("gpu.rs readable");
    let backend =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/backend.rs"))
            .expect("gpu/backend.rs readable");

    assert!(
        postprocess.contains("fn score_ml_pending_cpu")
            && postprocess.contains("crate::ml_scorer::score_with_config(")
            && postprocess.contains("scores.len() == pending_matches.len()")
            && postprocess.contains(
                "ML score count mismatch; recomputing CPU MoE scores before confidence blending"
            )
            && postprocess.contains("pending_matches.into_iter().zip(scores.into_iter())"),
        "postprocess ML scoring must preserve every pending finding when score cardinality drifts"
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
