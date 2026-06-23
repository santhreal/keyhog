#[test]
fn ml_batch_score_cardinality_is_checked_at_every_boundary() {
    let scan_state =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/scan_state.rs"))
            .expect("scan_state.rs readable");
    let process = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/process.rs"
    ))
    .expect("engine/process.rs readable");
    let entropy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_entropy.rs"
    ))
    .expect("engine/phase2_entropy.rs readable");
    let ml_postprocess = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/scan_postprocess/ml.rs"
    ))
    .expect("scan_postprocess/ml.rs readable");
    let policy = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/confidence/policy.rs"
    ))
    .expect("confidence/policy.rs readable");
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
        ml_postprocess.contains(
            "self.emit_finalized_pending_match(scan_state, pending, final_score)"
        )
            && ml_postprocess.contains("crate::adjudicate::finalize_report_raw_match(")
            && ml_postprocess.contains("crate::adjudicate::ReportAdjudicationPolicy"),
        "every ML-pending drain path must pass through the report finalizer and adjudicator-owned rejection stages"
    );
    assert!(
        ml_postprocess.contains("if !self.config.ml_enabled")
            && ml_postprocess.contains("internal invariant violation: ML pending queue populated while ML is disabled")
            && ml_postprocess.contains("scan_state.ml_pending.clear();")
            && !ml_postprocess.contains("for p in pending")
            && !ml_postprocess.contains("let heuristic_conf = p.heuristic_conf"),
        "ML postprocess must fail loud on impossible disabled-ML pending state instead of silently using heuristic fallback"
    );
    assert!(
        !ml_postprocess.contains("raw_match.confidence =")
            && !ml_postprocess.contains("&pending.credential,"),
        "ML postprocess must not mutate finalized confidence or pass a split credential into adjudicate"
    );
    assert!(
        scan_state.contains("pub(crate) is_named_detector: bool")
            && scan_state.contains("fn detector_candidate(")
            && scan_state.contains("fn entropy_authoritative(")
            && process.contains("&& !weak_anchor")
            && process.contains("MlPendingMatch::detector_candidate(")
            && entropy.contains("MlPendingMatch::entropy_authoritative(")
            && process.contains("ml_enabled: self.config.ml_enabled")
            && entropy.contains("if self.config.ml_enabled && self.config.entropy_ml_authoritative")
            && process.contains("crate::types::ml_context_for_candidate(")
            && entropy.contains("crate::types::ml_context_for_candidate(")
            && !process.contains("MlPendingMatch {")
            && !entropy.contains("MlPendingMatch {")
            && ml_postprocess.contains("is_named_detector: pending.is_named_detector")
            && !ml_postprocess.contains(
                "is_service_anchored_detector(\n                    &pending.raw_match.detector_id"
        ),
        "ML pending finalization must preserve the producer's weak-anchor-aware named-detector classification"
    );
    assert!(
        scan_state.contains("fn ml_context_for_candidate(")
            && !policy.contains("local_context_window(")
            && !policy.contains("file:{path}")
            && !process.contains("format!(\"file:{path}")
            && !entropy.contains("format!(\"file:{path}"),
        "ML context formatting must have one owner outside confidence policy"
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
