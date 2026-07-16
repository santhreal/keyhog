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

    let candidates = [
        ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "TOKEN="),
        ("d41d8cd98f00b204e9800998ecf8427e", "checksum="),
        ("", "EMPTY="),
    ];
    let mut config = keyhog_scanner::ScannerConfig::default();
    config.known_prefixes.clear();
    config.secret_keywords.clear();
    config.test_keywords.clear();
    config.placeholder_keywords.clear();
    let repaired =
        keyhog_scanner::testing::complete_ml_batch_scores(&candidates, vec![0.123], &config);
    let expected: Vec<_> = candidates
        .iter()
        .map(|(text, context)| keyhog_scanner::testing::ml_score(text, context))
        .collect();
    assert_eq!(repaired.len(), candidates.len());
    for (index, (actual, expected)) in repaired.iter().zip(expected.iter()).enumerate() {
        assert!(
            (*actual - *expected).abs() <= f64::EPSILON,
            "cardinality repair changed candidate {index}: actual={actual:.9} expected={expected:.9}"
        );
    }
    assert!(
        ml_postprocess.contains("self.emit_finalized_pending_match(scan_state, pending, report_conf)")
            && ml_postprocess.contains("crate::adjudicate::finalize_report_raw_match(")
            && ml_postprocess.contains("crate::adjudicate::ReportAdjudicationPolicy"),
        "every ML-pending drain path must pass through the report finalizer and adjudicator-owned rejection stages"
    );
    assert!(
        ml_postprocess.contains("if !self.config.ml_enabled")
            && ml_postprocess.contains("internal invariant violation: ML pending queue populated while ML is disabled")
            && ml_postprocess.contains("pending={pending}")
            && !ml_postprocess.contains("scan_state.ml_pending.clear();")
            && !ml_postprocess.contains("dropping pending ML matches")
            && !ml_postprocess.contains("for p in pending")
            && !ml_postprocess.contains("let heuristic_conf = p.heuristic_conf"),
        "ML postprocess must fail loud on impossible disabled-ML pending state instead of clearing queued findings"
    );
    assert!(
        !ml_postprocess.contains("raw_match.confidence =")
            && !ml_postprocess.contains("&pending.credential,"),
        "ML postprocess must not mutate finalized confidence or pass a split credential into adjudicate"
    );
    assert!(
        ml_postprocess.contains("crate::confidence::policy::ml_pending_match_confidence(")
            && !ml_postprocess.contains("crate::confidence::policy::MlConfidencePolicy")
            && !ml_postprocess.contains("pending.model_authoritative")
            && !ml_postprocess.contains("pending.heuristic_conf")
            && policy.contains("fn ml_pending_match_confidence(")
            && policy.contains("pending.model_authoritative")
            && policy.contains("pending.heuristic_conf")
            && policy.contains("pending.code_context"),
        "ML postprocess must not rebuild confidence policy from pending internals"
    );
    assert!(
        !ml_postprocess.contains("final_score")
            && !ml_postprocess.contains("let confidence =")
            && !ml_postprocess.contains("let Some(confidence)"),
        "ML postprocess must not bind report-confidence handoff values with confidence/score owner names"
    );
    assert!(
        scan_state.contains("pub(crate) is_named_detector: bool")
            && scan_state.contains("fn detector_candidate(")
            && scan_state.contains("fn entropy_candidate(")
            && scan_state.contains("fn push_detector_ml_pending(")
            && scan_state.contains("fn push_entropy_ml_pending(")
            && scan_state.contains("fn for_each_named_pending_ml_line")
            && process.contains("&& !weak_anchor")
            && process.contains("push_detector_ml_pending(")
            && entropy.contains("push_entropy_ml_pending(")
            && !process.contains("MlPendingMatch::detector_candidate(")
            && !entropy.contains("MlPendingMatch::entropy_candidate(")
            && !process.contains(".ml_pending.push(")
            && !entropy.contains(".ml_pending.push(")
            && !process.contains(".ml_pending")
            && !entropy.contains(".ml_pending")
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
            && gpu.contains("crate::confidence::policy::ml_score_for_candidate_text(")
            && gpu.contains("crate::confidence::policy::apply_empty_candidate_score_policy(")
            && !gpu.contains("*score = 0.0;")
            // The caller's malformed-score arm must surface the mismatch LOUDLY
            // through the SHARED degrade owner (Law 10 + ONE-PLACE), not a bare
            // tracing::warn!, the backend already owns the length invariant, so a
            // caller-side mismatch routes through the same moe_runtime_degrade
            // (hard-fail under --require-gpu, one-shot eprintln otherwise) before
            // recomputing the batch on the CPU MoE.
            && gpu.contains("backend::moe_runtime_degrade(")
            && gpu.contains("caller-side score count mismatch"),
        "GPU MoE caller must reject malformed score vectors, surface the mismatch loudly via the shared moe_runtime_degrade owner, and score the same batch on CPU"
    );
    assert!(
        backend.contains("scores.len() != batch_size")
            && backend
                .contains("GPU MoE score count mismatch; routing batch to CPU MoE for this scan")
            && backend.contains("moe_runtime_degrade(\"score count mismatch\")"),
        "GPU MoE backend must validate readback cardinality before returning scores"
    );
}
