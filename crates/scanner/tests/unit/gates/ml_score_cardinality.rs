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
    let exact_scores = vec![0.1, 0.2, 0.3];
    let exact = keyhog_scanner::testing::complete_ml_batch_scores(
        &candidates,
        exact_scores.clone(),
        &config,
    )
    .expect("matching ML score cardinality should succeed");
    assert_eq!(exact, exact_scores);
    for malformed in [Vec::new(), vec![0.123], vec![0.1, 0.2, 0.3, 0.4]] {
        let error =
            keyhog_scanner::testing::complete_ml_batch_scores(&candidates, malformed, &config)
                .expect_err("empty, short, and extra ML score rows must fail closed");
        assert!(
            matches!(error, keyhog_scanner::ScanError::Gpu(_)),
            "cardinality mismatch must remain a typed GPU backend error: {error}"
        );
    }
    assert!(
        ml_postprocess.contains("self.emit_finalized_pending_match(scan_state, pending, report_conf)")
            && ml_postprocess.contains("crate::adjudicate::finalize_report_candidate(")
            && ml_postprocess.contains(".materialize(final_confidence)")
            && ml_postprocess.contains("crate::adjudicate::ReportAdjudicationPolicy"),
        "every ML-pending drain path must adjudicate before durable match construction"
    );
    assert!(
        ml_postprocess.contains("if !self.config.ml_enabled")
            && ml_postprocess.contains("return Err(crate::ScanError::Config")
            && ml_postprocess.contains("ML pending queue populated while ML is disabled")
            && !ml_postprocess.contains("panic!(")
            && !ml_postprocess.contains("scan_state.ml_pending.clear();")
            && !ml_postprocess.contains("dropping pending ML matches"),
        "ML postprocess must return a typed error on impossible pending state without clearing queued findings or panicking"
    );
    assert!(
        !ml_postprocess.contains("raw_match.confidence =")
            && !ml_postprocess.contains("&pending.credential,"),
        "ML postprocess must not mutate finalized confidence or pass a split credential into adjudicate"
    );
    assert!(
        ml_postprocess.contains("crate::confidence::policy::ml_pending_match_confidence(")
            && !ml_postprocess.contains("crate::confidence::policy::MlConfidencePolicy")
            && !ml_postprocess.contains("pending.ml_mode")
            && !ml_postprocess.contains("pending.heuristic_conf")
            && policy.contains("fn ml_pending_match_confidence(")
            && policy.contains("pending.ml_mode")
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
            && scan_state.contains("fn for_each_pre_entropy_pending_ml_line")
            && process.contains("&& !weak_anchor")
            && process.contains("push_detector_ml_pending(")
            && entropy.contains("push_entropy_ml_pending(")
            && !process.contains("MlPendingMatch::detector_candidate(")
            && !entropy.contains("MlPendingMatch::entropy_candidate(")
            && !process.contains(".ml_pending.push(")
            && !entropy.contains(".ml_pending.push(")
            && !process.contains(".ml_pending")
            && !entropy.contains(".ml_pending")
            && process.contains("ml_mode: detector_ml_mode")
            && entropy.contains(".filter(|_| self.config.ml_enabled && self.config.entropy_ml_authoritative)")
            && process.contains("crate::types::ml_features_for_candidate(")
            && entropy.contains("crate::types::ml_features_for_candidate(")
            && !process.contains("MlPendingMatch {")
            && !entropy.contains("MlPendingMatch {")
            && ml_postprocess.contains("is_named_detector: pending.is_named_detector")
            && !ml_postprocess.contains(
                "is_service_anchored_detector(\n                    &pending.raw_match.detector_id"
        ),
        "ML pending finalization must preserve the producer's weak-anchor-aware named-detector classification"
    );
    let source = "first\nTOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\nthird";
    let credential = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    let context =
        keyhog_scanner::testing::ml_context_for_candidate(source, 2, Some("src/token.rs"), 5);
    let detector = keyhog_core::detector_spec_by_id("github-classic-pat").unwrap();
    let expected = keyhog_scanner::ml_scorer::compute_features_for_detector_with_config(
        credential,
        &context,
        &config.known_prefixes,
        &config.secret_keywords,
        &config.test_keywords,
        &config.placeholder_keywords,
        detector,
        keyhog_scanner::ml_scorer::MlCandidateChannel::Pattern,
    );
    let queued = keyhog_scanner::testing::queued_ml_features(
        source,
        2,
        Some("src/token.rs"),
        credential,
        5,
        &config,
        "github-classic-pat",
        false,
    );
    assert_eq!(queued.as_slice(), expected.as_slice());
    assert!(
        gpu.contains(
            "let score_features_on_cpu =\n            || crate::ml_scorer::score_precomputed_batch_on_cpu",
        ) && gpu.contains("scores.len() == candidates.len()")
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
