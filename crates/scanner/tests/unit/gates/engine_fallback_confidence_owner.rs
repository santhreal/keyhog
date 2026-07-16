//! Gate: fallback confidence base-score policy has one confidence owner.

use super::support::*;

#[test]
fn entropy_and_generic_fallback_confidence_route_through_confidence_owner() {
    let src = scanner_src();
    let scoring = uncommented_code(&read(&src.join("confidence/policy.rs")));
    for required in [
        "fn entropy_fallback_confidence(",
        "fn generic_secret_confidence(",
        "VERY_HIGH_ENTROPY_THRESHOLD",
        "HIGH_ENTROPY_THRESHOLD",
        "CodeContext::TestCode",
        "CodeContext::Documentation",
        "CodeContext::Comment",
    ] {
        assert!(
            scoring.contains(required),
            "confidence::policy must own fallback confidence policy token {required:?}"
        );
    }

    let entropy = uncommented_code(&read(&src.join("engine/phase2_entropy.rs")));
    let adjudicate = uncommented_code(&read(&src.join("adjudicate/mod.rs")));
    assert!(
        adjudicate.contains("fn detector_min_confidence_floor("),
        "adjudicate must own active-detector min-confidence floor resolution"
    );
    assert!(
        entropy.contains("crate::confidence::policy::entropy_fallback_confidence("),
        "entropy fallback must ask the confidence owner for its base confidence"
    );
    assert!(
        entropy.contains("crate::adjudicate::detector_min_confidence_floor(")
            && entropy.contains("policy_detector.and_then(|detector| detector.min_confidence)")
            && !entropy.contains("min_confidence_floor: self.config.min_confidence")
            && !entropy.contains("ml_context,\n                    self.config.min_confidence"),
        "entropy fallback must resolve confidence from its active policy detector"
    );
    for forbidden in [
        "base_confidence",
        "0.75",
        "0.65",
        "0.90_f64",
        "0.55_f64.min",
        "\"none (high-entropy)\"",
    ] {
        assert!(
            !entropy.contains(forbidden),
            "entropy fallback emitter must not own confidence policy token {forbidden:?}"
        );
    }
    for forbidden in [
        "let confidence = crate::confidence::policy::entropy_fallback_confidence(",
        "let Some(confidence) = crate::adjudicate::finalize_report_candidate(",
        "|scan_state: &mut ScanState, confidence|",
    ] {
        assert!(
            !entropy.contains(forbidden),
            "entropy fallback must not bind confidence-owner values with leaf-owned name {forbidden:?}"
        );
    }

    let generic = uncommented_code(&read(&src.join("engine/phase2_generic.rs")));
    assert!(
        generic.contains("crate::confidence::policy::generic_secret_confidence("),
        "generic fallback must ask the confidence owner for its base confidence"
    );
    assert!(
        generic.contains("crate::adjudicate::detector_min_confidence_floor(")
            && generic.contains("owning_detector.and_then(|detector| detector.min_confidence)")
            && !generic.contains("min_confidence_floor: self.config.min_confidence"),
        "generic fallback must resolve confidence from its active owning detector"
    );
    for forbidden in [
        "let base_conf",
        "entropy_boost",
        "length_boost",
        "CodeContext::TestCode if",
        "CodeContext::Documentation",
        "CodeContext::Comment if",
    ] {
        assert!(
            !generic.contains(forbidden),
            "generic fallback emitter must not own confidence policy token {forbidden:?}"
        );
    }
    for forbidden in [
        "let confidence = crate::confidence::policy::generic_secret_confidence(",
        "let Some(confidence) = crate::adjudicate::finalize_report_candidate(",
    ] {
        assert!(
            !generic.contains(forbidden),
            "generic fallback must not bind confidence-owner values with leaf-owned name {forbidden:?}"
        );
    }
}

#[test]
fn report_confidence_tail_routes_through_confidence_owner() {
    let src = scanner_src();
    let owner = src.join("confidence/policy.rs");
    let scoring = uncommented_code(&read(&owner));
    let adjudicate = uncommented_code(&read(&src.join("adjudicate/mod.rs")));
    for required in [
        "fn finalize_report_confidence(",
        "apply_post_ml_penalties_with_encoded_text_lift",
        "apply_path_confidence_penalties",
        "known_prefix_confidence_floor",
        "apply_calibration_multiplier",
        "apply_checksum_confidence",
    ] {
        assert!(
            scoring.contains(required),
            "confidence::policy must own report-confidence policy token {required:?}"
        );
    }
    for required in [
        "struct ReportAdjudicationPolicy",
        "fn finalize_report_candidate(",
        "fn finalize_report_raw_match(",
        "let credential = raw_match.credential.as_ref();",
        "finalize_report_confidence(",
        "record_checksum_invalid_suppression(",
        "MatchCtx::for_final_emit(",
        "Verdict::Reported(confidence) => confidence",
    ] {
        assert!(
            adjudicate.contains(required),
            "adjudicate must own final report candidate routing token {required:?}"
        );
    }

    for path in [
        "engine/process.rs",
        "engine/scan_postprocess/ml.rs",
        "engine/phase2_entropy.rs",
        "engine/phase2_generic.rs",
    ] {
        let code = uncommented_code(&read(&src.join(path)));
        let expected_finalizer = if path == "engine/scan_postprocess/ml.rs" {
            "crate::adjudicate::finalize_report_raw_match("
        } else {
            "crate::adjudicate::finalize_report_candidate("
        };
        assert!(
            code.contains(expected_finalizer)
                && code.contains("crate::adjudicate::ReportAdjudicationPolicy"),
            "{path} must route final report confidence through adjudicate"
        );
        if path == "engine/scan_postprocess/ml.rs" {
            assert!(
                !code.contains("raw_match.confidence =") && !code.contains("&pending.credential,"),
                "{path} must not mutate RawMatch confidence or pass a split credential into adjudicate"
            );
        }
        for forbidden in [
            "super::scoring::finalize_report_confidence(",
            "super::scoring::ReportConfidencePolicy",
            "crate::adjudicate::MatchCtx::for_final_emit(",
            "crate::adjudicate::FinalEmitSignals::new(",
            "crate::adjudicate::record_checksum_invalid_suppression(",
        ] {
            assert!(
                !code.contains(forbidden),
                "{path} must not own final report routing token {forbidden:?}"
            );
        }
    }
    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("self.process_match("),
        "hot patterns must route final report confidence through the shared process_match path"
    );
    assert!(
        !hot_patterns.contains("crate::confidence::policy::hot_pattern_confidence(")
            && !hot_patterns.contains("let Some(confidence)"),
        "hot patterns must not own a hot-specific confidence function or local confidence fork"
    );

    let mut files = Vec::new();
    collect_rs_files(&src.join("engine"), &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "crate::confidence::apply_post_ml_penalties(",
            "crate::confidence::apply_post_ml_penalties_with_encoded_text_lift(",
            "crate::confidence::apply_path_confidence_penalties(",
            "crate::confidence::apply_calibration_multiplier(",
            "super::scoring::apply_checksum_confidence(",
            ".adjusted_confidence(",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "engine files must not own report-confidence policy calls: {offenders:#?}"
    );
}

#[test]
fn engine_scoring_confidence_adjustments_use_confidence_owner() {
    let src = scanner_src();
    let policy = uncommented_code(&read(&src.join("confidence/policy.rs")));
    for required in [
        "fn pre_ml_heuristic_confidence(",
        "struct MatchHeuristicConfidencePolicy",
        "fn match_heuristic_confidence(",
        "compute_confidence",
        "ConfidenceSignals",
        "fn apply_known_prefix_floor(",
        "known_prefix_confidence_floor",
        "confidence.max(floor)",
        "CodeContext::TestCode | context::CodeContext::Documentation",
        "confidence_multiplier()",
    ] {
        assert!(
            policy.contains(required),
            "confidence::policy must own engine scoring adjustment token {required:?}"
        );
    }

    assert!(
        !src.join("engine/scoring.rs").exists(),
        "engine/scoring.rs must stay folded into confidence::policy"
    );
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    assert!(
        process.contains("fn match_companions(")
            && process.contains("crate::confidence::policy::candidate_match_score(")
            && !process.contains("self.match_confidence("),
        "process wiring must call confidence::policy directly for candidate scoring"
    );
    for required in [
        "struct CandidateMatchScorePolicy",
        "fn candidate_match_score",
        "match_heuristic_confidence(",
        "MatchHeuristicConfidencePolicy",
        "apply_known_prefix_floor(",
    ] {
        assert!(
            policy.contains(required),
            "confidence::policy must own candidate scoring token {required:?}"
        );
    }
    assert!(
        !policy.contains(
            "fn candidate_match_score<'a>(\n    policy: CandidateMatchScorePolicy<'a>,\n) -> Option"
        ) && !process.contains("from_scoring_rejected")
            && !process.contains("let Some(score_result)")
            && !process.contains("let score_result =")
            && !process.contains("match score_result")
            && !process.contains("MlScoreResult::Final(confidence)")
            && !process
                .contains("let Some(confidence) = crate::adjudicate::finalize_report_candidate("),
        "candidate scoring must return a concrete result without preserving dead scoring_rejected or leaf-owned confidence/score result names"
    );
    for forbidden in [
        "let context_multiplier =",
        "crate::confidence::compute_confidence(",
        "crate::confidence::ConfidenceSignals",
        "pre_ml_heuristic_confidence(",
        "CodeContext::TestCode | crate::context::CodeContext::Documentation",
        "context.confidence_multiplier()",
        "known_prefix_confidence_floor(credential)",
        "confidence.max(floor)",
    ] {
        assert!(
            !process.contains(forbidden),
            "engine process must not own confidence adjustment token {forbidden:?}"
        );
    }
}

#[test]
fn ml_pending_confidence_policy_routes_through_confidence_owner() {
    let src = scanner_src();
    let policy = uncommented_code(&read(&src.join("confidence/policy.rs")));
    let engine_mod = uncommented_code(&read(&src.join("engine/mod.rs")));
    for required in [
        "enum MlScoreResult",
        "struct MlConfidencePolicy",
        "fn ml_pending_confidence(",
        "fn ml_pending_match_confidence(",
        "ActiveMlMode",
        "ml_weight",
        "CodeContext::Comment",
        "CodeContext::TestCode",
        "confidence_multiplier()",
    ] {
        assert!(
            policy.contains(required),
            "confidence::policy must own ML confidence token {required:?}"
        );
    }
    assert!(
        !engine_mod.contains("enum MlScoreResult"),
        "engine/mod.rs must not own ML confidence result state"
    );

    let ml = uncommented_code(&read(&src.join("engine/scan_postprocess/ml.rs")));
    assert!(
        ml.contains("crate::confidence::policy::ml_pending_match_confidence(")
            && !ml.contains("crate::confidence::policy::ml_pending_confidence(")
            && !ml.contains("crate::confidence::policy::MlConfidencePolicy")
            && ml.contains(
                "internal invariant violation: ML pending queue populated while ML is disabled"
            )
            && ml.contains("pending={pending}")
            && !ml.contains("scan_state.ml_pending.clear();")
            && !ml.contains("dropping pending ML matches"),
        "ML postprocess must route pending confidence through confidence owner and fail loud on impossible disabled-ML pending state"
    );
    for forbidden in [
        "let ml_weight =",
        "let mut final_score =",
        "let blended =",
        ".max(pending.heuristic_conf)",
        "context_penalty_applies",
        "final_score *=",
        "confidence_multiplier()",
        "for p in pending",
        "let heuristic_conf = p.heuristic_conf",
    ] {
        assert!(
            !ml.contains(forbidden),
            "ML postprocess must not own confidence policy token {forbidden:?}"
        );
    }
}

#[test]
fn probabilistic_promise_confidence_routes_through_confidence_owner() {
    let src = scanner_src();
    let policy = uncommented_code(&read(&src.join("confidence/policy.rs")));
    for required in [
        "fn probabilistic_promise_confidence_override(",
        "ProbabilisticGate::looks_promising",
        "looks_like_word_separated_identifier",
        "looks_like_pure_identifier",
        "then_some(0.1)",
    ] {
        assert!(
            policy.contains(required),
            "confidence::policy must own probabilistic promise token {required:?}"
        );
    }

    assert!(
        policy.contains("candidate_match_score")
            && policy.contains("probabilistic_promise_confidence_override("),
        "candidate scoring must use the confidence owner for probabilistic promise confidence"
    );
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    for forbidden in [
        "ProbabilisticGate::looks_promising",
        "looks_like_word_separated_identifier(credential)",
        "looks_like_pure_identifier(credential)",
        "MlScoreResult::Final(0.1)",
    ] {
        assert!(
            !process.contains(forbidden),
            "engine process must not own probabilistic promise policy token {forbidden:?}"
        );
    }
}
