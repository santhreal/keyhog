//! Remaining report-tail wiring gate.

use super::support::*;

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
