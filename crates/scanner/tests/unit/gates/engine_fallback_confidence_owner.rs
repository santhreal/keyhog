//! Gate: fallback confidence base-score policy has one confidence owner.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{} not readable: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn uncommented_code(src: &str) -> String {
    src.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                None
            } else {
                Some(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

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
    assert!(
        entropy.contains("crate::confidence::policy::entropy_fallback_confidence("),
        "entropy fallback must ask the confidence owner for its base confidence"
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

    let generic = uncommented_code(&read(&src.join("engine/phase2_generic.rs")));
    assert!(
        generic.contains("crate::confidence::policy::generic_secret_confidence("),
        "generic fallback must ask the confidence owner for its base confidence"
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
        assert!(
            code.contains("crate::adjudicate::finalize_report_candidate(")
                && code.contains("crate::adjudicate::ReportAdjudicationPolicy"),
            "{path} must route final report confidence through adjudicate"
        );
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
        hot_patterns.contains("crate::confidence::policy::hot_pattern_confidence("),
        "hot patterns must route final report confidence through the confidence owner"
    );

    let mut files = Vec::new();
    collect_rs_files(&src.join("engine"), &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).expect("scanner src prefix");
        if rel == Path::new("engine/scoring.rs") {
            continue;
        }
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
        "engine files other than scoring.rs must not own report-confidence policy calls: {offenders:#?}"
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

    let scoring = uncommented_code(&read(&src.join("engine/scoring.rs")));
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    assert!(
        process.contains("fn match_companions(") && !scoring.contains("fn match_companions("),
        "companion matching is process wiring, not engine/scoring confidence ownership"
    );
    for required in [
        "match_heuristic_confidence(",
        "MatchHeuristicConfidencePolicy",
        "apply_known_prefix_floor(",
    ] {
        assert!(
            scoring.contains(required),
            "engine scoring must use direct confidence-owner token {required:?}"
        );
    }
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
            !scoring.contains(forbidden),
            "engine scoring must not own confidence adjustment token {forbidden:?}"
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
        "model_authoritative",
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
        ml.contains("crate::confidence::policy::ml_pending_confidence(")
            && ml.contains("crate::confidence::policy::MlConfidencePolicy"),
        "ML postprocess must route pending confidence through confidence owner"
    );
    for forbidden in [
        "let ml_weight =",
        "let mut final_score =",
        "let blended =",
        ".max(pending.heuristic_conf)",
        "context_penalty_applies",
        "final_score *=",
        "confidence_multiplier()",
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

    let scoring = uncommented_code(&read(&src.join("engine/scoring.rs")));
    assert!(
        scoring.contains("probabilistic_promise_confidence_override(")
            && !scoring.contains("super::scoring::probabilistic_promise_confidence_override("),
        "engine scoring must use direct confidence owner for probabilistic promise confidence"
    );
    for forbidden in [
        "ProbabilisticGate::looks_promising",
        "looks_like_word_separated_identifier(credential)",
        "looks_like_pure_identifier(credential)",
        "MlScoreResult::Final(0.1)",
    ] {
        assert!(
            !scoring.contains(forbidden),
            "engine scoring must not own probabilistic promise policy token {forbidden:?}"
        );
    }
}
