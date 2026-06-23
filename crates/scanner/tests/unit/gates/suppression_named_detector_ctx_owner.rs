//! Gate: production named-detector suppression uses one typed context entry point.

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

fn adjudicate_code(src: &Path) -> String {
    [
        "adjudicate/mod.rs",
        "adjudicate/stage.rs",
        "adjudicate/generic.rs",
        "adjudicate/entropy.rs",
    ]
    .into_iter()
    .map(|rel| uncommented_code(&read(&src.join(rel))))
    .collect::<Vec<_>>()
    .join("\n")
}

#[test]
fn engine_uses_typed_named_detector_suppression_context() {
    let src = scanner_src();
    let api = read(&src.join("suppression/api.rs"));
    assert!(
        api.contains("struct NamedDetectorSuppressionCtx")
            && api.contains("fn suppress_named_detector_finding(")
            && api.contains("fn suppress_named_detector_finding_stage(")
            && api.contains(") -> Option<crate::adjudicate::StageId>"),
        "suppression::api must expose the typed named-detector suppression entry point and exact adjudicator stage"
    );
    assert!(
        !api.contains("fn should_suppress_named_detector_finding(")
            && !api.contains("fn should_suppress_named_detector_finding_weak(")
            && !api.contains("fn named_detector_suppressed("),
        "named-detector suppression must not expose a separate weak rigor-tier function"
    );
    let suppression_mod = read(&src.join("suppression/mod.rs"));
    assert!(
        !suppression_mod.contains("should_suppress_named_detector_finding"),
        "suppression::mod must not re-export named-detector rigor wrappers"
    );

    let mut files = Vec::new();
    collect_rs_files(&src.join("engine"), &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "should_suppress_named_detector_finding(",
            "should_suppress_named_detector_finding_weak(",
            "crate::pipeline::should_suppress_named_detector_finding",
            "crate::pipeline::detector_weak_anchor",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "production engine callers must use NamedDetectorSuppressionCtx through suppression, not pipeline rigor-tier wrappers: {offenders:#?}"
    );
}

#[test]
fn pipeline_does_not_facade_suppression_decisions() {
    let src = scanner_src();
    for rel in ["pipeline/mod.rs", "pipeline/postprocess/mod.rs"] {
        let path = src.join(rel);
        let code = uncommented_code(&read(&path));
        assert!(
            !code.contains("should_suppress_")
                && !code.contains("suppress_named_detector_finding")
                && !code.contains("detector_weak_anchor"),
            "{rel} must not re-export suppression policy decisions"
        );
    }
}

#[test]
fn engine_named_detector_suppression_routes_through_adjudicator() {
    let src = scanner_src();
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    let adjudicate = adjudicate_code(&src);
    let api = uncommented_code(&read(&src.join("suppression/api.rs")));
    assert!(
        process.contains("crate::adjudicate::record_suppression("),
        "engine/process.rs must route named-detector candidate decisions through the adjudicator recorder"
    );
    assert!(
        !process.contains("suppress_named_detector_finding("),
        "engine/process.rs must not call suppress_named_detector_finding directly; the adjudicator owns the decision"
    );
    assert!(
        adjudicate.contains("crate::suppression::suppress_named_detector_finding_stage(")
            && !adjudicate.contains("StageId::NamedDetectorSuppression")
            && !adjudicate.contains("named_detector_suppressed")
            && !api.contains("StageId::NamedDetectorSuppression"),
        "adjudicator must preserve exact named-detector suppression stages instead of flattening them"
    );
}

#[test]
fn engine_process_early_suppression_reasons_live_in_adjudicator() {
    let src = scanner_src();
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    let adjudicate = adjudicate_code(&src);
    for reason in [
        "aws_access_key_length_invalid",
        "anthropic_legacy_length_invalid",
        "within_hex_context",
        "hex_digest_fragment",
        "probabilistic_gate_not_promising",
        "false_positive_context",
        "missing_required_companion",
        "entropy_below_floor",
        "camel_case_no_digit",
        "checksum_invalid",
        "below_min_confidence",
    ] {
        assert!(
            !process.contains(&format!("\"{reason}\"")),
            "engine/process.rs must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate module must own the {reason} suppression reason"
        );
    }
    assert!(
        process.contains("ProcessCandidateSignals::from_checksum_policy(")
            && !process.contains("ProcessCandidateSignals::from_checksum_invalid(")
            && !process.contains("crate::confidence::policy::checksum_policy_for("),
        "engine/process.rs checksum drops must ask adjudicate to derive the checksum signal"
    );
    let shape = uncommented_code(&read(&src.join("suppression/shape/mod.rs")));
    let generic_shape = uncommented_code(&read(&src.join("engine/phase2_generic_shape.rs")));
    let scan_filters = uncommented_code(&read(&src.join("engine/scan_filters.rs")));
    assert!(
        shape.contains("fn looks_like_camel_case_no_digit(")
            && adjudicate.contains("crate::suppression::shape::looks_like_camel_case_no_digit(")
            && !process.contains("crate::suppression::shape::looks_like_camel_case_no_digit(")
            && !process.contains("let camel_transitions =")
            && !process.contains(".windows(2)")
            && !process.contains("w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase()"),
        "engine/process.rs must route camel-case/no-digit value-shape checks through adjudicate"
    );
    assert!(
        adjudicate.contains("fn generic_entropy_floor(")
            && adjudicate.contains("fn generic_entropy_below_floor(")
            && adjudicate.contains("fn from_process_entropy_shape(")
            && process.contains("ProcessCandidateSignals::from_process_entropy_shape(")
            && generic_shape.contains("crate::adjudicate::generic_entropy_below_floor(")
            && !process.contains("generic_entropy_floor(")
            && !process.contains("generic_entropy_below_floor(")
            && !process.contains("ProcessCandidateSignals::from_entropy_shape(")
            && !scan_filters.contains("fn generic_entropy_floor(")
            && !generic_shape.contains("super::scan_filters::generic_entropy_floor("),
        "generic entropy-floor policy must live in adjudicate, not engine leaves"
    );
    assert!(
        adjudicate.contains("fn detector_min_confidence_floor(")
            && process.contains("crate::adjudicate::detector_min_confidence_floor(")
            && !process.contains("match detector.min_confidence"),
        "engine/process.rs must not own detector-vs-default min-confidence floor resolution"
    );
    assert!(
        !process.contains("from_scoring_rejected")
            && !adjudicate.contains("from_scoring_rejected")
            && !adjudicate.contains("scoring_rejected"),
        "dead candidate-score rejection route must not return as a fake suppression stage"
    );
    assert!(
        process.contains("crate::adjudicate::finalize_report_candidate(")
            && !process.contains("ProcessCandidateSignals::from_checksum_invalid(true)"),
        "engine/process.rs finalizer checksum drops must route through the adjudicator final report helper"
    );
    assert!(
        adjudicate.contains("fn record_checksum_invalid_suppression(")
            && adjudicate.contains("ProcessCandidateSignals::from_checksum_invalid(true)"),
        "adjudicate module must own finalizer checksum-invalid suppression conversion"
    );
}

#[test]
fn generic_bridge_suppression_reasons_route_through_adjudicator() {
    let src = scanner_src();
    let generic = uncommented_code(&read(&src.join("engine/phase2_generic.rs")));
    let generic_shape = uncommented_code(&read(&src.join("engine/phase2_generic_shape.rs")));
    let adjudicate = adjudicate_code(&src);

    assert!(
        generic.contains("crate::adjudicate::record_suppression(")
            && generic.contains("crate::adjudicate::MatchCtx::for_generic_bridge("),
        "engine/phase2_generic.rs must route generic suppression telemetry through the adjudicator"
    );
    assert!(
        generic.contains("crate::adjudicate::finalize_report_candidate("),
        "engine/phase2_generic.rs finalizer checksum drops must use the adjudicator final report helper"
    );
    assert!(
        !generic.contains("ProcessCandidateSignals::from_checksum_invalid(true)"),
        "engine/phase2_generic.rs must not rebuild finalizer checksum-invalid context"
    );

    for reason in [
        "generic_named_detector_owned_keyword",
        "generic_keyword_boundary",
        "bare_auth_unstructured",
        "generic_below_min_confidence",
    ] {
        assert!(
            !generic.contains(&format!("\"{reason}\"")),
            "engine/phase2_generic.rs must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate module must own the {reason} suppression reason"
        );
    }
    for forbidden in [
        "StageId::GenericKeywordBoundary",
        "StageId::GenericNamedDetectorOwnedKeyword",
        "StageId::BareAuthUnstructured",
        "StageId::GenericValueShape",
    ] {
        assert!(
            !generic.contains(forbidden),
            "engine/phase2_generic.rs must not name generic suppression stages directly: {forbidden}"
        );
    }
    for reason in [
        "caesar_generic_fallback",
        "generic_entropy_below_floor",
        "value_too_short",
        "code_expression_chars",
        "source_code_expression",
        "source_symbol_identifier",
        "scope_resolution",
        "type_name_shape",
        "non_jwt_dotted",
        "pure_identifier_no_digit",
        "pure_identifier",
        "word_separated_identifier",
        "scheme_prefixed_uri",
        "punctuation_decorated_identifier",
        "url_or_path_segment",
        "vendored_minified_path",
        "regex_literal_tail",
        "base64_blob",
        "trimmed_aws_arn",
        "encoded_binary",
        "random_byte_blob",
    ] {
        assert!(
            !generic_shape.contains(&format!("\"{reason}\"")),
            "engine/phase2_generic_shape.rs must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate module must own the {reason} suppression reason"
        );
    }
}

#[test]
fn entropy_and_ml_emit_reject_reasons_route_through_adjudicator() {
    let src = scanner_src();
    let entropy = uncommented_code(&read(&src.join("engine/phase2_entropy.rs")));
    let ml = uncommented_code(&read(&src.join("engine/scan_postprocess/ml.rs")));
    let adjudicate = adjudicate_code(&src);

    assert!(
        entropy.contains("crate::adjudicate::record_suppression(")
            && entropy.contains("crate::adjudicate::MatchCtx::for_entropy_fallback("),
        "engine/phase2_entropy.rs must route entropy suppressions through the adjudicator"
    );
    assert!(
        entropy.contains("crate::adjudicate::finalize_report_candidate("),
        "engine/phase2_entropy.rs finalizer checksum drops must use the adjudicator final report helper"
    );
    assert!(
        ml.contains("crate::adjudicate::finalize_report_raw_match("),
        "engine/scan_postprocess/ml.rs must route pending-match suppressions through the adjudicator raw-match final report helper"
    );
    assert!(
        ml.contains("crate::adjudicate::finalize_report_raw_match(")
            && !ml.contains("raw_match.confidence =")
            && !ml.contains("&pending.credential,"),
        "engine/scan_postprocess/ml.rs checksum drops, confidence assignment, and raw-match credential selection must use the adjudicator raw-match final report helper"
    );
    for (path, code) in [
        ("engine/phase2_entropy.rs", entropy.as_str()),
        ("engine/scan_postprocess/ml.rs", ml.as_str()),
    ] {
        assert!(
            !code.contains("ProcessCandidateSignals::from_checksum_invalid(true)"),
            "{path} must not rebuild finalizer checksum-invalid context"
        );
    }

    for reason in [
        "entropy_named_detector_owned_assignment",
        "checksum_invalid",
        "below_min_confidence",
        "hard_suppressed_context",
    ] {
        assert!(
            !entropy.contains(&format!("\"{reason}\"")),
            "engine/phase2_entropy.rs must not own the {reason} suppression reason"
        );
        assert!(
            !ml.contains(&format!("\"{reason}\"")),
            "engine/scan_postprocess/ml.rs must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate module must own the {reason} suppression reason"
        );
    }
}

#[test]
fn entropy_fallback_shape_gauntlet_returns_adjudicator_stage() {
    let src = scanner_src();
    let entropy = uncommented_code(&read(&src.join("engine/phase2_entropy.rs")));
    let gates = uncommented_code(&read(&src.join("engine/phase2_entropy/gates.rs")));
    let adjudicate = adjudicate_code(&src);

    assert!(
        gates.contains("fn entropy_match_suppression_stage(")
            && gates.contains(") -> Option<EntropyShapeStage>"),
        "entropy fallback shape gauntlet must return typed entropy shape stages, not a silent bool"
    );
    assert!(
        !gates.contains("fn entropy_match_suppressed("),
        "the old boolean entropy_match_suppressed entry point must not return"
    );
    assert!(
        entropy.contains("if let Some(shape_stage) = entropy_match_suppression_stage(")
            && entropy.contains("crate::adjudicate::MatchCtx::for_entropy_fallback(")
            && entropy
                .contains("crate::adjudicate::EntropyFallbackSignal::ValueShape(shape_stage)")
            && entropy
                .contains("crate::adjudicate::EntropyFallbackSignal::NamedDetectorOwnedAssignment"),
        "phase2 entropy caller must route entropy fallback drops through the adjudicator context"
    );
    assert!(
        !gates.contains("StageId::EntropyValueShape(")
            && !entropy.contains("StageId::EntropyValueShape(")
            && !entropy.contains("StageId::EntropyNamedDetectorOwnedAssignment"),
        "entropy fallback gates/caller must not name adjudicator entropy StageIds directly"
    );
    assert!(
        adjudicate.contains("enum EntropyShapeStage")
            && adjudicate.contains("\"entropy_random_base64_blob\""),
        "adjudicate module must own entropy fallback suppression stage names"
    );
}

#[test]
fn entropy_generation_plausibility_rejections_route_through_adjudicator() {
    let src = scanner_src();
    let scanner = uncommented_code(&read(&src.join("entropy/scanner.rs")));
    let isolated = uncommented_code(&read(&src.join("entropy/isolated.rs")));
    let keywords = uncommented_code(&read(&src.join("entropy/keywords.rs")));
    let adjudicate = adjudicate_code(&src);

    assert!(
        scanner.contains("fn candidate_plausibility_rejection_stage(")
            && scanner.contains(") -> Option<StageId>"),
        "entropy candidate generation plausibility must return the adjudicator StageId, not a silent bool"
    );
    assert!(
        scanner.contains("candidate_plausibility_rejection_stage(")
            && scanner.contains("&candidate")
            && scanner.contains("crate::telemetry::is_dogfood_enabled()")
            && scanner.contains("crate::adjudicate::MatchCtx::for_entropy_generation(")
            && scanner.contains("crate::adjudicate::EntropyGenerationSignal::SuppressionStage(stage_id)")
            && scanner.contains("crate::adjudicate::record_suppression(None, &candidate, &ctx)"),
        "collect_line_candidates must record generation-side entropy drops through the adjudicator when dogfood is enabled"
    );
    assert!(
        keywords.contains("struct ExtractionRejection")
            && keywords.contains("pub(super) stage_id: StageId")
            && keywords.contains("EntropyShapeStage::ConcatenationFragmentLine")
            && scanner.contains("extract_candidates_with_rejections(")
            && scanner.contains("EntropyGenerationSignal::SuppressionStage(rejection.stage_id)"),
        "entropy extraction-time drops must carry typed adjudicator stages back to the collector"
    );
    assert!(
        isolated.contains("fn isolated_bare_secret_entropy_decision(")
            && isolated.contains(") -> Result<f64, StageId>")
            && isolated.contains("crate::telemetry::is_dogfood_enabled()")
            && isolated.contains("crate::adjudicate::MatchCtx::for_entropy_generation(")
            && isolated.contains("crate::adjudicate::EntropyGenerationSignal::SuppressionStage(stage_id)")
            && isolated.contains("crate::adjudicate::record_suppression(None, candidate, &ctx)"),
        "isolated bare entropy generation drops must carry typed adjudicator stages back to the collector"
    );
    assert!(
        !scanner.contains("crate::adjudicate::record_stage_suppression(None,")
            && !isolated.contains("crate::adjudicate::record_stage_suppression(None,"),
        "entropy generation paths must not bypass the adjudicator context with direct stage recording"
    );
    for reason in [
        "entropy_concatenation_fragment_line",
        "entropy_structured_dotted_too_short",
        "entropy_canonical_non_secret_shape",
        "entropy_credential_context_too_short",
        "entropy_keyword_free_too_short",
        "entropy_candidate_plausibility_rejected",
        "entropy_secret_plausibility_rejected",
    ] {
        assert!(
            !scanner.contains(&format!("\"{reason}\""))
                && !keywords.contains(&format!("\"{reason}\"")),
            "entropy scanner/keywords must not own the {reason} suppression reason"
        );
        assert!(
            !isolated.contains(&format!("\"{reason}\"")),
            "entropy isolated scanner must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate module must own the {reason} suppression reason"
        );
    }
}

#[test]
fn shape_suppression_telemetry_is_only_called_by_adjudicator() {
    let src = scanner_src();
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).expect("scanner src prefix");
        if rel == Path::new("telemetry.rs") || rel == Path::new("adjudicate/mod.rs") {
            continue;
        }
        let code = uncommented_code(&read(&path));
        if code.contains("record_shape_suppression(") {
            offenders.push(rel.display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "production code must route shape suppression telemetry through adjudicate, not call telemetry directly: {offenders:#?}"
    );
}

#[test]
fn example_suppression_telemetry_is_only_called_by_adjudicator() {
    let src = scanner_src();
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let rel = path.strip_prefix(&src).expect("scanner src prefix");
        if rel == Path::new("telemetry.rs") || rel == Path::new("adjudicate/mod.rs") {
            continue;
        }
        let code = uncommented_code(&read(&path));
        if code.contains("crate::telemetry::record_example_suppression(") {
            offenders.push(rel.display().to_string());
        }
    }

    assert!(
        offenders.is_empty(),
        "production code must route example suppression telemetry through adjudicate, not call telemetry directly: {offenders:#?}"
    );
}

#[test]
fn decoded_postprocess_example_drops_route_through_adjudicator() {
    let src = scanner_src();
    let code = uncommented_code(&read(&src.join("engine/scan_postprocess.rs")));
    assert!(
        code.contains("crate::adjudicate::record_match_example_suppression(")
            && code.contains("\"decoded_parent_example\"")
            && code.contains("\"decoded_reverse_placeholder\""),
        "decoded postprocess example/reverse drops must emit adjudicator-owned example telemetry"
    );
    assert!(
        !code.contains("crate::telemetry::record_example_suppression("),
        "scan_postprocess.rs must not bypass adjudicator for decoded suppression telemetry"
    );
}

#[test]
fn final_emit_context_hard_suppression_stays_out_of_scoring_owner() {
    let src = scanner_src();
    let adjudicate = adjudicate_code(&src);
    let confidence_policy = uncommented_code(&read(&src.join("confidence/policy.rs")));
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    let generic = uncommented_code(&read(&src.join("engine/phase2_generic.rs")));
    let entropy = uncommented_code(&read(&src.join("engine/phase2_entropy.rs")));
    let ml = uncommented_code(&read(&src.join("engine/scan_postprocess/ml.rs")));

    assert!(
        !src.join("engine/scoring.rs").exists()
            && !confidence_policy.contains("should_hard_suppress("),
        "candidate scoring must not hide context hard suppression behind None/scoring_rejected"
    );
    assert!(
        adjudicate.contains("fn final_emit_suppression_stage(")
            && adjudicate.contains("StageId::HardSuppressedContext")
            && adjudicate.contains("fn final_emit_stage(")
            && adjudicate.contains("fn finalize_report_candidate(")
            && adjudicate.contains("fn finalize_report_raw_match(")
            && adjudicate.contains("let credential = raw_match.credential.as_ref();")
            && !adjudicate.contains(
                "fn finalize_report_raw_match(\n    mut raw_match: RawMatch,\n    credential: &str,"
            )
            && process.contains("crate::adjudicate::finalize_report_candidate(")
            && generic.contains("crate::adjudicate::finalize_report_candidate(")
            && entropy.contains("crate::adjudicate::finalize_report_candidate(")
            && ml.contains("crate::adjudicate::finalize_report_raw_match("),
        "all final emit tails must route through adjudicate final report candidate helper, and raw-match finalization must derive the credential from RawMatch"
    );
    for (path, code) in [
        ("engine/process.rs", process.as_str()),
        ("engine/phase2_generic.rs", generic.as_str()),
        ("engine/phase2_entropy.rs", entropy.as_str()),
        ("engine/scan_postprocess/ml.rs", ml.as_str()),
    ] {
        assert!(
            !code.contains("crate::adjudicate::MatchCtx::for_final_emit("),
            "{path} must not build final emit contexts directly"
        );
    }
    assert!(
        !process.contains("crate::adjudicate::final_emit_suppression_stage(")
            && !generic.contains("crate::adjudicate::final_emit_suppression_stage(")
            && !entropy.contains("crate::adjudicate::final_emit_suppression_stage(")
            && !ml.contains("crate::adjudicate::final_emit_suppression_stage("),
        "engine code must not locally ask for a final emit stage and post-record it"
    );
}
