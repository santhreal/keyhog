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

#[test]
fn engine_uses_typed_named_detector_suppression_context() {
    let src = scanner_src();
    let api = read(&src.join("suppression/api.rs"));
    assert!(
        api.contains("struct NamedDetectorSuppressionCtx")
            && api.contains("fn suppress_named_detector_finding("),
        "suppression::api must expose the typed named-detector suppression entry point"
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
    assert!(
        process.contains("crate::adjudicate::record_suppression("),
        "engine/process.rs must route named-detector candidate decisions through the adjudicator recorder"
    );
    assert!(
        !process.contains("suppress_named_detector_finding("),
        "engine/process.rs must not call suppress_named_detector_finding directly; the adjudicator owns the decision"
    );
}

#[test]
fn engine_process_early_suppression_reasons_live_in_adjudicator() {
    let src = scanner_src();
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    let adjudicate = uncommented_code(&read(&src.join("adjudicate/mod.rs")));
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
        "scoring_rejected",
        "below_min_confidence",
    ] {
        assert!(
            !process.contains(&format!("\"{reason}\"")),
            "engine/process.rs must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate/mod.rs must own the {reason} suppression reason"
        );
    }
}

#[test]
fn generic_bridge_suppression_reasons_route_through_adjudicator() {
    let src = scanner_src();
    let generic = uncommented_code(&read(&src.join("engine/phase2_generic.rs")));
    let adjudicate = uncommented_code(&read(&src.join("adjudicate/mod.rs")));

    assert!(
        generic.contains("crate::adjudicate::record_stage_suppression("),
        "engine/phase2_generic.rs must route generic suppression telemetry through the adjudicator"
    );

    for reason in [
        "generic_named_detector_owned_keyword",
        "bare_auth_unstructured",
        "generic_below_min_confidence",
    ] {
        assert!(
            !generic.contains(&format!("\"{reason}\"")),
            "engine/phase2_generic.rs must not own the {reason} suppression reason"
        );
        assert!(
            adjudicate.contains(&format!("\"{reason}\"")),
            "adjudicate/mod.rs must own the {reason} suppression reason"
        );
    }
}

#[test]
fn entropy_and_ml_emit_reject_reasons_route_through_adjudicator() {
    let src = scanner_src();
    let entropy = uncommented_code(&read(&src.join("engine/phase2_entropy.rs")));
    let ml = uncommented_code(&read(&src.join("engine/scan_postprocess/ml.rs")));
    let adjudicate = uncommented_code(&read(&src.join("adjudicate/mod.rs")));

    assert!(
        entropy.contains("crate::adjudicate::record_stage_suppression("),
        "engine/phase2_entropy.rs must route entropy suppressions through the adjudicator"
    );
    assert!(
        ml.contains("crate::adjudicate::record_stage_suppression("),
        "engine/scan_postprocess/ml.rs must route pending-match suppressions through the adjudicator"
    );

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
            "adjudicate/mod.rs must own the {reason} suppression reason"
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
fn final_emit_context_hard_suppression_stays_out_of_scoring_owner() {
    let src = scanner_src();
    let scoring = uncommented_code(&read(&src.join("engine/scoring.rs")));
    let process = uncommented_code(&read(&src.join("engine/process.rs")));
    let ml = uncommented_code(&read(&src.join("engine/scan_postprocess/ml.rs")));

    assert!(
        !scoring.contains("should_hard_suppress("),
        "engine/scoring.rs must not hide context hard suppression behind None/scoring_rejected"
    );
    assert!(
        process.contains("StageId::HardSuppressedContext")
            && ml.contains("StageId::HardSuppressedContext"),
        "both direct and ML final emit tails must report hard_suppressed_context through adjudication"
    );
}
