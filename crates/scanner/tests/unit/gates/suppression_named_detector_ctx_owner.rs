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
        process.contains("crate::adjudicate::adjudicate_match("),
        "engine/process.rs must route named-detector candidate decisions through adjudicate_match"
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
