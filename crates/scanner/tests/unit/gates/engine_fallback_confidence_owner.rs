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
fn entropy_and_generic_fallback_confidence_route_through_scoring_owner() {
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
        entropy.contains("super::scoring::entropy_fallback_confidence("),
        "entropy fallback must ask the scoring owner for its base confidence"
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
        generic.contains("super::scoring::generic_secret_confidence("),
        "generic fallback must ask the scoring owner for its base confidence"
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
fn report_confidence_tail_routes_through_scoring_owner() {
    let src = scanner_src();
    let owner = src.join("confidence/policy.rs");
    let scoring = uncommented_code(&read(&owner));
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

    for path in [
        "engine/process.rs",
        "engine/scan_postprocess/ml.rs",
        "engine/phase2_entropy.rs",
        "engine/phase2_generic.rs",
    ] {
        let code = uncommented_code(&read(&src.join(path)));
        assert!(
            code.contains("super::scoring::finalize_report_confidence("),
            "{path} must route final report confidence through engine::scoring"
        );
    }
    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("super::scoring::hot_pattern_confidence("),
        "hot patterns must route final report confidence through the hot scoring owner"
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
