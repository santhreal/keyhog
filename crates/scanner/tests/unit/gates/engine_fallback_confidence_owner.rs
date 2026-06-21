//! Gate: fallback confidence base-score policy has one engine owner.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
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
    let scoring = uncommented_code(&read(&src.join("engine/scoring.rs")));
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
            "engine::scoring must own fallback confidence policy token {required:?}"
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
