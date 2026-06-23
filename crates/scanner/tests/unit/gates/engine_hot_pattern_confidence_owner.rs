//! Gate: hot-pattern confidence policy has one confidence owner.

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
fn hot_pattern_confidence_routes_through_confidence_owner() {
    let src = scanner_src();
    let scoring = uncommented_code(&read(&src.join("confidence/policy.rs")));
    assert!(
        scoring.contains("fn hot_pattern_confidence(")
            && scoring.contains("const BASE_CONFIDENCE")
            && scoring.contains("finalize_report_confidence"),
        "confidence::policy must own hot-pattern base confidence plus report-confidence finalization"
    );

    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("crate::confidence::policy::hot_pattern_confidence("),
        "hot-pattern fast path must call the confidence owner directly"
    );
    for forbidden in [
        "known_prefix_confidence_floor",
        "apply_checksum_confidence",
        "base_confidence",
        "unwrap_or(0.7)",
    ] {
        assert!(
            !hot_patterns.contains(forbidden),
            "hot-pattern fast path must not own confidence policy token {forbidden:?}"
        );
    }
}
