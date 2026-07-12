//! Gate: hot-pattern confidence policy has one owner.

use super::support::*;

#[test]
fn hot_pattern_confidence_routes_through_confidence_owner() {
    let src = scanner_src();
    let scoring = uncommented_code(&read(&src.join("confidence/policy.rs")));
    assert!(
        !scoring.contains("fn hot_pattern_confidence(")
            && scoring.contains("fn finalize_report_confidence("),
        "confidence::policy must not keep a hot-pattern-only confidence fork"
    );

    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    assert!(
        hot_patterns.contains("self.process_match("),
        "hot-pattern fast path must route through process_match for shared confidence policy"
    );
    for forbidden in [
        "hot_pattern_confidence",
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
