//! All signals present yields confidence exactly 1.0.

use keyhog_scanner::confidence::{compute_confidence, ConfidenceSignals};

#[test]
fn confidence_exact_max_score_one() {
    let signals = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: true,
        entropy: 8.0,
        keyword_nearby: true,
        sensitive_file: true,
        match_length: 128,
        has_companion: true,
    };
    assert_eq!(
        compute_confidence(&signals),
        1.0,
        "full signal set must normalize to 1.0"
    );
}
