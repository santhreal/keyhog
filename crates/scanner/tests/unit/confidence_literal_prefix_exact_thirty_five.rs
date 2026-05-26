//! Literal prefix alone yields confidence 1.0 within its bucket.

use keyhog_scanner::confidence::{compute_confidence, ConfidenceSignals};

#[test]
fn confidence_literal_prefix_exact_thirty_five() {
    let signals = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: false,
        entropy: 0.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 8,
        has_companion: false,
    };
    assert!(
        (compute_confidence(&signals) - 0.35).abs() < 1e-9,
        "literal prefix alone must score 0.35/1.0, got {}",
        compute_confidence(&signals)
    );
}
