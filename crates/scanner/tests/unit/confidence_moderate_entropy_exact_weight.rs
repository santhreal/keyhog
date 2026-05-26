//! Moderate entropy tier earns exactly 0.05/0.20 = 0.25 confidence.

use keyhog_scanner::confidence::{compute_confidence, ConfidenceSignals};

#[test]
fn confidence_moderate_entropy_exact_weight() {
    let signals = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 3.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 32,
        has_companion: false,
    };
    assert!(
        (compute_confidence(&signals) - 0.05).abs() < 1e-9,
        "moderate entropy-only score must be 0.05/1.0, got {}",
        compute_confidence(&signals)
    );
}
