//! Sensitive file alone yields confidence 1.0 (only signal present).

use keyhog_scanner::testing::confidence::{compute_confidence, ConfidenceSignals};

#[test]
fn confidence_sensitive_file_weight_ten_percent() {
    let signals = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 0.0,
        keyword_nearby: false,
        sensitive_file: true,
        match_length: 8,
        has_companion: false,
    };
    assert!(
        (compute_confidence(&signals) - 0.10).abs() < 1e-9,
        "sensitive_file-only score must be 0.10/1.0, got {}",
        compute_confidence(&signals)
    );
}
