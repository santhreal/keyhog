use keyhog_scanner::confidence::{compute_confidence, ConfidenceSignals};
use keyhog_scanner::entropy::{HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD};
#[test]
fn high_confidence_with_prefix_and_entropy() {
    let signals = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: false,
        entropy: 5.2,
        keyword_nearby: true,
        sensitive_file: true,
        match_length: 50,
        has_companion: false,
    };
    let score = compute_confidence(&signals);
    assert!(score > 0.6, "score was {}", score);
}

#[test]
fn low_confidence_generic_hex() {
    let signals = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 3.5,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 32,
        has_companion: false,
    };
    let score = compute_confidence(&signals);
    assert!(score < 0.3, "score was {}", score);
}

#[test]
fn medium_confidence_with_context() {
    let signals = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: true,
        entropy: 4.8,
        keyword_nearby: true,
        sensitive_file: false,
        match_length: 40,
        has_companion: false,
    };
    let score = compute_confidence(&signals);
    assert!(score > 0.4 && score < 0.8, "score was {}", score);
}

#[test]
fn low_entropy_penalty_variants() {
    let penalized = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: false,
        entropy: 1.5,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 32,
        has_companion: false,
    };
    assert!(compute_confidence(&penalized) < 0.5);

    let no_penalty = ConfidenceSignals {
        match_length: 10,
        entropy: 1.0,
        ..penalized
    };
    let score = compute_confidence(&no_penalty);
    assert!((score - 0.35).abs() < 1e-9, "score was {}", score);
}

#[test]
fn edge_weight_cases() {
    let zero = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: 0.0,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 0,
        has_companion: false,
    };
    assert_eq!(compute_confidence(&zero), 0.0);

    let full = ConfidenceSignals {
        has_literal_prefix: true,
        has_context_anchor: true,
        entropy: 8.0,
        keyword_nearby: true,
        sensitive_file: true,
        match_length: 128,
        has_companion: true,
    };
    assert_eq!(compute_confidence(&full), 1.0);
}

#[test]
fn entropy_weight_tiers() {
    let very_high = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: false,
        entropy: VERY_HIGH_ENTROPY_THRESHOLD,
        keyword_nearby: false,
        sensitive_file: false,
        match_length: 32,
        has_companion: false,
    };
    assert!((compute_confidence(&very_high) - 0.2).abs() < 1e-9);

    let high = ConfidenceSignals {
        entropy: HIGH_ENTROPY_THRESHOLD,
        ..very_high
    };
    assert!((compute_confidence(&high) - 0.12).abs() < 1e-9);

    let moderate = ConfidenceSignals {
        entropy: 3.0,
        ..very_high
    };
    assert!((compute_confidence(&moderate) - 0.05).abs() < 1e-9);
}

#[test]
fn context_keyword_and_companion_weights_stack() {
    let stacked = ConfidenceSignals {
        has_literal_prefix: false,
        has_context_anchor: true,
        entropy: 0.0,
        keyword_nearby: true,
        sensitive_file: false,
        match_length: 20,
        has_companion: false,
    };
    assert!((compute_confidence(&stacked) - 0.18).abs() < 1e-9);

    let companion = ConfidenceSignals {
        has_context_anchor: false,
        keyword_nearby: false,
        match_length: 24,
        has_companion: true,
        ..stacked
    };
    assert!((compute_confidence(&companion) - 0.03).abs() < 1e-9);
}
