//! Migrated from src/probabilistic_gate.rs

use keyhog_scanner::testing::ProbabilisticGate;

#[test]
fn realistic_secret_passes() {
    // GitHub PAT shape (varied bigrams, length 40).
    assert!(ProbabilisticGate::looks_promising(concat!(
        "gh",
        "p_aBcD1234EFgh5678ijklMNop9012qrSTuvWX"
    )));
}

#[test]
fn uuid_with_dashes_is_rejected() {
    assert!(!ProbabilisticGate::looks_promising(
        "550e8400-e29b-41d4-a716-446655440000"
    ));
}

#[test]
fn short_input_passes_through() {
    // <16 bytes (gating returns true regardless).
    assert!(ProbabilisticGate::looks_promising("ghp_short"));
}

#[test]
fn pure_repetition_is_rejected() {
    assert!(!ProbabilisticGate::looks_promising(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ));
}
