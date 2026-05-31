//! Test-like path components halve confidence exactly.

use keyhog_scanner::confidence::apply_path_confidence_penalties;

#[test]
fn confidence_path_penalty_halves_test_dir() {
    let adjusted = apply_path_confidence_penalties(0.8, Some("tests/integration/.env"), true);
    assert!(
        (adjusted - 0.4).abs() < 1e-9,
        "test path must halve score: expected 0.4, got {adjusted}"
    );
}

#[test]
fn confidence_path_penalty_skipped_when_disabled() {
    let adjusted = apply_path_confidence_penalties(0.8, Some("tests/integration/.env"), false);
    assert!(
        (adjusted - 0.8).abs() < 1e-9,
        "penalize=false must preserve score even under a test path: expected 0.8, got {adjusted}"
    );
}
