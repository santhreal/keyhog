//! Missing path still sanitizes but preserves finite score.

use keyhog_scanner::confidence::apply_path_confidence_penalties;

#[test]
fn confidence_path_penalty_none_path_passes_through() {
    let adjusted = apply_path_confidence_penalties(0.55, None, true);
    assert!(
        (adjusted - 0.55).abs() < 1e-9,
        "None path must pass score through: expected 0.55, got {adjusted}"
    );
}
