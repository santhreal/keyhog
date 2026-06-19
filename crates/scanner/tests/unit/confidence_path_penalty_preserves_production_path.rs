//! Production paths must not alter confidence.

use keyhog_scanner::testing::confidence::apply_path_confidence_penalties;

#[test]
fn confidence_path_penalty_preserves_production_path() {
    let adjusted = apply_path_confidence_penalties(0.72, Some("deploy/production/.env"), true);
    assert!(
        (adjusted - 0.72).abs() < 1e-9,
        "production path must preserve score: expected 0.72, got {adjusted}"
    );
}
