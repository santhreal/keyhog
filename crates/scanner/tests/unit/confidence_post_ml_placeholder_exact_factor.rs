//! Placeholder word applies 0.05 multiplier to ML score.

use keyhog_scanner::confidence::apply_post_ml_penalties;

#[test]
fn confidence_post_ml_placeholder_exact_factor() {
    let adjusted = apply_post_ml_penalties(1.0, "example_token_value_abc");
    assert!(
        (adjusted - 0.05).abs() < 1e-9,
        "placeholder word must multiply by 0.05: got {adjusted}"
    );
}
