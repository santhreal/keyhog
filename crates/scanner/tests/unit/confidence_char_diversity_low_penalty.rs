//! Low char diversity applies 0.1 multiplier.

use keyhog_scanner::testing::confidence::apply_post_ml_penalties;

#[test]
fn confidence_char_diversity_low_penalty() {
    let adjusted = apply_post_ml_penalties(1.0, "abababababababababab", false);
    assert!(
        (adjusted - 0.1).abs() < 1e-9,
        "low diversity must multiply by 0.1: got {adjusted}"
    );
}
