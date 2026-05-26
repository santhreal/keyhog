//! Long repeat run applies 0.1 multiplier.

use keyhog_scanner::confidence::apply_post_ml_penalties;

#[test]
fn confidence_max_repeat_run_penalty() {
    let adjusted = apply_post_ml_penalties(1.0, "abcdefghiiiiiiiiii");
    assert!(
        (adjusted - 0.1).abs() < 1e-9,
        "long repeat run >0.5 must multiply by 0.1: got {adjusted}"
    );
}
