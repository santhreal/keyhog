//! Migrated from the inline `tests` module in `ml_scorer.rs` (removed to satisfy
//! `ml_scorer_no_inline_tests`). Pins the sigmoid saturation/interior behaviour
//! and the score-cache capacity through the `crate::testing` facade.

use keyhog_scanner::testing::{
    ml_score_cache_capacity_for_test as score_cache_capacity, ml_sigmoid_for_test as sigmoid,
    ml_sigmoid_saturation_for_test as sigmoid_saturation,
};

#[test]
fn sigmoid_saturates_symmetrically_at_named_bound() {
    let sat = sigmoid_saturation();
    // At/beyond the single-owner saturation bound the output clamps exactly.
    assert_eq!(sigmoid(sat), 1.0);
    assert_eq!(sigmoid(-sat), 0.0);
    assert_eq!(sigmoid(sat + 1.0), 1.0);
    assert_eq!(sigmoid(-sat - 1.0), 0.0);
    // The midpoint uses the rational branch, not the clamp.
    assert_eq!(sigmoid(0.0), 0.5);
    // Just inside the bound stays strictly interior (rational branch active).
    let just_inside = sigmoid(sat - 0.001);
    assert!(just_inside > 0.5 && just_inside < 1.0, "{just_inside}");
}

#[test]
fn score_cache_capacity_is_the_documented_bound() {
    assert_eq!(score_cache_capacity(), 256);
}
