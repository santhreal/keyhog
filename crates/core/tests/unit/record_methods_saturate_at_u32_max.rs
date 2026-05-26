//! Saturation increments clamp at u32::MAX instead of wrapping.

use keyhog_core::calibration::Calibration;

#[test]
fn record_methods_saturate_at_u32_max() {
    let c = Calibration::empty();
    c.test_seed_counters("saturating", u32::MAX, u32::MAX);
    c.record_true_positive("saturating");
    c.record_false_positive("saturating");
    let counters = c.counters("saturating");
    assert_eq!(counters.alpha, u32::MAX, "alpha must saturate at u32::MAX");
    assert_eq!(counters.beta, u32::MAX, "beta must saturate at u32::MAX");
    assert_eq!(counters.observations(), u32::MAX);
}
