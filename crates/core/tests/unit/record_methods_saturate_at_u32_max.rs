//! Saturation increments clamp at u32::MAX instead of wrapping.

use keyhog_core::Calibration;

#[test]
fn record_methods_saturate_at_u32_max() {
    let c = Calibration::default();
    keyhog_core::testing::CoreTestApi::seed_calibration_counters(
        &keyhog_core::testing::TestApi,
        &c,
        "saturating",
        u32::MAX,
        u32::MAX,
    );
    c.record_outcome("saturating", true);
    c.record_outcome("saturating", false);
    let counters = c.counters("saturating");
    assert_eq!(counters.alpha, u32::MAX, "alpha must saturate at u32::MAX");
    assert_eq!(counters.beta, u32::MAX, "beta must saturate at u32::MAX");
    assert_eq!(
        keyhog_core::testing::CoreTestApi::beta_observations(
            &keyhog_core::testing::TestApi,
            &counters
        ),
        u32::MAX
    );
}
