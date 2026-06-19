//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn false_positives_drive_posterior_down() {
    let c = Calibration::default();
    for _ in 0..9 {
        c.record_outcome("noisy-detector", false);
    }
    // α = 1, β = 10 → mean = 1/11 ≈ 0.091
    let m = keyhog_core::testing::CoreTestApi::calibration_confidence_multiplier(
        &keyhog_core::testing::TestApi,
        &c,
        "noisy-detector",
    );
    assert!(m < 0.15, "expected <0.15, got {m}");
}
