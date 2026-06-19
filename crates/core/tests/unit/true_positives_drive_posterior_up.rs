//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn true_positives_drive_posterior_up() {
    let c = Calibration::default();
    for _ in 0..9 {
        c.record_outcome("aws-access-key", true);
    }
    // α = 10, β = 1 → mean = 10/11 ≈ 0.909
    let m = keyhog_core::testing::CoreTestApi::calibration_confidence_multiplier(
        &keyhog_core::testing::TestApi,
        &c,
        "aws-access-key",
    );
    assert!(m > 0.85, "expected >0.85, got {m}");
}
