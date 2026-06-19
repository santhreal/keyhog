//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn fresh_detector_returns_uniform_prior() {
    let c = Calibration::default();
    assert_eq!(
        keyhog_core::testing::CoreTestApi::calibration_confidence_multiplier(
            &keyhog_core::testing::TestApi,
            &c,
            "never-seen"
        ),
        0.5
    );
}
