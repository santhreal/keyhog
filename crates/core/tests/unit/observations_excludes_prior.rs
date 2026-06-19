//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::Calibration;
#[test]
fn observations_excludes_prior() {
    let c = Calibration::default();
    assert_eq!(
        keyhog_core::testing::CoreTestApi::beta_observations(
            &keyhog_core::testing::TestApi,
            &c.counters("x")
        ),
        0
    );
    c.record_outcome("x", true);
    c.record_outcome("x", false);
    assert_eq!(
        keyhog_core::testing::CoreTestApi::beta_observations(
            &keyhog_core::testing::TestApi,
            &c.counters("x")
        ),
        2
    );
}
