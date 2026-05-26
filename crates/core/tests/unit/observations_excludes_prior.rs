//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::calibration::Calibration;
#[test]
fn observations_excludes_prior() {
    let c = Calibration::empty();
    assert_eq!(c.counters("x").observations(), 0);
    c.record_true_positive("x");
    c.record_false_positive("x");
    assert_eq!(c.counters("x").observations(), 2);
}
