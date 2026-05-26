//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::calibration::Calibration;
#[test]
    fn fresh_detector_returns_uniform_prior() {
        let c = Calibration::empty();
        assert_eq!(c.confidence_multiplier("never-seen"), 0.5);
    }
