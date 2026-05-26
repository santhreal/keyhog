//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::calibration::Calibration;
#[test]
    fn false_positives_drive_posterior_down() {
        let c = Calibration::empty();
        for _ in 0..9 {
            c.record_false_positive("noisy-detector");
        }
        // α = 1, β = 10 → mean = 1/11 ≈ 0.091
        let m = c.confidence_multiplier("noisy-detector");
        assert!(m < 0.15, "expected <0.15, got {m}");
    }
