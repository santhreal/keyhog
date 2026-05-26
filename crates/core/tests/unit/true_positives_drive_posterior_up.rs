//! Migrated from `src/calibration.rs` inline tests.
use keyhog_core::calibration::Calibration;
#[test]
fn true_positives_drive_posterior_up() {
    let c = Calibration::empty();
    for _ in 0..9 {
        c.record_true_positive("aws-access-key");
    }
    // α = 10, β = 1 → mean = 10/11 ≈ 0.909
    let m = c.confidence_multiplier("aws-access-key");
    assert!(m > 0.85, "expected >0.85, got {m}");
}
