//! KH-GAP-016: uncalibrated detectors must not halve confidence on fresh install.

use keyhog_scanner::testing::confidence::apply_calibration_multiplier;

#[test]
fn confidence_calibration_uncalibrated_passthrough() {
    let score = apply_calibration_multiplier(0.84, "nonexistent-detector-id-lr1-a4");
    assert!(
        (score - 0.84).abs() < 1e-9,
        "zero-observation detector must pass score through unchanged, got {score}"
    );
}
