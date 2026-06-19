#[test]
fn calibration_nan_sanitized() {
    let out = keyhog_scanner::testing::confidence::apply_calibration_multiplier(
        f64::NAN,
        "stripe-secret-key",
    );
    assert!(!out.is_nan());
}
