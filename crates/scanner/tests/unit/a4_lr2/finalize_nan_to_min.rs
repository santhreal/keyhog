#[test]
fn finalize_nan_to_min() {
    let out = keyhog_scanner::testing::confidence::finalize_confidence(f64::NAN);
    assert!(!out.is_nan());
    assert_eq!(out, 0.0);
}
