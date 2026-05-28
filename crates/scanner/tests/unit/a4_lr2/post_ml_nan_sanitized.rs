use keyhog_scanner::confidence;

#[test]
fn post_ml_nan_sanitized() {
    let out = keyhog_scanner::confidence::apply_post_ml_penalties(f64::NAN, "sk_test_123");
    assert!(!out.is_nan());
}
