#[test]
fn post_ml_nan_sanitized() {
    let out = keyhog_scanner::testing::confidence::apply_post_ml_penalties(
        f64::NAN,
        "sk_test_123",
        false,
    );
    assert!(!out.is_nan());
}
