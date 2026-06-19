#[test]
fn path_penalty_nan_sanitized() {
    let out = keyhog_scanner::testing::confidence::apply_path_confidence_penalties(
        f64::NAN,
        Some("tests/fixtures/.env"),
        true,
    );
    assert!(!out.is_nan());
}
