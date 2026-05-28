#[test]
fn entropy_kw_all_caps_constant() {
    let val = "ALLOWED_HOSTS";
    assert!(!keyhog_scanner::testing::looks_like_program_identifier(val));
}
