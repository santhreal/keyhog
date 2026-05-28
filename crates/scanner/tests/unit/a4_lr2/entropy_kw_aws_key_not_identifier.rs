#[test]
fn entropy_kw_aws_key_not_identifier() {
    let val = "AKIAIOSFODNN7EXAMPLE";
    assert!(!keyhog_scanner::testing::looks_like_program_identifier(val));
}
