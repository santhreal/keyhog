#[test]
fn entropy_kw_dotted_value() {
    let val = "my.dotted.value";
    assert!(!keyhog_scanner::testing::looks_like_program_identifier(val));
}
