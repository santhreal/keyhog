#[test]
fn entropy_kw_short_pascal_foo() {
    let val = "Foo";
    assert!(!keyhog_scanner::testing::looks_like_program_identifier(val));
}
