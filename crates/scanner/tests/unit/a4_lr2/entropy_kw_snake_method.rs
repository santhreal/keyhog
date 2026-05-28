#[test]
fn entropy_kw_snake_method() {
    let val = "my_long_helper_function_name";
    assert!(keyhog_scanner::testing::looks_like_program_identifier(val));
}
