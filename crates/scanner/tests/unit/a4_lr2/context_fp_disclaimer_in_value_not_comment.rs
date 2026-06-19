use keyhog_scanner::testing::context::is_false_positive_match_context;

#[test]
fn context_fp_disclaimer_in_value_not_comment() {
    let text = r#"password = "FakePassword!2024" + suffix"#;
    let offset = text.find("Fake").expect("needle");
    assert!(!is_false_positive_match_context(text, offset, None));
}
