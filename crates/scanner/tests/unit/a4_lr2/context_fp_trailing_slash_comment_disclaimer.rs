use keyhog_scanner::testing::context::is_false_positive_match_context;

#[test]
fn context_fp_trailing_slash_comment_disclaimer() {
    let text = r#"const KEY = "AKIAIOSFODNN7EXAMPLE"; // not a real aws key"#;
    let offset = text.find("AKIA").expect("needle");
    assert!(is_false_positive_match_context(text, offset, None));
}
