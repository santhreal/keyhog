use keyhog_scanner::testing::context::is_false_positive_match_context;

#[test]
fn context_fp_ordinary_comment_no_disclaimer() {
    let text = r#"const KEY = concat!("AK", "IA1234567890ABCD12"); // production key, see vault"#;
    let offset = text.find("1234567890").expect("needle");
    assert!(!is_false_positive_match_context(text, offset, None));
}
