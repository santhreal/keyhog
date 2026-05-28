use keyhog_scanner::context::is_false_positive_match_context;

#[test]
fn context_fp_trailing_hash_comment_disclaimer() {
    let text = r#"API_TOKEN=ghp_1234567890abcdef1234567890abcdef123456 # fake credential, demo only"#;
    let offset = text.find("ghp_").expect("needle");
    assert!(
        is_false_positive_match_context(text, offset, None)
    );
}
