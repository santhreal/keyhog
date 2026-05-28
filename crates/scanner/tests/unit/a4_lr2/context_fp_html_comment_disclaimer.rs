use keyhog_scanner::context::is_false_positive_match_context;

#[test]
fn context_fp_html_comment_disclaimer() {
    let text = r#"secret=xyz <!-- replace with your value -->"#;
    let offset = text.find("xyz").expect("needle");
    assert!(
        is_false_positive_match_context(text, offset, None)
    );
}
