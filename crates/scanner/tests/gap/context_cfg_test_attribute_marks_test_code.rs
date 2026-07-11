use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_cfg_test_attribute_marks_following_line_as_test_code() {
    let lines = [
        concat!("#[cfg(", "test)]"),
        r#"    let secret = "sk-proj-abc123def456";"#,
    ];
    assert_eq!(
        infer_context(&lines, 1, None),
        CodeContext::TestCode,
        "code under a cfg(test) attribute must classify as TestCode",
    );
}
