use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn html_color_code_suppressed() {
    assert!(should_suppress_known_example_credential(
        "#AABBCC",
        None,
        CodeContext::Unknown,
    ));
}
