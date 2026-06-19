use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn brace_template_suppressed() {
    assert!(should_suppress_known_example_credential(
        "{API_TOKEN}",
        None,
        CodeContext::Assignment,
    ));
}
