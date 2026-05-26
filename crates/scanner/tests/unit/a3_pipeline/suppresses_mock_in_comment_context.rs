use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn mock_token_suppressed_in_comment() {
    assert!(should_suppress_known_example_credential(
        "MOCK_SECRET_VALUE",
        None,
        CodeContext::Comment,
    ));
}
