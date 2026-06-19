use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn fake_keyword_suppresses_placeholder() {
    assert!(should_suppress_known_example_credential(
        "api_key_FAKE_12345",
        None,
        CodeContext::Unknown,
    ));
}
