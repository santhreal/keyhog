use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn fake_keyword_suppresses_placeholder() {
    assert!(known_example_suppressed(
        "api_key_FAKE_12345",
        None,
        CodeContext::Unknown,
    ));
}
