use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn mock_token_suppressed_in_comment() {
    assert!(known_example_suppressed(
        "MOCK_SECRET_VALUE",
        None,
        CodeContext::Comment,
    ));
}
