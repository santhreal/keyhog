use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn bare_token_in_docs_suppressed() {
    assert!(known_example_suppressed(
        "TOKEN",
        None,
        CodeContext::Documentation,
    ));
}
