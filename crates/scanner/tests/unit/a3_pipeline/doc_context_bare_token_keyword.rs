use keyhog_scanner::context::CodeContext;
use keyhog_scanner::should_suppress_known_example_credential;

#[test]
fn bare_token_in_docs_suppressed() {
    assert!(should_suppress_known_example_credential(
        "TOKEN",
        None,
        CodeContext::Documentation,
    ));
}
