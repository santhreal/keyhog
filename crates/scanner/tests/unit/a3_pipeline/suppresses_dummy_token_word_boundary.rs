use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn dummy_token_in_credential_is_suppressed() {
    assert!(known_example_suppressed(
        "sk_live_DUMMY_not_real",
        None,
        CodeContext::Assignment,
    ));
}
