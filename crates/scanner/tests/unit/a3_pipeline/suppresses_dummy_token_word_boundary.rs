use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn dummy_token_in_credential_is_suppressed() {
    assert!(should_suppress_known_example_credential(
        "sk_live_DUMMY_not_real",
        None,
        CodeContext::Assignment,
    ));
}
