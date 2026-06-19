use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn rfc7519_specimen_suppressed() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIjox";
    assert!(should_suppress_known_example_credential(
        jwt,
        None,
        CodeContext::Unknown
    ));
}
