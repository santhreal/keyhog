use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn rfc7519_specimen_suppressed() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIjox";
    assert!(known_example_suppressed(jwt, None, CodeContext::Unknown));
}
