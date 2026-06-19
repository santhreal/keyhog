use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn bare_sha256_hex_suppressed() {
    let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(should_suppress_known_example_credential(
        sha,
        None,
        CodeContext::Unknown
    ));
}
