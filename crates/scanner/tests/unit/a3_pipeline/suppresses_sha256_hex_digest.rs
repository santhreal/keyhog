use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn bare_sha256_hex_suppressed() {
    let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    assert!(known_example_suppressed(sha, None, CodeContext::Unknown));
}
