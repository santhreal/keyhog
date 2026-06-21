use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn docker_digest_prefix_suppressed() {
    let body = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    assert!(known_example_suppressed(
        &format!("sha256:{body}"),
        None,
        CodeContext::Unknown,
    ));
}
