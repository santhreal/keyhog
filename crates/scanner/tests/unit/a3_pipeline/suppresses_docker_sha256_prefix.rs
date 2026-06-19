use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn docker_digest_prefix_suppressed() {
    let body = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    assert!(should_suppress_known_example_credential(
        &format!("sha256:{body}"),
        None,
        CodeContext::Unknown,
    ));
}
