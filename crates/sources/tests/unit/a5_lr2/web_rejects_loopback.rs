#[test]
fn web_rejects_loopback() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://127.0.0.1/"));
}
