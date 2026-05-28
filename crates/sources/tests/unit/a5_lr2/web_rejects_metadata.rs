#[test]
fn web_rejects_metadata() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://169.254.169.254/latest/meta-data/"));
}
