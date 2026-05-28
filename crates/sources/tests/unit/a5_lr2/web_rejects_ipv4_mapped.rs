#[test]
fn web_rejects_ipv4_mapped() {
    assert!(keyhog_sources::testing::is_disallowed_web_host("http://[::ffff:127.0.0.1]/"));
}
