#[test]
fn web_accepts_example() {
    assert!(!keyhog_sources::testing::is_disallowed_web_host("https://example.com/"));
}
