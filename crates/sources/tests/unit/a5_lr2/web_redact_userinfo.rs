#[test]
fn web_redact_userinfo() {
    assert_eq!(keyhog_sources::testing::redact_url("https://u:SECRET@host/p"), "https://***@host/p");
}
