#[test]
fn web_redact_path_at() {
    let u="https://example.com/users/@me"; assert_eq!(keyhog_sources::testing::redact_url(u), u);
}
