#[test]
fn http_proxy_off_preserved() {
    let cfg = keyhog_sources::http::HttpClientConfig {
        proxy: Some("off".into()),
        ..Default::default()
    };
    assert_eq!(
        keyhog_sources::testing::http_effective_proxy(&cfg).as_deref(),
        Some("off")
    );
}
