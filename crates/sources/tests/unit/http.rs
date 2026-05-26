use keyhog_sources::http::{async_client_builder, HttpClientConfig};

#[test]
fn http_client_config_effective_proxy_honors_explicit_off() {
    let mut config = HttpClientConfig::default();
    config.proxy = Some("off".into());
    assert_eq!(config.effective_proxy().as_deref(), Some("off"));
}

#[test]
fn http_client_config_default_builds_async_client() {
    let config = HttpClientConfig::default();
    let builder = async_client_builder(&config).expect("default config must build");
    let client = builder.build().expect("async client must build");
    assert!(client.get("https://example.com").build().is_ok());
}
