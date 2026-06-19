#![cfg(any(feature = "web", feature = "github", feature = "slack", feature = "s3"))]

use keyhog_sources::http::HttpClientConfig;
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn http_client_config_effective_proxy_honors_explicit_off() {
    let mut config = HttpClientConfig::default();
    config.proxy = Some("off".into());
    assert_eq!(
        TestApi.http_effective_proxy(&config).as_deref(),
        Some("off")
    );
}

#[test]
fn http_client_config_default_builds_async_client() {
    let config = HttpClientConfig::default();
    let builder = TestApi
        .http_async_client_builder(&config)
        .expect("default config must build");
    let client = builder.build().expect("async client must build");
    assert!(client.get("https://example.com").build().is_ok());
}
