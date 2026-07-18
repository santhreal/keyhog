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
    // keyhog's OWN builder must turn the default config into a buildable async
    // client. The `expect`s ARE the assertions (a failure panics the test); we no
    // longer re-test reqwest's request builder (`client.get(...).build().is_ok()`),
    // which exercised the dependency rather than keyhog.
    let builder = TestApi
        .http_async_client_builder(&config)
        .expect("keyhog default config must produce an async client builder");
    builder
        .build()
        .expect("keyhog default config must build a working async client");
}

#[test]
fn http_client_config_insecure_tls_reflects_explicit_flag() {
    let mut config = HttpClientConfig::default();
    assert!(!TestApi.http_effective_insecure_tls(&config));
    config.insecure_tls = true;
    assert!(TestApi.http_effective_insecure_tls(&config));
}

#[test]
fn http_client_config_explicit_proxy_is_preserved() {
    let mut config = HttpClientConfig::default();
    assert_eq!(TestApi.http_effective_proxy(&config), None);

    config.proxy = Some("http://proxy.example:8080".into());
    assert_eq!(
        TestApi.http_effective_proxy(&config),
        Some("http://proxy.example:8080".into())
    );
}

#[test]
fn http_blocking_client_builder_with_allow_private_endpoint_builds() {
    let config = HttpClientConfig {
        allow_private_endpoint: true,
        ..HttpClientConfig::default()
    };
    let builder = TestApi
        .http_blocking_client_builder(&config)
        .expect("keyhog allow-private config must produce a blocking client builder");
    builder
        .build()
        .expect("keyhog allow-private config must build a working blocking client");
}
