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
