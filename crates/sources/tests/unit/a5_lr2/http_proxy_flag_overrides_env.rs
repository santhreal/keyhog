//! `KEYHOG_PROXY` is never consulted: the explicit `--proxy` field is the only
//! thing that sets a proxy, and with no field the env is ignored (returns None,
//! not the env value). Config-policy mandate + security: an ambient proxy must
//! not silently reroute secret-verification traffic.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[test]
fn http_proxy_flag_overrides_env() {
    std::env::set_var("KEYHOG_PROXY", "http://env:8080");

    // Explicit flag set: that value is used verbatim (env irrelevant).
    let with_flag = keyhog_sources::http::HttpClientConfig {
        proxy: Some("http://flag:9090".into()),
        ..Default::default()
    };
    assert_eq!(
        TestApi.http_effective_proxy(&with_flag).as_deref(),
        Some("http://flag:9090"),
    );

    // No flag: the env var is IGNORED — effective proxy is None, NOT the env
    // value. This is the security-load-bearing assertion.
    let no_flag = keyhog_sources::http::HttpClientConfig::default();
    assert_eq!(
        TestApi.http_effective_proxy(&no_flag),
        None,
        "KEYHOG_PROXY must not set a proxy when --proxy is unset",
    );

    std::env::remove_var("KEYHOG_PROXY");
}
