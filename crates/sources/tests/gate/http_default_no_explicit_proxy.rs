//! LR1-A8 replacement gate: `http.rs` default proxy policy.

use keyhog_sources::http::HttpClientConfig;

#[test]
fn http_config_default_has_no_explicit_proxy_override() {
    let cfg = HttpClientConfig::default();
    assert!(cfg.proxy.is_none());
    assert!(cfg.effective_proxy().is_none());
}
