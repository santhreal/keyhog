//! LR1-A8 replacement gate: `http.rs` default proxy policy.

use keyhog_sources::http::HttpClientConfig;
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn http_config_default_has_no_explicit_proxy_override() {
    let cfg = HttpClientConfig::default();
    assert!(cfg.proxy.is_none());
    assert!(TestApi.http_effective_proxy(&cfg).is_none());
}
