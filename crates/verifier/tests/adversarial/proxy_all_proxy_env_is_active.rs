//! Verifier proxy edge: ambient ALL_PROXY is IGNORED, no env var may activate
//! the proxy (config-policy mandate + security: an ambient proxy must never
//! silently reroute the verifier's secret-bearing traffic).

use crate::contract::support::with_proxy_contract_env;
use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_all_proxy_env_is_active() {
    with_proxy_contract_env(|| {
        for var in [
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "KEYHOG_PROXY",
            "https_proxy",
            "http_proxy",
        ] {
            unsafe {
                std::env::remove_var(var);
            }
        }
        unsafe {
            std::env::set_var("ALL_PROXY", "http://burp:8080");
        }
        assert!(
            !proxy_is_active(None),
            "ambient ALL_PROXY must NOT activate the verifier proxy"
        );
        unsafe {
            std::env::remove_var("ALL_PROXY");
        }
    });
}
