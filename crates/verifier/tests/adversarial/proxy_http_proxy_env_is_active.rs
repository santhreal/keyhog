//! Verifier proxy edge: ambient HTTP_PROXY is IGNORED, no env var may activate
//! the proxy (config-policy mandate + security).

use crate::contract::support::with_proxy_contract_env;
use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_http_proxy_env_is_active() {
    with_proxy_contract_env(|| {
        for var in ["HTTPS_PROXY", "KEYHOG_PROXY", "ALL_PROXY"] {
            unsafe {
                std::env::remove_var(var);
            }
        }
        unsafe {
            std::env::set_var("HTTP_PROXY", "http://proxy.example:3128");
        }
        assert!(
            !proxy_is_active(None),
            "ambient HTTP_PROXY must NOT activate the verifier proxy"
        );
        unsafe {
            std::env::remove_var("HTTP_PROXY");
        }
    });
}
