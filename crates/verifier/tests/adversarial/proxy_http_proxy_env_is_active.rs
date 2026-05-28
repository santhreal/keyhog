//! Verifier proxy edge: HTTP_PROXY env alone is active

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_http_proxy_env_is_active() {
    with_proxy_contract_env(|| {
        for var in ["HTTPS_PROXY", "KEYHOG_PROXY", "ALL_PROXY"] {
            unsafe { std::env::remove_var(var); }
        }
        unsafe { std::env::set_var("HTTP_PROXY", "http://proxy.example:3128"); }
        assert!(proxy_is_active(None));
        unsafe { std::env::remove_var("HTTP_PROXY"); }
    });
}
