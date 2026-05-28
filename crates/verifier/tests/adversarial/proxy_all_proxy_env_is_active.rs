//! Verifier proxy edge: ALL_PROXY alone must mark proxy as active

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_all_proxy_env_is_active() {
    with_proxy_contract_env(|| {
        for var in ["HTTPS_PROXY", "HTTP_PROXY", "KEYHOG_PROXY", "https_proxy", "http_proxy"] {
            unsafe { std::env::remove_var(var); }
        }
        unsafe { std::env::set_var("ALL_PROXY", "http://burp:8080"); }
        assert!(proxy_is_active(None));
        unsafe { std::env::remove_var("ALL_PROXY"); }
    });
}
