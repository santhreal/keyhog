//! Verifier proxy edge: empty KEYHOG_PROXY falls through

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_empty_keyhog_proxy_falls_through_to_https_proxy() {
    with_proxy_contract_env(|| {
        unsafe { std::env::set_var("KEYHOG_PROXY", ""); }
        unsafe { std::env::set_var("HTTPS_PROXY", "http://burp:8080"); }
        assert!(proxy_is_active(None));
        unsafe { std::env::remove_var("KEYHOG_PROXY"); }
        unsafe { std::env::remove_var("HTTPS_PROXY"); }
    });
}
