//! Verifier proxy edge: KEYHOG_PROXY=off disables HTTPS_PROXY

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_keyhog_off_disables_https_proxy() {
    with_proxy_contract_env(|| {
        unsafe { std::env::set_var("HTTPS_PROXY", "http://burp:8080"); }
        unsafe { std::env::set_var("KEYHOG_PROXY", "off"); }
        assert!(!proxy_is_active(None));
        unsafe { std::env::remove_var("HTTPS_PROXY"); }
        unsafe { std::env::remove_var("KEYHOG_PROXY"); }
    });
}
