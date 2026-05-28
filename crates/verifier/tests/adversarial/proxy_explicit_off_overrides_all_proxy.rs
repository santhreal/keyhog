//! Verifier proxy edge: explicit off overrides ALL_PROXY

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_explicit_off_overrides_all_proxy() {
    with_proxy_contract_env(|| {
        unsafe { std::env::set_var("ALL_PROXY", "http://burp:8080"); }
        assert!(!proxy_is_active(Some("off")));
        unsafe { std::env::remove_var("ALL_PROXY"); }
    });
}
