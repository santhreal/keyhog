//! Verifier proxy edge: whitespace HTTPS_PROXY is inactive

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_whitespace_https_proxy_not_active() {
    with_proxy_contract_env(|| {
        unsafe { std::env::set_var("HTTPS_PROXY", "   "); }
        assert!(!proxy_is_active(None));
        unsafe { std::env::remove_var("HTTPS_PROXY"); }
    });
}
