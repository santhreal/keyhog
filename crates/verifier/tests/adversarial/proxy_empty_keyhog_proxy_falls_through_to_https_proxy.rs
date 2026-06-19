//! Verifier proxy edge: neither KEYHOG_PROXY nor an ambient HTTPS_PROXY can
//! activate the proxy — both are ignored (config-policy mandate + security).

use crate::contract::support::with_proxy_contract_env;
use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_empty_keyhog_proxy_falls_through_to_https_proxy() {
    with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("KEYHOG_PROXY", "");
        }
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://burp:8080");
        }
        assert!(
            !proxy_is_active(None),
            "neither KEYHOG_PROXY nor ambient HTTPS_PROXY may activate the proxy"
        );
        unsafe {
            std::env::remove_var("KEYHOG_PROXY");
        }
        unsafe {
            std::env::remove_var("HTTPS_PROXY");
        }
    });
}
