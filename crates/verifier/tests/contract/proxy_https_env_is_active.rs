//! Contract: an ambient HTTPS_PROXY does NOT mark the verifier proxy active
//! it is ignored and neutralized via `.no_proxy()` (config-policy mandate +
//! security: an ambient proxy must never silently reroute secret-bearing
//! traffic).

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_https_env_is_active() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://burp:8080");
        }
        assert!(
            !proxy_is_active(None),
            "ambient HTTPS_PROXY must NOT activate the verifier proxy"
        );
    });
}
