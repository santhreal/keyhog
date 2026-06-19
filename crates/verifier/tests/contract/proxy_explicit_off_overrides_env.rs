//! Contract: explicit `off` disables proxy even when HTTPS_PROXY is set.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_explicit_off_overrides_env() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://corp-burp:8080");
        }
        assert!(!proxy_is_active(Some("off")));
    });
}
