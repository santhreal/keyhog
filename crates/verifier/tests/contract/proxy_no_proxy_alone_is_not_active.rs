//! Contract: NO_PROXY alone does not activate proxy routing.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_no_proxy_alone_is_not_active() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("NO_PROXY", "*.internal.corp");
        }
        assert!(
            !proxy_is_active(None),
            "NO_PROXY alone must not mark proxy active"
        );
    });
}
