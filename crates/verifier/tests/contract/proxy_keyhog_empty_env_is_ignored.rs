//! Contract: retired KEYHOG_PROXY='' env is ignored.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_keyhog_empty_env_is_ignored() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("KEYHOG_PROXY", "");
        }
        assert_eq!(proxy_is_active(None), false);
    });
}
