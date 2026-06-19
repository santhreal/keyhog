//! Contract: KEYHOG_PROXY='' semantics.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_empty_is_not_active() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("KEYHOG_PROXY", "");
        }
        assert_eq!(proxy_is_active(None), false);
    });
}
