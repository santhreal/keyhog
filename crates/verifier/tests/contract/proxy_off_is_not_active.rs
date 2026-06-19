//! Contract: KEYHOG_PROXY='off' semantics.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_off_is_not_active() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("KEYHOG_PROXY", "off");
        }
        assert_eq!(proxy_is_active(None), false);
    });
}
