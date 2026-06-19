//! Contract: retired KEYHOG_PROXY='off' env is ignored.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_keyhog_off_env_is_ignored() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("KEYHOG_PROXY", "off");
        }
        assert_eq!(proxy_is_active(None), false);
    });
}
