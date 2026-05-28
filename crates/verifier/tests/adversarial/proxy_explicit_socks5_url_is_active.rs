//! Verifier proxy edge: explicit socks5 proxy URL is active

use keyhog_verifier::proxy_is_active;
use crate::contract::support::with_proxy_contract_env;

#[test]
fn proxy_explicit_socks5_url_is_active() {
    with_proxy_contract_env(|| {
        assert!(proxy_is_active(Some("socks5://127.0.0.1:1080")));
    });
}
