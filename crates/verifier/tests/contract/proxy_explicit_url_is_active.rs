//! Contract: an explicit `--proxy` URL activates the proxy; a `KEYHOG_PROXY`
//! env var does NOT (it is ignored entirely).

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_explicit_url_is_active() {
    super::support::with_proxy_contract_env(|| {
        unsafe {
            std::env::set_var("KEYHOG_PROXY", "http://burp:8080");
        }
        // Env is ignored: with no explicit proxy, the proxy is not active even
        // though KEYHOG_PROXY is set.
        assert_eq!(proxy_is_active(None), false, "KEYHOG_PROXY must be ignored");
        // The explicit flag value is what activates the proxy.
        assert_eq!(proxy_is_active(Some("http://burp:8080")), true);
    });
}
