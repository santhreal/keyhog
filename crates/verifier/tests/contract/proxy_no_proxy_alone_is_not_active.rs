//! Contract: NO_PROXY alone does not activate proxy routing.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_no_proxy_alone_is_not_active() {
    let _guard = crate::common::proxy_env_lock();
    let saved = [
        ("KEYHOG_PROXY", std::env::var("KEYHOG_PROXY").ok()),
        ("HTTPS_PROXY", std::env::var("HTTPS_PROXY").ok()),
        ("HTTP_PROXY", std::env::var("HTTP_PROXY").ok()),
        ("ALL_PROXY", std::env::var("ALL_PROXY").ok()),
        ("NO_PROXY", std::env::var("NO_PROXY").ok()),
    ];
    unsafe {
        std::env::remove_var("KEYHOG_PROXY");
        std::env::remove_var("HTTPS_PROXY");
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("ALL_PROXY");
        std::env::set_var("NO_PROXY", "*.internal.corp");
    }
    assert!(
        !proxy_is_active(None),
        "NO_PROXY alone must not mark proxy active"
    );
    for (k, v) in saved {
        unsafe {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
