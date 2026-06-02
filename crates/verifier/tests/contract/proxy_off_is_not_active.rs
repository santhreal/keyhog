//! Contract: KEYHOG_PROXY='off' semantics.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_off_is_not_active() {
    let _guard = crate::common::proxy_env_lock();
    let saved_kh = std::env::var("KEYHOG_PROXY").ok();
    for var in [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    ] {
        unsafe {
            std::env::remove_var(var);
        }
    }
    unsafe {
        std::env::set_var("KEYHOG_PROXY", "off");
    }
    let active = proxy_is_active(None);
    match saved_kh {
        Some(v) => unsafe {
            std::env::set_var("KEYHOG_PROXY", v);
        },
        None => unsafe {
            std::env::remove_var("KEYHOG_PROXY");
        },
    }
    assert_eq!(active, false);
}
