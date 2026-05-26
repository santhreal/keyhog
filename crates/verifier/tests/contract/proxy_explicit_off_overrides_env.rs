//! Contract: explicit `off` disables proxy even when HTTPS_PROXY is set.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_explicit_off_overrides_env() {
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("HTTPS_PROXY").ok();
    unsafe {
        std::env::set_var("HTTPS_PROXY", "http://corp-burp:8080");
    }
    assert!(!proxy_is_active(Some("off")));
    match saved {
        Some(v) => unsafe {
            std::env::set_var("HTTPS_PROXY", v);
        },
        None => unsafe {
            std::env::remove_var("HTTPS_PROXY");
        },
    }
}
