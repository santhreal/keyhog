//! Contract: HTTPS_PROXY env var marks proxy active.

use keyhog_verifier::proxy_is_active;

#[test]
fn proxy_https_env_is_active() {
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let saved = [
        ("KEYHOG_PROXY", std::env::var("KEYHOG_PROXY").ok()),
        ("HTTPS_PROXY", std::env::var("HTTPS_PROXY").ok()),
        ("HTTP_PROXY", std::env::var("HTTP_PROXY").ok()),
        ("ALL_PROXY", std::env::var("ALL_PROXY").ok()),
    ];
    unsafe {
        std::env::remove_var("KEYHOG_PROXY");
        std::env::set_var("HTTPS_PROXY", "http://burp:8080");
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("ALL_PROXY");
    }
    assert!(
        proxy_is_active(None),
        "HTTPS_PROXY alone must mark proxy active"
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
