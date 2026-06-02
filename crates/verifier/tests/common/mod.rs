pub mod ssrf_engine;

/// Shared in-process lock serializing every test that mutates the process-global
/// proxy env vars (`KEYHOG_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`).
/// The `contract/` proxy tests previously each declared their own
/// `static ENV_MUTEX`, which do NOT mutually exclude — so parallel `all_tests`
/// workers stomped each other's env and the asserts flaked. Routing them all
/// through this single mutex makes the env mutation + read atomic across the
/// suite. Held for the test's duration via the returned guard (RAII).
pub fn proxy_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static PROXY_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    PROXY_ENV_MUTEX
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
