use crate::unit::orchestrator::support::ENV_LOCK;
use keyhog::orchestrator::explicit_backend_override;

#[test]
fn explicit_backend_unknown_returns_none() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("KEYHOG_BACKEND", "not-a-real-backend");
    assert!(explicit_backend_override().is_none());
    std::env::remove_var("KEYHOG_BACKEND");
}
