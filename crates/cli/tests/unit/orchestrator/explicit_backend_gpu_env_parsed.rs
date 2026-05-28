use crate::unit::orchestrator::support::ENV_LOCK;
use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_gpu_env_parsed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("KEYHOG_BACKEND", "gpu");
    assert_eq!(explicit_backend_override(), Some(ScanBackend::Gpu));
    std::env::remove_var("KEYHOG_BACKEND");
}
