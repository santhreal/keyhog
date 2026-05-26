use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_cpu_fallback_aliases() {
    std::env::set_var("KEYHOG_BACKEND", "scalar");
    assert_eq!(explicit_backend_override(), Some(ScanBackend::CpuFallback));
    std::env::remove_var("KEYHOG_BACKEND");
}
