use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_simd_aliases() {
    std::env::set_var("KEYHOG_BACKEND", "hyperscan");
    assert_eq!(explicit_backend_override(), Some(ScanBackend::SimdCpu));
    std::env::remove_var("KEYHOG_BACKEND");
}
