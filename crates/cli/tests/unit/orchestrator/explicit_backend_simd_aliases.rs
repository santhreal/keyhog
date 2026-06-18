use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_simd_aliases() {
    assert_eq!(
        explicit_backend_override(Some("hyperscan")).unwrap(),
        Some(ScanBackend::SimdCpu)
    );
}
