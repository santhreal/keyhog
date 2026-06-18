use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_cpu_fallback_aliases() {
    assert_eq!(
        explicit_backend_override(Some("scalar")).unwrap(),
        Some(ScanBackend::CpuFallback)
    );
}
