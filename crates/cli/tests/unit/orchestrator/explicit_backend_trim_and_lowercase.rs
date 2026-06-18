use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_trim_and_lowercase() {
    assert_eq!(
        explicit_backend_override(Some("  GPU  ")).unwrap(),
        Some(ScanBackend::Gpu)
    );
}
