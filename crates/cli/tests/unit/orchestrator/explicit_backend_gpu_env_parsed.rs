use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_gpu_env_parsed() {
    assert_eq!(
        explicit_backend_override(Some("gpu")).unwrap(),
        Some(ScanBackend::Gpu)
    );
}
