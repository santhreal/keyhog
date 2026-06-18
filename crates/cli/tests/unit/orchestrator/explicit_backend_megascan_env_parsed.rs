use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_megascan_env_parsed() {
    assert_eq!(
        explicit_backend_override(Some("mega-scan")).unwrap(),
        Some(ScanBackend::MegaScan)
    );
}
