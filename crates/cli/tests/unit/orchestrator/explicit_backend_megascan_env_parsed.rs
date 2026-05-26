use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_megascan_env_parsed() {
    std::env::set_var("KEYHOG_BACKEND", "mega-scan");
    assert_eq!(explicit_backend_override(), Some(ScanBackend::MegaScan));
    std::env::remove_var("KEYHOG_BACKEND");
}
