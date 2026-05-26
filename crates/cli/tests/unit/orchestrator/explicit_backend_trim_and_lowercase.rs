use keyhog::orchestrator::explicit_backend_override;
use keyhog_scanner::hw_probe::ScanBackend;

#[test]
fn explicit_backend_trim_and_lowercase() {
    std::env::set_var("KEYHOG_BACKEND", "  GPU  ");
    assert_eq!(explicit_backend_override(), Some(ScanBackend::Gpu));
    std::env::remove_var("KEYHOG_BACKEND");
}
