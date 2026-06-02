use keyhog_scanner::hw_probe::{parse_backend_str, ScanBackend};

#[test]
fn forced_backend_megascan_env() {
    // Pure mapping — no global `KEYHOG_BACKEND` mutation (see parse_backend_str
    // docs: a global GPU/MegaScan value races with concurrent scans and trips
    // gpu_forced's process-exit, aborting the whole harness).
    assert_eq!(parse_backend_str("mega-scan"), Some(ScanBackend::MegaScan));
    assert_eq!(
        parse_backend_str("gpu-mega-scan"),
        Some(ScanBackend::MegaScan)
    );
    assert_eq!(
        parse_backend_str("rule-pipeline"),
        Some(ScanBackend::MegaScan)
    );
}
