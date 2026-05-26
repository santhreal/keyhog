use keyhog_scanner::hw_probe::ScanBackend;
#[test]
fn scan_backend_label_megascan() {
    assert_eq!(ScanBackend::MegaScan.label(), "gpu-mega-scan");
}
