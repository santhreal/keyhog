use keyhog_scanner::hw_probe::testing::ScanBackend;
#[test]
fn scan_backend_label_gpu() {
    assert_eq!(ScanBackend::Gpu.label(), "gpu-zero-copy");
}
