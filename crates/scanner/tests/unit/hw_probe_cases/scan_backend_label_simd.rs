use keyhog_scanner::hw_probe::testing::ScanBackend;
#[test]
fn scan_backend_label_simd() {
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
}
