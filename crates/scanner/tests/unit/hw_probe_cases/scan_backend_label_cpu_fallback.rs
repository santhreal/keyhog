use keyhog_scanner::hw_probe::ScanBackend;
#[test]
fn scan_backend_label_cpu_fallback() {
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
}
