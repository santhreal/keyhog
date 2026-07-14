use keyhog_scanner::hw_probe::testing::ScanBackend;
#[test]
fn scan_backend_label_gpu() {
    assert_eq!(ScanBackend::GpuCuda.label(), "gpu-cuda-region-presence");
    assert_eq!(ScanBackend::GpuWgpu.label(), "gpu-wgpu-region-presence");
}
