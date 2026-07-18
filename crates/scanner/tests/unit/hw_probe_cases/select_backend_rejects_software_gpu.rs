use keyhog_scanner::hw_probe::testing::{select_backend, HardwareCaps, ScanBackend};
use keyhog_scanner::testing::clear_test_backend_override;
#[test]
fn select_backend_rejects_software_gpu() {
    clear_test_backend_override();
    let caps = HardwareCaps {
        physical_cores: 4,
        logical_cores: 8,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some("llvmpipe".into()),
        gpu_vram_mb: None,
        gpu_runtime_identity: Some("test-runtime:llvmpipe".to_string()),
        gpu_is_software: true,
        total_memory_mb: Some(8192),
        io_uring_available: false,
        hyperscan_available: true,
        hyperscan_runtime_identity: None,
    };
    assert_ne!(
        select_backend(&caps, 1_000_000_000, 5000),
        ScanBackend::GpuWgpu
    );
}
