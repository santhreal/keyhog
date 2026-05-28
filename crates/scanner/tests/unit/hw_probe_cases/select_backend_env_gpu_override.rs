use keyhog_scanner::hw_probe::{
    clear_test_backend_override, select_backend, set_test_backend_override, HardwareCaps,
    ScanBackend,
};
#[test]
fn select_backend_env_gpu_override() {
    set_test_backend_override(Some(ScanBackend::Gpu));
    let caps = HardwareCaps {
        physical_cores: 4,
        logical_cores: 8,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_is_software: false,
        total_memory_mb: Some(8192),
        io_uring_available: false,
        hyperscan_available: true,
    };
    assert_eq!(select_backend(&caps, 0, 0), ScanBackend::Gpu);
    clear_test_backend_override();
}
