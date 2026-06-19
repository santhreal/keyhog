use keyhog_scanner::hw_probe::testing::{select_backend, HardwareCaps, ScanBackend};
use keyhog_scanner::testing::{clear_test_backend_override, set_test_backend_override};
#[test]
fn select_backend_test_gpu_override() {
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
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(8192),
        io_uring_available: false,
        hyperscan_available: true,
    };
    assert_eq!(select_backend(&caps, 0, 0), ScanBackend::Gpu);
    clear_test_backend_override();
}
