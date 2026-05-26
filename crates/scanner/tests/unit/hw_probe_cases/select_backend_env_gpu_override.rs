use keyhog_scanner::hw_probe::{select_backend, HardwareCaps, ScanBackend};
#[test]
fn select_backend_env_gpu_override() {
    unsafe { std::env::set_var("KEYHOG_BACKEND", "gpu"); }
    let caps = HardwareCaps {
        physical_cores: 4, logical_cores: 8, has_avx2: true, has_avx512: false, has_neon: false,
        gpu_available: false, gpu_name: None, gpu_vram_mb: None, gpu_is_software: false,
        total_memory_mb: Some(8192), io_uring_available: false, hyperscan_available: true,
    };
    assert_eq!(select_backend(&caps, 0, 0), ScanBackend::Gpu);
    unsafe { std::env::remove_var("KEYHOG_BACKEND"); }
}
