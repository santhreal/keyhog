use keyhog_scanner::hw_probe::{startup_banner, HardwareCaps};
#[test]
fn startup_banner_no_gpu() {
    let caps = HardwareCaps {
        physical_cores: 4, logical_cores: 8, has_avx2: true, has_avx512: false, has_neon: false,
        gpu_available: false, gpu_name: None, gpu_vram_mb: None, gpu_is_software: false,
        total_memory_mb: Some(8192), io_uring_available: false, hyperscan_available: true,
    };
    let banner = startup_banner(&caps, 100, 200);
    assert!(banner.contains("GPU: none"));
}
