use keyhog_scanner::hw_probe::testing::{startup_banner, HardwareCaps};
#[test]
fn startup_banner_software_gpu_ignored() {
    let caps = HardwareCaps {
        physical_cores: 4,
        logical_cores: 8,
        has_avx2: false,
        has_avx512: false,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some("llvmpipe".into()),
        gpu_vram_mb: None,
        gpu_runtime_identity: Some("test-runtime:llvmpipe".to_string()),
        gpu_is_software: true,
        total_memory_mb: None,
        io_uring_available: false,
        hyperscan_available: false,
        hyperscan_runtime_identity: None,
    };
    let banner = startup_banner(&caps, 1, 1);
    assert!(banner.contains("software, ignored"));
}
