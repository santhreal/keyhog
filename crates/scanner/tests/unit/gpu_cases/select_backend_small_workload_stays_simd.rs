use keyhog_scanner::hw_probe::{select_backend, HardwareCaps, ScanBackend};
#[test]
fn select_backend_small_workload_stays_simd() {
    let caps = HardwareCaps {
        physical_cores: 8, logical_cores: 16, has_avx2: true, has_avx512: false, has_neon: false,
        gpu_available: true, gpu_name: Some("NVIDIA GeForce RTX 4090".into()), gpu_vram_mb: Some(8192),
        gpu_is_software: false, total_memory_mb: Some(16384), io_uring_available: false,
        hyperscan_available: true,
    };
    assert_eq!(select_backend(&caps, 1024, 10), ScanBackend::SimdCpu);
}
