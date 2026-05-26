use keyhog_scanner::hw_probe::{
    classify_gpu_tier, gpu_solo_bytes_for_tier, select_backend, GpuTier, HardwareCaps, ScanBackend,
};
#[test]
fn select_backend_high_tier_large_file() {
    let name = "NVIDIA GeForce RTX 4090";
    let tier = classify_gpu_tier(Some(name));
    assert_eq!(tier, GpuTier::High);
    let caps = HardwareCaps {
        physical_cores: 16,
        logical_cores: 32,
        has_avx2: true,
        has_avx512: true,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some(name.into()),
        gpu_vram_mb: Some(24576),
        gpu_is_software: false,
        total_memory_mb: Some(65536),
        io_uring_available: true,
        hyperscan_available: true,
    };
    let solo = gpu_solo_bytes_for_tier(tier);
    assert_eq!(select_backend(&caps, solo, 1), ScanBackend::Gpu);
}
