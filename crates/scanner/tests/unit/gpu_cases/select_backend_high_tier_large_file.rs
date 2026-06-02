use keyhog_scanner::hw_probe::{
    classify_gpu_tier, gpu_could_engage, gpu_solo_bytes_for_tier, GpuTier, HardwareCaps,
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
    // A high-tier solo-cap workload clears the GPU crossover. Asserted on the
    // side-effect-free `gpu_could_engage` predicate rather than `select_backend`:
    // the router additionally degrades a GPU choice to SIMD on a GPU-less host
    // (`gpu::env_no_gpu()`), so `select_backend(..) == Gpu` is green on a GPU dev
    // box but red on a GPU-less CI runner. The crossover math is host-independent.
    assert!(gpu_could_engage(&caps, solo, 1));
}
