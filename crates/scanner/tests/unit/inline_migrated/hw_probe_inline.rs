//! Migrated from src/hw_probe.rs

use keyhog_scanner::hw_probe::{
    classify_gpu_tier, clear_test_backend_override, parse_backend_str, select_backend,
    set_test_backend_override, thresholds, GpuTier, HardwareCaps, ScanBackend,
};

// NOTE: these tests deliberately do NOT mutate the process-global
// `KEYHOG_BACKEND` env var. A global set to a GPU/MegaScan value races with
// every concurrent scan in the parallel `all_tests` pool — `gpu_forced` reacts
// to a forced-but-unavailable GPU by exiting the whole process, which would
// abort the entire harness. Backend FORCING is exercised via the thread-local
// `set_test_backend_override` (race-free); the env-string→backend MAPPING is
// exercised via the pure `parse_backend_str`.

fn caps_with(gpu: bool, soft: bool, hs: bool, avx2: bool) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: avx2,
        has_avx512: false,
        has_neon: false,
        gpu_available: gpu,
        gpu_name: gpu.then(|| "Test GPU".to_string()),
        gpu_vram_mb: gpu.then_some(8192),
        gpu_is_software: soft,
        total_memory_mb: Some(32_768),
        io_uring_available: false,
        hyperscan_available: hs,
    }
}

/// Ensure no thread-local backend override leaks in from a prior test reusing
/// this worker thread, so the auto-routing assertions see a clean slate.
fn clear_env() {
    clear_test_backend_override();
}

#[test]
fn gpu_picked_when_workload_huge_solo() {
    clear_env();
    let caps = caps_with(true, false, true, true);
    // 256 MiB single file, low pattern count → still GPU (solo
    // crossover).
    assert_eq!(
        select_backend(&caps, thresholds::GPU_BYTES_BREAKEVEN_SOLO, 50),
        ScanBackend::Gpu
    );
}

#[test]
fn gpu_picked_when_buffer_big_and_many_patterns() {
    clear_env();
    let caps = caps_with(true, false, true, true);
    // 64 MiB + 2K patterns → GPU.
    assert_eq!(
        select_backend(
            &caps,
            thresholds::GPU_MIN_BYTES,
            thresholds::GPU_PATTERN_BREAKEVEN
        ),
        ScanBackend::Gpu
    );
}

#[test]
fn gpu_skipped_below_buffer_threshold() {
    clear_env();
    let caps = caps_with(true, false, true, true);
    // 63 MiB even with 5K patterns → SimdCpu (under MIN_BYTES).
    assert_eq!(
        select_backend(&caps, thresholds::GPU_MIN_BYTES - 1, 5_000),
        ScanBackend::SimdCpu
    );
}

#[test]
fn gpu_skipped_when_software_renderer() {
    clear_env();
    // GPU available, but it's llvmpipe — must NEVER pick it.
    let caps = caps_with(true, true, true, true);
    assert_eq!(
        select_backend(&caps, 1024 * 1024 * 1024, 10_000),
        ScanBackend::SimdCpu
    );
}

#[test]
fn simd_cpu_when_no_gpu_with_hyperscan() {
    clear_env();
    let caps = caps_with(false, false, true, true);
    assert_eq!(
        select_backend(&caps, 1024 * 1024, 100),
        ScanBackend::SimdCpu
    );
}

#[test]
fn simd_cpu_when_no_gpu_no_hyperscan_but_avx2() {
    clear_env();
    let caps = caps_with(false, false, false, true);
    // SIMD CPU features alone still pick the SIMD path (sans Hyperscan).
    assert_eq!(
        select_backend(&caps, 1024 * 1024, 100),
        ScanBackend::SimdCpu
    );
}

#[test]
fn cpu_fallback_when_no_gpu_no_hyperscan_no_simd() {
    clear_env();
    let caps = caps_with(false, false, false, false);
    assert_eq!(
        select_backend(&caps, 1024 * 1024, 100),
        ScanBackend::CpuFallback
    );
}

#[test]
fn env_override_forces_gpu_even_without_workload() {
    // Forced backend (via the race-free thread-local override) wins regardless
    // of workload size or hardware availability.
    set_test_backend_override(Some(ScanBackend::Gpu));
    let caps = caps_with(false, false, true, true);
    assert_eq!(select_backend(&caps, 1024, 10), ScanBackend::Gpu);
    clear_test_backend_override();
}

#[test]
fn env_override_forces_cpu_fallback() {
    // Forced CpuFallback pins the CPU path even with a big GPU workload.
    set_test_backend_override(Some(ScanBackend::CpuFallback));
    let caps = caps_with(true, false, true, true);
    assert_eq!(
        select_backend(&caps, 1024 * 1024 * 1024, 10_000),
        ScanBackend::CpuFallback
    );
    clear_test_backend_override();
}

#[test]
fn env_override_invalid_value_falls_through_to_auto() {
    // An unrecognized KEYHOG_BACKEND value maps to no forced backend...
    assert!(parse_backend_str("garbage-value").is_none());
    // ...so selection falls through to auto routing (no override set).
    clear_test_backend_override();
    let caps = caps_with(false, false, true, true);
    assert_eq!(
        select_backend(&caps, 1024 * 1024, 100),
        ScanBackend::SimdCpu
    );
}

#[test]
fn backend_label_is_stable() {
    // Stable labels are part of our CLI banner contract.
    assert_eq!(ScanBackend::Gpu.label(), "gpu-zero-copy");
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
}

#[test]
fn env_override_accepts_label_aliases() {
    // Each backend has multiple opt-in aliases; CI runners and Dockerfiles
    // routinely use the human-readable label as the env value, so all forms
    // must map to the same backend. Asserted on the pure mapping (no global env).
    for value in ["gpu", "GPU", "Gpu-Zero-Copy", " gpu ", "literal-set"] {
        assert_eq!(
            parse_backend_str(value),
            Some(ScanBackend::Gpu),
            "value {value:?} must map to Gpu"
        );
    }
    for value in ["simd", "SIMD", "simd-regex", "hyperscan", "HYPERSCAN"] {
        assert_eq!(
            parse_backend_str(value),
            Some(ScanBackend::SimdCpu),
            "value {value:?} must map to SimdCpu"
        );
    }
    for value in ["cpu", "Cpu", "cpu-fallback", "scalar"] {
        assert_eq!(
            parse_backend_str(value),
            Some(ScanBackend::CpuFallback),
            "value {value:?} must map to CpuFallback"
        );
    }
}

fn caps_with_named_gpu(name: &str) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some(name.to_string()),
        gpu_vram_mb: Some(8192),
        gpu_is_software: false,
        total_memory_mb: Some(32_768),
        io_uring_available: false,
        hyperscan_available: true,
    }
}

#[test]
fn classify_high_tier_gpus() {
    for name in [
        "NVIDIA GeForce RTX 5090",
        "NVIDIA GeForce RTX 4090",
        "NVIDIA H100 PCIe",
        "NVIDIA A100-SXM4-80GB",
        "Apple M3 Max",
        "AMD Radeon RX 7900 XTX",
    ] {
        assert_eq!(
            classify_gpu_tier(Some(name)),
            GpuTier::High,
            "expected High tier for {name:?}"
        );
    }
}

#[test]
fn classify_mid_tier_gpus() {
    for name in [
        "NVIDIA GeForce RTX 3060",
        "NVIDIA GeForce RTX 2080 Ti",
        "NVIDIA GeForce GTX 1660",
        "Intel(R) Arc(TM) A770 Graphics",
        "Apple M1 Pro",
    ] {
        assert_eq!(
            classify_gpu_tier(Some(name)),
            GpuTier::Mid,
            "expected Mid tier for {name:?}"
        );
    }
}

#[test]
fn classify_low_tier_gpus() {
    for name in [
        "Intel(R) UHD Graphics 620",
        "Intel(R) Iris Xe Graphics",
        "AMD Radeon Vega 8",
        "Mystery GPU 9000",
    ] {
        assert_eq!(
            classify_gpu_tier(Some(name)),
            GpuTier::Low,
            "expected Low tier for {name:?}"
        );
    }
    assert_eq!(classify_gpu_tier(None), GpuTier::Low);
}

#[test]
fn high_tier_gpu_activates_at_2mib() {
    clear_env();
    let caps = caps_with_named_gpu("NVIDIA GeForce RTX 5090");
    // 2 MiB workload + 2K patterns → GPU on RTX 5090.
    assert_eq!(
        select_backend(&caps, 2 * 1024 * 1024, thresholds::GPU_PATTERN_BREAKEVEN),
        ScanBackend::Gpu
    );
    // 2 MiB single file (no pattern threshold needed) shouldn't
    // hit the solo cap (16 MiB on high tier), so falls back to SIMD
    // when pattern count is low.
    assert_eq!(
        select_backend(&caps, 2 * 1024 * 1024, 50),
        ScanBackend::SimdCpu
    );
    // 16 MiB single file → solo cap on high tier → GPU.
    assert_eq!(
        select_backend(&caps, 16 * 1024 * 1024, 50),
        ScanBackend::Gpu
    );
}

#[test]
fn mid_tier_gpu_activates_at_16mib() {
    clear_env();
    let caps = caps_with_named_gpu("NVIDIA GeForce RTX 3070");
    // 2 MiB on mid-tier is too small — SIMD wins.
    assert_eq!(
        select_backend(&caps, 2 * 1024 * 1024, thresholds::GPU_PATTERN_BREAKEVEN),
        ScanBackend::SimdCpu
    );
    // 16 MiB + 2K patterns → GPU.
    assert_eq!(
        select_backend(
            &caps,
            thresholds::GPU_MIN_BYTES_MID_TIER,
            thresholds::GPU_PATTERN_BREAKEVEN
        ),
        ScanBackend::Gpu
    );
}

#[test]
fn low_tier_gpu_keeps_legacy_64mib_threshold() {
    clear_env();
    // Unknown adapter name → Low tier → original 64 MiB threshold.
    let caps = caps_with_named_gpu("Mystery GPU");
    // 16 MiB even with many patterns → SIMD (Low tier needs 64 MiB).
    assert_eq!(
        select_backend(&caps, 16 * 1024 * 1024, 5_000),
        ScanBackend::SimdCpu
    );
    assert_eq!(
        select_backend(
            &caps,
            thresholds::GPU_MIN_BYTES,
            thresholds::GPU_PATTERN_BREAKEVEN
        ),
        ScanBackend::Gpu
    );
}
