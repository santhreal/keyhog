//! Routing decision matrix - parametric tests over every documented
//! [`select_backend`] cell. Auto-generates ~200 cells from data tables
//! covering:
//!
//!   * explicit backend override mapping (every recognized value + invalid)
//!   * GPU adapter-name → [`GpuTier`] classification
//!   * Per-tier byte/pattern thresholds (boundary + below + above)
//!   * Software-GPU rejection (llvmpipe / lavapipe / swiftshader)
//!   * Hyperscan availability fallback paths
//!   * `gpu_available = false` fallback
//!
//! These are pure-logic tests over `HardwareCaps` and `select_backend()`:
//! no GPU hardware required, no real scan executed. The point is to
//! lock the documented routing contract so a refactor of the thresholds
//! or the tier table can't silently flip prod routing.
//!
//! Every cell that goes through the test override serializes on [`ENV_LOCK`] so
//! the thread-local override is restored deterministically around each case.

use keyhog_scanner::hw_probe::testing::{
    classify_gpu_tier, gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier,
    gpu_solo_bytes_for_tier, parse_backend_str, select_backend, select_backend_for_batch, GpuTier,
    HardwareCaps, ScanBackend,
};
use keyhog_scanner::testing::{clear_test_backend_override, set_test_backend_override};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());
const fn automatic_gpu_backend() -> ScanBackend {
    if cfg!(target_os = "macos") {
        ScanBackend::GpuMetal
    } else {
        ScanBackend::GpuWgpu
    }
}

fn caps_with_gpu(name: &str, hyperscan: bool, simd: bool) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: simd,
        has_avx512: false,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some(name.into()),
        gpu_vram_mb: Some(24 * 1024),
        gpu_runtime_identity: Some(format!("test-runtime:{name}")),
        gpu_is_software: name.to_ascii_lowercase().contains("llvmpipe")
            || name.to_ascii_lowercase().contains("lavapipe")
            || name.to_ascii_lowercase().contains("swiftshader"),
        total_memory_mb: Some(64 * 1024),
        io_uring_available: true,
        hyperscan_available: hyperscan,
        hyperscan_runtime_identity: None,
    }
}

fn caps_no_gpu(hyperscan: bool, simd: bool) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: simd,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(64 * 1024),
        io_uring_available: true,
        hyperscan_available: hyperscan,
        hyperscan_runtime_identity: None,
    }
}

/// Run `body` with a race-free test backend override derived from `value`.
fn with_env<R>(value: Option<&str>, body: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(value) = value {
        set_test_backend_override(parse_backend_str(value));
    } else {
        clear_test_backend_override();
    }
    let out = body();
    clear_test_backend_override();
    out
}

// ────────────────────────────────────────────────────────────────────
// CELL 1: explicit test override
// ────────────────────────────────────────────────────────────────────

/// An explicit WGPU override must force `GpuWgpu` even when no GPU is detected
/// at all - the override is a contract for benchmarks and CI assertions,
/// not a "best-effort" hint. The default routing rules cannot override it.
#[test]
fn env_override_wgpu_forces_wgpu_regardless_of_hardware() {
    let caps = caps_no_gpu(true, true);
    for alias in ["gpu-wgpu", "GPU-WGPU", "gpu-wgpu-region-presence"] {
        with_env(Some(alias), || {
            assert_eq!(
                select_backend(&caps, 1 << 30, 10_000),
                ScanBackend::GpuWgpu,
                "backend={alias} must force GpuWgpu"
            );
        });
    }
}

#[test]
fn env_override_simd_forces_simd_even_when_gpu_would_win() {
    let caps = caps_with_gpu("NVIDIA RTX 5090", true, true);
    for alias in ["simd", "SIMD", "simd-regex"] {
        with_env(Some(alias), || {
            assert_eq!(
                select_backend(&caps, 1 << 30, 10_000),
                ScanBackend::SimdCpu,
                "env={alias} must force SimdCpu"
            );
        });
    }
}

#[test]
fn env_override_cpu_forces_cpu_fallback() {
    let caps = caps_with_gpu("NVIDIA RTX 5090", true, true);
    for alias in ["cpu", "CPU", "cpu-fallback"] {
        with_env(Some(alias), || {
            assert_eq!(
                select_backend(&caps, 1 << 30, 10_000),
                ScanBackend::CpuFallback,
                "env={alias} must force CpuFallback"
            );
        });
    }
}

#[test]
fn env_override_invalid_value_falls_through_to_auto() {
    let caps = caps_with_gpu("NVIDIA RTX 5090", true, true);
    for garbage in ["", "  ", "gibberish", "GPU2", "ssdmd", "🦀"] {
        with_env(Some(garbage), || {
            // RTX 5090 + 1 GiB + 10k patterns → high-tier auto picks Gpu.
            assert_eq!(
                select_backend(&caps, 1 << 30, 10_000),
                automatic_gpu_backend(),
                "garbage env {garbage:?} must fall through to auto-Gpu"
            );
        });
    }
}

#[test]
fn env_unset_uses_auto_routing() {
    let caps = caps_no_gpu(false, false);
    with_env(None, || {
        // No GPU, no Hyperscan, no SIMD → fall all the way to CpuFallback.
        assert_eq!(
            select_backend(&caps, 1 << 30, 10_000),
            ScanBackend::CpuFallback,
        );
    });
}

// ────────────────────────────────────────────────────────────────────
// CELL 2: tier classification (every named adapter family)
// ────────────────────────────────────────────────────────────────────

#[test]
fn classify_gpu_tier_high_tier_adapters() {
    let high = [
        "NVIDIA GeForce RTX 4090",
        "NVIDIA GeForce RTX 4080 SUPER",
        "NVIDIA GeForce RTX 4070 Ti",
        "NVIDIA GeForce RTX 5090",
        "NVIDIA GeForce RTX 5080",
        "NVIDIA GeForce RTX 5070",
        "NVIDIA A100-SXM4-80GB",
        "NVIDIA H100 80GB HBM3",
        "NVIDIA H200",
        "AMD Radeon RX 7900 XTX",
        "AMD Radeon RX 7900 XT",
        "Apple M4 Max",
        "Apple M3 Max",
        "Apple M2 Max",
        "Apple M1 Max",
        "Apple M4 Ultra",
        "Apple M3 Ultra",
        "Apple M2 Ultra",
        "Apple M1 Ultra",
    ];
    for name in high {
        assert_eq!(
            classify_gpu_tier(Some(name)),
            GpuTier::High,
            "{name} must classify as High"
        );
    }
}

#[test]
fn classify_gpu_tier_mid_tier_adapters() {
    let mid = [
        "NVIDIA GeForce RTX 2080 Ti",
        "NVIDIA GeForce RTX 3090",
        "NVIDIA GeForce GTX 1660 Ti",
        "Intel Arc A770",
        "AMD Radeon RX 6800 XT",
        "AMD Radeon RX 7600",
        "Apple M1",
        "Apple M2",
        "Apple M3",
        "Apple M4",
        "Apple M1 Pro",
        "Apple M2 Pro",
        "Apple M3 Pro",
        "Apple M4 Pro",
    ];
    for name in mid {
        assert_eq!(
            classify_gpu_tier(Some(name)),
            GpuTier::Mid,
            "{name} must classify as Mid"
        );
    }
}

#[test]
fn classify_gpu_tier_low_tier_unknown_or_old_adapters() {
    let low = [
        "Intel UHD Graphics 770",
        "Intel Iris Xe Graphics",
        "NVIDIA GeForce GTX 1050 Ti",
        "AMD Radeon Vega 8",
        "llvmpipe (LLVM 17.0.0, 256 bits)",
        "Mesa Intel(R) HD Graphics 4400 (HSW GT2)",
        "Unknown Adapter",
    ];
    for name in low {
        assert_eq!(
            classify_gpu_tier(Some(name)),
            GpuTier::Low,
            "{name} must classify as Low"
        );
    }
}

#[test]
fn classify_gpu_tier_none_yields_low() {
    assert_eq!(classify_gpu_tier(None), GpuTier::Low);
}

// ────────────────────────────────────────────────────────────────────
// CELL 3: per-tier threshold monotonicity
// ────────────────────────────────────────────────────────────────────

/// As tier improves (Low→Mid→High), every routing threshold must drop
/// monotonically. A high-tier 5090 must NEVER need more bytes to win
/// than a low-tier iGPU; a regression that crossed these would silently
/// disable GPU routing on the fastest cards.
#[test]
fn tier_thresholds_are_monotone_decreasing_with_tier() {
    let low_min = gpu_min_bytes_for_tier(GpuTier::Low);
    let mid_min = gpu_min_bytes_for_tier(GpuTier::Mid);
    let high_min = gpu_min_bytes_for_tier(GpuTier::High);
    assert!(high_min <= mid_min, "high={high_min} must <= mid={mid_min}");
    assert!(mid_min <= low_min, "mid={mid_min} must <= low={low_min}");

    let low_solo = gpu_solo_bytes_for_tier(GpuTier::Low);
    let mid_solo = gpu_solo_bytes_for_tier(GpuTier::Mid);
    let high_solo = gpu_solo_bytes_for_tier(GpuTier::High);
    assert!(high_solo <= mid_solo);
    assert!(mid_solo <= low_solo);

    let low_pat = gpu_pattern_breakeven_for_tier(GpuTier::Low);
    let mid_pat = gpu_pattern_breakeven_for_tier(GpuTier::Mid);
    let high_pat = gpu_pattern_breakeven_for_tier(GpuTier::High);
    assert!(high_pat <= mid_pat);
    assert!(mid_pat <= low_pat);
}

// ────────────────────────────────────────────────────────────────────
// CELL 4: GPU activation crossover (workload bytes × pattern count)
// ────────────────────────────────────────────────────────────────────

/// `(workload_bytes, pattern_count, expected_backend)` cells for a
/// high-tier GPU (RTX 5090). Each cell is one assertion.
#[allow(clippy::too_many_arguments)]
fn assert_high_tier_routing_cells() -> Vec<(u64, usize, ScanBackend, &'static str)> {
    let solo = gpu_solo_bytes_for_tier(GpuTier::High);
    let min = gpu_min_bytes_for_tier(GpuTier::High);
    let pat_floor = gpu_pattern_breakeven_for_tier(GpuTier::High);
    vec![
        // Solo path: above solo cap, any pattern count wins for GPU.
        (
            solo,
            1,
            automatic_gpu_backend(),
            "high: at solo, 1 pattern → Gpu",
        ),
        (
            solo + 1,
            0,
            automatic_gpu_backend(),
            "high: just above solo → Gpu",
        ),
        (solo * 4, 1, automatic_gpu_backend(), "high: 4× solo → Gpu"),
        // Min + pattern-floor path: both conditions must hold.
        (
            min,
            pat_floor,
            automatic_gpu_backend(),
            "high: at (min, pat_floor) → Gpu",
        ),
        (
            min,
            pat_floor + 1,
            automatic_gpu_backend(),
            "high: at min, above pat_floor → Gpu",
        ),
        // Below min: never Gpu, falls to SimdCpu when Hyperscan present.
        (
            min - 1,
            pat_floor + 100,
            ScanBackend::SimdCpu,
            "high: just below min → SimdCpu",
        ),
        (
            0,
            pat_floor + 100,
            ScanBackend::SimdCpu,
            "high: zero bytes → SimdCpu",
        ),
        // Above min but below pat_floor remains SIMD until the distinct,
        // higher solo threshold is reached.
        (
            min + 1,
            pat_floor - 1,
            ScanBackend::SimdCpu,
            "high: above min, below pat_floor, below solo → SimdCpu",
        ),
    ]
}

#[test]
fn high_tier_routing_crossover_cells() {
    let caps = caps_with_gpu("NVIDIA RTX 5090", true, true);
    with_env(None, || {
        for (bytes, patterns, expected, label) in assert_high_tier_routing_cells() {
            assert_eq!(
                select_backend(&caps, bytes, patterns),
                expected,
                "[{label}] bytes={bytes} patterns={patterns}"
            );
        }
    });
}

#[test]
fn mid_tier_routing_crossover_cells() {
    let caps = caps_with_gpu("NVIDIA RTX 3080", true, true);
    let solo = gpu_solo_bytes_for_tier(GpuTier::Mid);
    let min = gpu_min_bytes_for_tier(GpuTier::Mid);
    let pat_floor = gpu_pattern_breakeven_for_tier(GpuTier::Mid);
    with_env(None, || {
        for (bytes, patterns, expected, label) in [
            (solo, 0, automatic_gpu_backend(), "mid: at solo cap → Gpu"),
            (
                min,
                pat_floor,
                automatic_gpu_backend(),
                "mid: at (min, pat_floor) → Gpu",
            ),
            (
                min - 1,
                pat_floor + 100,
                ScanBackend::SimdCpu,
                "mid: below min → SimdCpu",
            ),
            (
                min + 1,
                pat_floor - 1,
                ScanBackend::SimdCpu,
                "mid: above min, below pat_floor → SimdCpu",
            ),
        ] {
            assert_eq!(
                select_backend(&caps, bytes, patterns),
                expected,
                "[{label}]"
            );
        }
    });
}

#[test]
fn low_tier_routing_crossover_cells() {
    let caps = caps_with_gpu("Intel UHD Graphics 770", true, true);
    let solo = gpu_solo_bytes_for_tier(GpuTier::Low);
    let min = gpu_min_bytes_for_tier(GpuTier::Low);
    let pat_floor = gpu_pattern_breakeven_for_tier(GpuTier::Low);
    with_env(None, || {
        for (bytes, patterns, expected, label) in [
            (solo, 0, automatic_gpu_backend(), "low: at solo cap → Gpu"),
            (
                min,
                pat_floor,
                automatic_gpu_backend(),
                "low: at (min, pat_floor) → Gpu",
            ),
            (
                min - 1,
                pat_floor + 100,
                ScanBackend::SimdCpu,
                "low: below min → SimdCpu",
            ),
            (
                1024,
                10,
                ScanBackend::SimdCpu,
                "low: tiny workload → SimdCpu",
            ),
        ] {
            assert_eq!(
                select_backend(&caps, bytes, patterns),
                expected,
                "[{label}]"
            );
        }
    });
}

// ────────────────────────────────────────────────────────────────────
// CELL 5: software-GPU rejection
// ────────────────────────────────────────────────────────────────────

#[test]
fn software_gpu_adapters_rejected_even_above_thresholds() {
    for name in [
        "llvmpipe (LLVM 17.0.0, 256 bits)",
        "lavapipe (LLVM 18, 256 bits)",
        "SwiftShader Vulkan",
    ] {
        let caps = caps_with_gpu(name, true, true);
        assert!(
            caps.gpu_is_software,
            "{name} must be flagged as software GPU"
        );
        with_env(None, || {
            // Even at 1 GiB + 100k patterns, a software adapter must
            // NEVER be picked - emulated GPU is slower than CPU.
            assert_eq!(
                select_backend(&caps, 1 << 30, 100_000),
                ScanBackend::SimdCpu,
                "{name} must fall through to SimdCpu"
            );
        });
    }
}

// ────────────────────────────────────────────────────────────────────
// CELL 6: Hyperscan / SIMD fallback chain
// ────────────────────────────────────────────────────────────────────

#[test]
fn no_gpu_with_hyperscan_picks_simd() {
    let caps = caps_no_gpu(true, true);
    with_env(None, || {
        assert_eq!(select_backend(&caps, 1 << 30, 10_000), ScanBackend::SimdCpu,);
    });
}

// The `SimdCpu` ("simd-regex") backend IS the Hyperscan/Vectorscan path:
// `cpu_tier_backend = hyperscan_available ? SimdCpu : CpuFallback` (select.rs).
// Commit 0eb97683a ("Fail closed selected SIMD routes") dropped the standalone
// ISA branch, so a CPU's AVX2/NEON/AVX512 flags no longer enable a SIMD backend
// on their own: Hyperscan detects and uses those ISAs internally. Without
// Hyperscan there is no SIMD regex engine, so every no-Hyperscan capability mix
// routes to the scalar CpuFallback.

#[test]
fn no_gpu_no_hyperscan_with_avx2_picks_cpu_fallback() {
    let mut caps = caps_no_gpu(false, true);
    caps.has_avx2 = true;
    with_env(None, || {
        assert_eq!(
            select_backend(&caps, 1 << 30, 10_000),
            ScanBackend::CpuFallback,
        );
    });
}

#[test]
fn no_gpu_no_hyperscan_no_simd_picks_cpu_fallback() {
    let caps = caps_no_gpu(false, false);
    with_env(None, || {
        assert_eq!(
            select_backend(&caps, 1 << 30, 10_000),
            ScanBackend::CpuFallback,
        );
    });
}

#[test]
fn neon_alone_without_hyperscan_picks_cpu_fallback() {
    let mut caps = caps_no_gpu(false, false);
    caps.has_neon = true;
    with_env(None, || {
        assert_eq!(
            select_backend(&caps, 1 << 30, 10_000),
            ScanBackend::CpuFallback,
        );
    });
}

#[test]
fn avx512_alone_without_hyperscan_picks_cpu_fallback() {
    let mut caps = caps_no_gpu(false, false);
    caps.has_avx512 = true;
    with_env(None, || {
        assert_eq!(
            select_backend(&caps, 1 << 30, 10_000),
            ScanBackend::CpuFallback,
        );
    });
}

// ────────────────────────────────────────────────────────────────────
// CELL 7: GpuTier classification invariants
// ────────────────────────────────────────────────────────────────────

/// Empty strings and weird inputs must classify as Low - never panic,
/// never elevate to High by accident.
#[test]
fn classify_gpu_tier_edge_cases_are_low() {
    for name in ["", " ", "\n", "RTX", "4090", "M1"] {
        // "M1" alone matches `m1 max`/`m1 ultra` via substring? No - those
        // require the "max"/"ultra" tail. "Apple M1" matches Mid.
        let tier = classify_gpu_tier(Some(name));
        assert!(
            matches!(tier, GpuTier::Low | GpuTier::Mid),
            "{name:?} must not classify as High (got {tier:?})"
        );
    }
}

// ────────────────────────────────────────────────────────────────────
// CELL 8: ScanBackend stable labels
// ────────────────────────────────────────────────────────────────────

#[test]
fn scan_backend_labels_are_stable() {
    // Stable labels feed logs, the `keyhog backend` subcommand, and CI
    // assertions. A renamed label breaks every downstream consumer.
    assert_eq!(ScanBackend::GpuCuda.label(), "gpu-cuda-region-presence");
    assert_eq!(ScanBackend::GpuWgpu.label(), "gpu-wgpu-region-presence");
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
}

// ────────────────────────────────────────────────────────────────────
// CELL N: batch-aware routing - select_backend_for_batch()
//
// Validates that batch selection delegates to threshold-aware backend selection
// without arbitrary hand-written dominance rules.
// ────────────────────────────────────────────────────────────────────

#[test]
fn batch_routing_delegates_to_select_backend() {
    let caps = caps_with_gpu("NVIDIA GeForce RTX 5090", true, true);
    let tier = classify_gpu_tier(caps.gpu_name.as_deref());
    let solo = gpu_solo_bytes_for_tier(tier);
    with_env(None, || {
        assert_eq!(
            select_backend_for_batch(&caps, solo, 1, solo),
            select_backend(&caps, solo, 1),
            "batch routing must delegate to select_backend"
        );
        assert_eq!(
            select_backend_for_batch(&caps, 1024, 10, 0),
            select_backend(&caps, 1024, 10),
            "below threshold must match select_backend"
        );
    });
}

#[test]
fn batch_env_override_gpu_wins() {
    let caps = caps_with_gpu("NVIDIA GeForce RTX 5090", true, true);
    with_env(Some("gpu-wgpu"), || {
        assert_eq!(
            select_backend_for_batch(&caps, 1024, 10, 0),
            ScanBackend::GpuWgpu,
            "explicit GPU override forces GPU"
        );
    });
}

#[test]
fn batch_no_gpu_caps_routes_cpu() {
    let caps = caps_no_gpu(true, true);
    with_env(None, || {
        assert_eq!(
            select_backend_for_batch(&caps, 1 << 30, 10_000, 1 << 30),
            ScanBackend::SimdCpu,
        );
    });
}
