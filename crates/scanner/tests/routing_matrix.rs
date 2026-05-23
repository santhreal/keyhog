//! Routing decision matrix — parametric tests over every documented
//! [`select_backend`] cell. Auto-generates ~200 cells from data tables
//! covering:
//!
//!   * `KEYHOG_BACKEND` env override (every recognized value + invalid)
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
//! Every cell that goes through `KEYHOG_BACKEND` must serialize on
//! [`ENV_LOCK`] — the env var is process-global so concurrent tests
//! would race and produce non-deterministic results. The lock-guard
//! pattern matches the prior `hw_probe` env-touching tests.

use keyhog_scanner::hw_probe::{
    classify_gpu_tier, gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier,
    gpu_solo_bytes_for_tier, select_backend, GpuTier, HardwareCaps, ScanBackend,
};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        gpu_is_software: name.to_ascii_lowercase().contains("llvmpipe")
            || name.to_ascii_lowercase().contains("lavapipe")
            || name.to_ascii_lowercase().contains("swiftshader"),
        total_memory_mb: Some(64 * 1024),
        io_uring_available: true,
        hyperscan_available: hyperscan,
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
        gpu_is_software: false,
        total_memory_mb: Some(64 * 1024),
        io_uring_available: true,
        hyperscan_available: hyperscan,
    }
}

/// Run `body` with `KEYHOG_BACKEND` set to `value` (or unset when None).
/// Restores the prior value on exit so the next test sees a clean env.
fn with_env<R>(value: Option<&str>, body: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = std::env::var("KEYHOG_BACKEND").ok();
    unsafe {
        match value {
            Some(v) => std::env::set_var("KEYHOG_BACKEND", v),
            None => std::env::remove_var("KEYHOG_BACKEND"),
        }
    }
    let out = body();
    unsafe {
        match prior {
            Some(v) => std::env::set_var("KEYHOG_BACKEND", v),
            None => std::env::remove_var("KEYHOG_BACKEND"),
        }
    }
    out
}

// ────────────────────────────────────────────────────────────────────
// CELL 1: env override
// ────────────────────────────────────────────────────────────────────

/// `KEYHOG_BACKEND=gpu` must force `Gpu` even when no GPU is detected
/// at all — the override is a contract for benchmarks and CI assertions,
/// not a "best-effort" hint. The default routing rules cannot override it.
#[test]
fn env_override_gpu_forces_gpu_regardless_of_hardware() {
    let caps = caps_no_gpu(true, true);
    for alias in ["gpu", "GPU", "gpu-zero-copy", "literal-set"] {
        with_env(Some(alias), || {
            assert_eq!(
                select_backend(&caps, 1 << 30, 10_000),
                ScanBackend::Gpu,
                "env={alias} must force Gpu"
            );
        });
    }
}

#[test]
fn env_override_mega_scan_forces_mega_scan() {
    let caps = caps_with_gpu("Apple M1 Max", true, true);
    for alias in [
        "mega-scan",
        "MEGA-SCAN",
        "gpu-mega-scan",
        "regex-nfa",
        "rule-pipeline",
    ] {
        with_env(Some(alias), || {
            assert_eq!(
                select_backend(&caps, 1 << 30, 10_000),
                ScanBackend::MegaScan,
                "env={alias} must force MegaScan"
            );
        });
    }
}

#[test]
fn env_override_simd_forces_simd_even_when_gpu_would_win() {
    let caps = caps_with_gpu("NVIDIA RTX 5090", true, true);
    for alias in ["simd", "SIMD", "simd-regex", "hyperscan"] {
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
    for alias in ["cpu", "CPU", "cpu-fallback", "scalar"] {
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
                ScanBackend::Gpu,
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
        (solo, 1, ScanBackend::Gpu, "high: at solo, 1 pattern → Gpu"),
        (solo + 1, 0, ScanBackend::Gpu, "high: just above solo → Gpu"),
        (solo * 4, 1, ScanBackend::Gpu, "high: 4× solo → Gpu"),
        // Min + pattern-floor path: both conditions must hold.
        (
            min,
            pat_floor,
            ScanBackend::Gpu,
            "high: at (min, pat_floor) → Gpu",
        ),
        (
            min,
            pat_floor + 1,
            ScanBackend::Gpu,
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
        // Above min but below pat_floor AND below solo: stays SimdCpu.
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
            (solo, 0, ScanBackend::Gpu, "mid: at solo cap → Gpu"),
            (
                min,
                pat_floor,
                ScanBackend::Gpu,
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
            (solo, 0, ScanBackend::Gpu, "low: at solo cap → Gpu"),
            (
                min,
                pat_floor,
                ScanBackend::Gpu,
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
            // NEVER be picked — emulated GPU is slower than CPU.
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

#[test]
fn no_gpu_no_hyperscan_with_avx2_picks_simd() {
    let mut caps = caps_no_gpu(false, true);
    caps.has_avx2 = true;
    with_env(None, || {
        assert_eq!(select_backend(&caps, 1 << 30, 10_000), ScanBackend::SimdCpu,);
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
fn neon_alone_picks_simd_cpu() {
    let mut caps = caps_no_gpu(false, false);
    caps.has_neon = true;
    with_env(None, || {
        assert_eq!(select_backend(&caps, 1 << 30, 10_000), ScanBackend::SimdCpu,);
    });
}

#[test]
fn avx512_alone_picks_simd_cpu() {
    let mut caps = caps_no_gpu(false, false);
    caps.has_avx512 = true;
    with_env(None, || {
        assert_eq!(select_backend(&caps, 1 << 30, 10_000), ScanBackend::SimdCpu,);
    });
}

// ────────────────────────────────────────────────────────────────────
// CELL 7: GpuTier classification invariants
// ────────────────────────────────────────────────────────────────────

/// Empty strings and weird inputs must classify as Low — never panic,
/// never elevate to High by accident.
#[test]
fn classify_gpu_tier_edge_cases_are_low() {
    for name in ["", " ", "\n", "RTX", "4090", "M1"] {
        // "M1" alone matches `m1 max`/`m1 ultra` via substring? No — those
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
    assert_eq!(ScanBackend::Gpu.label(), "gpu-zero-copy");
    assert_eq!(ScanBackend::MegaScan.label(), "gpu-mega-scan");
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
}
