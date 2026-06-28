//! Gap test: exact startup-banner text shape (CLI contract).
//!
//! `startup_banner` formats the one-line hardware summary the `keyhog backend`
//! text-vs-JSON diffing tests parse, so its shape is a contract. The existing
//! unit tests only assert weak substrings (`banner.contains("GPU: none")`);
//! this pins the WHOLE string across every branch: the three GPU states
//! (named / software-ignored / none), all four SIMD tiers (AVX-512 > AVX2 >
//! NEON > scalar), both literal engines (Hyperscan / AC), and the optional
//! trailing ` io_uring`.

use keyhog_scanner::hw_probe::{startup_banner, HardwareCaps};

#[allow(clippy::too_many_arguments)]
fn caps(
    physical_cores: usize,
    gpu_name: Option<&str>,
    gpu_is_software: bool,
    has_avx512: bool,
    has_avx2: bool,
    has_neon: bool,
    hyperscan_available: bool,
    io_uring_available: bool,
) -> HardwareCaps {
    HardwareCaps {
        physical_cores,
        logical_cores: physical_cores * 2,
        has_avx2,
        has_avx512,
        has_neon,
        gpu_available: gpu_name.is_some(),
        gpu_name: gpu_name.map(str::to_string),
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software,
        total_memory_mb: Some(16384),
        io_uring_available,
        hyperscan_available,
    }
}

#[test]
fn high_end_box_banner_is_exact() {
    // Real GPU + AVX-512 + Hyperscan + io_uring.
    let c = caps(16, Some("NVIDIA GeForce RTX 4090"), false, true, true, false, true, true);
    assert_eq!(
        startup_banner(&c, 42, 1234),
        "16 cores | GPU: NVIDIA GeForce RTX 4090 | SIMD: AVX-512 | Hyperscan | 42 detectors (1234 patterns) io_uring"
    );
}

#[test]
fn software_gpu_avx2_ac_banner_is_exact() {
    // Software GPU is surfaced as "(software, ignored)"; AVX2 tier; AC; no uring.
    let c = caps(8, Some("llvmpipe"), true, false, true, false, false, false);
    assert_eq!(
        startup_banner(&c, 10, 200),
        "8 cores | GPU: llvmpipe (software, ignored) | SIMD: AVX2 | AC | 10 detectors (200 patterns)"
    );
}

#[test]
fn no_gpu_neon_banner_is_exact() {
    // No GPU -> "GPU: none"; NEON tier (no avx); AC; no uring.
    let c = caps(4, None, false, false, false, true, false, false);
    assert_eq!(
        startup_banner(&c, 5, 50),
        "4 cores | GPU: none | SIMD: NEON | AC | 5 detectors (50 patterns)"
    );
}

#[test]
fn scalar_fallback_banner_is_exact() {
    // No SIMD feature -> "scalar".
    let c = caps(2, None, false, false, false, false, false, false);
    assert_eq!(
        startup_banner(&c, 1, 1),
        "2 cores | GPU: none | SIMD: scalar | AC | 1 detectors (1 patterns)"
    );
}
