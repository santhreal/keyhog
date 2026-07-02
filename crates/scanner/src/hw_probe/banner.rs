//! One-line startup banner formatter. Stable text shape is part of
//! the CLI contract (parsed by the `keyhog backend` text-vs-JSON
//! diffing tests).

use super::HardwareCaps;

/// Format a one-line startup banner summarizing detected hardware.
pub fn startup_banner(caps: &HardwareCaps, detector_count: usize, pattern_count: usize) -> String {
    let gpu = if let Some(name) = &caps.gpu_name {
        if caps.gpu_is_software {
            // Software-only adapters (llvmpipe, lavapipe, swiftshader) get
            // detected and probed, but `select_backend` rejects them
            // because dispatching the literal-set pipeline through CPU-
            // emulated GL/Vulkan is slower than just running the SIMD
            // path directly. Surface this in the banner so users on
            // headless boxes (CI runners, containers) understand why
            // their scan is using SIMD even though `keyhog backend`
            // shows a "GPU" line.
            format!("GPU: {name} (software, ignored)")
        } else {
            format!("GPU: {name}")
        }
    } else {
        "GPU: none".to_string()
    };

    let simd = super::simd_label(caps.has_avx512, caps.has_avx2, caps.has_neon);

    let hs = if caps.hyperscan_available {
        "Hyperscan"
    } else {
        "AC"
    };
    let uring = if caps.io_uring_available {
        " io_uring"
    } else {
        ""
    };

    format!(
        "{} cores | {} | SIMD: {} | {} | {detector_count} detectors ({pattern_count} patterns){uring}",
        caps.physical_cores, gpu, simd, hs,
    )
}
