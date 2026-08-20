//! One-line startup banner formatter. Stable text shape is part of
//! the CLI contract (parsed by the `keyhog backend` text-vs-JSON
//! diffing tests).

use super::HardwareCaps;

/// Format a one-line startup banner summarizing detected hardware.
pub fn startup_banner(caps: &HardwareCaps, detector_count: usize, pattern_count: usize) -> String {
    let gpu = if caps.gpu_available {
        let name = caps.gpu_name.as_deref().unwrap_or("available"); // LAW10: display-only label for an unnamed adapter
        if caps.gpu_is_software {
            format!("GPU: {name} (software, ignored)")
        } else {
            format!("GPU: {name}")
        }
    } else if let Some(name) = &caps.gpu_name {
        if caps.gpu_is_software {
            format!("GPU: {name} (software, ignored)")
        } else if !super::gpu_backend_compiled() {
            format!(
                "GPU: {name} ({})",
                super::uncompiled_gpu_backend_explanation()
            )
        } else {
            format!("GPU: {name} (not active)")
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
