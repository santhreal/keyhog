//! GPU performance tier classifier + per-tier threshold lookups.
//! The substring heuristics in [`classify_gpu_tier`] are pure-fn so
//! the tier table is unit-testable without a real GPU.

use super::thresholds;

/// GPU performance tier inferred from the adapter name. Coarse but
/// matches measured dispatch latency well enough to drive routing.
/// `Unknown` keeps the legacy conservative thresholds, so an unfamiliar
/// adapter is never wrongly routed to the lower-threshold path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuTier {
    /// RTX 40/50-series, A100/H100, M-series Max/Ultra, RX 7900 XTX.
    /// Sub-300µs dispatch latency.
    High,
    /// RTX 20/30-series, GTX 16, Intel Arc, M-series base/Pro,
    /// RX 6000-series. ~600-1500µs dispatch latency.
    Mid,
    /// iGPU, older discrete cards, anything we can't classify.
    /// Multi-millisecond dispatch latency assumed.
    Low,
}

/// Classify a GPU adapter name into a performance tier. Pure
/// substring heuristics - bumped only when a new high-volume part
/// ships (or the user reports a misclassification).
#[must_use]
pub fn classify_gpu_tier(adapter_name: Option<&str>) -> GpuTier {
    let Some(name) = adapter_name else {
        return GpuTier::Low;
    };
    let lower = name.to_ascii_lowercase();

    // High-tier discretes.
    if lower.contains("rtx 40")
        || lower.contains("rtx 50")
        || lower.contains("rtx 4090")
        || lower.contains("rtx 4080")
        || lower.contains("rtx 4070")
        || lower.contains("rtx 5090")
        || lower.contains("rtx 5080")
        || lower.contains("rtx 5070")
        || lower.contains("a100")
        || lower.contains("h100")
        || lower.contains("h200")
        || lower.contains("rx 7900 xtx")
        || lower.contains("rx 7900 xt")
        || lower.contains("m4 max")
        || lower.contains("m3 max")
        || lower.contains("m2 max")
        || lower.contains("m1 max")
        || lower.contains("m4 ultra")
        || lower.contains("m3 ultra")
        || lower.contains("m2 ultra")
        || lower.contains("m1 ultra")
    {
        return GpuTier::High;
    }

    // Mid-tier discretes.
    if lower.contains("rtx 20")
        || lower.contains("rtx 30")
        || lower.contains("gtx 16")
        || lower.contains("arc")
        || lower.contains("rx 6")
        || lower.contains("rx 7")
        || lower.contains("apple m1")
        || lower.contains("apple m2")
        || lower.contains("apple m3")
        || lower.contains("apple m4")
        || lower.contains("m1 pro")
        || lower.contains("m2 pro")
        || lower.contains("m3 pro")
        || lower.contains("m4 pro")
    {
        return GpuTier::Mid;
    }

    GpuTier::Low
}

/// GPU minimum-bytes routing threshold for the given tier.
#[must_use]
pub fn gpu_min_bytes_for_tier(tier: GpuTier) -> u64 {
    match tier {
        GpuTier::High => thresholds::GPU_MIN_BYTES_HIGH_TIER,
        GpuTier::Mid => thresholds::GPU_MIN_BYTES_MID_TIER,
        GpuTier::Low => thresholds::GPU_MIN_BYTES,
    }
}

/// GPU single-file solo-breakeven threshold for the given tier.
#[must_use]
pub fn gpu_solo_bytes_for_tier(tier: GpuTier) -> u64 {
    match tier {
        GpuTier::High => thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER,
        GpuTier::Mid => thresholds::GPU_BYTES_BREAKEVEN_SOLO_MID_TIER,
        GpuTier::Low => thresholds::GPU_BYTES_BREAKEVEN_SOLO,
    }
}

/// Pattern-count threshold for the given tier. Below this and below
/// the solo-cap, GPU dispatch costs more than Hyperscan saves -
/// stay on SIMD.
#[must_use]
pub fn gpu_pattern_breakeven_for_tier(tier: GpuTier) -> usize {
    match tier {
        GpuTier::High => thresholds::GPU_PATTERN_BREAKEVEN_HIGH_TIER,
        GpuTier::Mid => thresholds::GPU_PATTERN_BREAKEVEN_MID_TIER,
        GpuTier::Low => thresholds::GPU_PATTERN_BREAKEVEN,
    }
}
