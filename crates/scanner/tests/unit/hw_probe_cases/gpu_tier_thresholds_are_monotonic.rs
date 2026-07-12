//! Cross-tier MONOTONICITY invariant for the GPU routing thresholds.
//!
//! A more-capable GPU tier must never require a LARGER buffer / solo-file size /
//! pattern count before GPU routing engages than a less-capable tier — otherwise
//! a stronger adapter would be routed MORE conservatively than a weaker one,
//! which is incoherent. The per-tier value tests (`gpu_min_bytes_*_tier_*.rs`,
//! `gpu_pattern_breakeven_high_100.rs`, `gpu_solo_bytes_high_tier_256mb.rs`) pin
//! today's ABSOLUTE numbers; those change whenever the crossover is retuned
//! (e.g. lowering the high-tier `GPU_MIN_BYTES_HIGH_TIER` once a fresh 5090
//! crossover sweep lands — see the open thresholds.rs routing items). THIS test
//! pins the durable RELATIONSHIP instead, so it survives any such retune and
//! fails loudly if an edit inverts the tier ordering.
//!
//! Asserted through the real routing accessors (`gpu_*_for_tier`), the exact
//! functions the autorouter consults — not the raw constants — so the invariant
//! holds at the routing decision point, not merely in the constant table.

use keyhog_scanner::hw_probe::testing::{
    gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier, gpu_solo_bytes_for_tier, GpuTier,
};

#[test]
fn gpu_min_bytes_crossover_is_monotonic_high_le_mid_le_low() {
    let high = gpu_min_bytes_for_tier(GpuTier::High);
    let mid = gpu_min_bytes_for_tier(GpuTier::Mid);
    let low = gpu_min_bytes_for_tier(GpuTier::Low);
    assert!(
        high <= mid && mid <= low,
        "min-bytes crossover must be monotonic High<=Mid<=Low (a stronger GPU \
         engages no later than a weaker one), got High={high} Mid={mid} Low={low}"
    );
}

#[test]
fn gpu_solo_bytes_crossover_is_monotonic_high_le_mid_le_low() {
    let high = gpu_solo_bytes_for_tier(GpuTier::High);
    let mid = gpu_solo_bytes_for_tier(GpuTier::Mid);
    let low = gpu_solo_bytes_for_tier(GpuTier::Low);
    assert!(
        high <= mid && mid <= low,
        "solo-file byte crossover must be monotonic High<=Mid<=Low, \
         got High={high} Mid={mid} Low={low}"
    );
}

#[test]
fn gpu_pattern_breakeven_is_monotonic_high_le_mid_le_low() {
    let high = gpu_pattern_breakeven_for_tier(GpuTier::High);
    let mid = gpu_pattern_breakeven_for_tier(GpuTier::Mid);
    let low = gpu_pattern_breakeven_for_tier(GpuTier::Low);
    assert!(
        high <= mid && mid <= low,
        "pattern-count breakeven must be monotonic High<=Mid<=Low, \
         got High={high} Mid={mid} Low={low}"
    );
}

/// The tiering must be LOAD-BEARING, not vestigial: the strongest tier has to be
/// strictly more aggressive than the weakest on the primary buffer-size gate,
/// otherwise the whole High/Mid/Low distinction does nothing for routing.
#[test]
fn gpu_tiering_is_load_bearing_high_strictly_below_low() {
    assert!(
        gpu_min_bytes_for_tier(GpuTier::High) < gpu_min_bytes_for_tier(GpuTier::Low),
        "high-tier min-bytes must be STRICTLY below low-tier — the tiering must \
         actually route stronger GPUs sooner, not collapse to one threshold"
    );
    assert!(
        gpu_pattern_breakeven_for_tier(GpuTier::High)
            < gpu_pattern_breakeven_for_tier(GpuTier::Low),
        "high-tier pattern breakeven must be STRICTLY below low-tier"
    );
}
