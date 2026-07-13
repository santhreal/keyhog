//! Gap test: Mid/Low-tier GPU routing thresholds (MiB-unit consts).
//!
//! The hw_probe threshold byte sizes now share a single `MIB` (= 1024 * 1024)
//! multiplier (e.g. `GPU_BYTES_BREAKEVEN_SOLO = 1024 * MIB`). Iter 62's table
//! test pinned the High-tier solo/pattern thresholds; this pins the Mid and Low
//! tiers, the rows that carry the refactored `1024 * MIB` (low solo = 1 GiB),
//! `512 * MIB` (mid solo / low min) consts, so the MIB-unit rewrite cannot
//! silently change any value.

use keyhog_scanner::hw_probe::gpu_routing_profiles;

const MIB: u64 = 1024 * 1024;

#[test]
fn mid_tier_solo_and_pattern_breakeven_are_exact() {
    let mid = gpu_routing_profiles()[1];
    assert_eq!(mid.tier, "mid");
    // GPU_BYTES_BREAKEVEN_SOLO_MID_TIER = 512 * MIB.
    assert_eq!(mid.solo_bytes, 512 * MIB);
    // GPU_PATTERN_BREAKEVEN_MID_TIER.
    assert_eq!(mid.pattern_breakeven, 500);
}

#[test]
fn low_tier_thresholds_are_the_conservative_defaults() {
    let low = gpu_routing_profiles()[2];
    assert_eq!(low.tier, "low");
    // GPU_MIN_BYTES = 512 * MIB (most conservative min floor).
    assert_eq!(low.min_bytes, 512 * MIB);
    // GPU_BYTES_BREAKEVEN_SOLO = 1024 * MIB = 1 GiB.
    assert_eq!(low.solo_bytes, 1024 * MIB);
    assert_eq!(low.solo_bytes, 1024 * 1024 * 1024);
    // GPU_PATTERN_BREAKEVEN (low/default).
    assert_eq!(low.pattern_breakeven, 2_000);
}
