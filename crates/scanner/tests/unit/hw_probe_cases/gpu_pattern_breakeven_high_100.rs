use keyhog_scanner::hw_probe::{gpu_pattern_breakeven_for_tier, thresholds, GpuTier};
#[test]
fn gpu_pattern_breakeven_high_100() {
    assert_eq!(
        gpu_pattern_breakeven_for_tier(GpuTier::High),
        thresholds::GPU_PATTERN_BREAKEVEN_HIGH_TIER
    );
}
