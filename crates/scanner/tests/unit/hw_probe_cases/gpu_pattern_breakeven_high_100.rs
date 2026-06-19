use keyhog_scanner::hw_probe::testing::{gpu_pattern_breakeven_for_tier, GpuTier};
use keyhog_scanner::testing::thresholds;
#[test]
fn gpu_pattern_breakeven_high_100() {
    assert_eq!(
        gpu_pattern_breakeven_for_tier(GpuTier::High),
        thresholds::GPU_PATTERN_BREAKEVEN_HIGH_TIER
    );
}
