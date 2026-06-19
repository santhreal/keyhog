use keyhog_scanner::hw_probe::testing::{gpu_solo_bytes_for_tier, GpuTier};
use keyhog_scanner::testing::thresholds;
#[test]
fn gpu_solo_bytes_high_tier_256mb() {
    assert_eq!(
        gpu_solo_bytes_for_tier(GpuTier::High),
        thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER
    );
    assert_eq!(
        thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER,
        256 * 1024 * 1024
    );
}
