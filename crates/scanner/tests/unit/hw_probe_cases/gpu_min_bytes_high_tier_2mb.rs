use keyhog_scanner::hw_probe::testing::{gpu_min_bytes_for_tier, GpuTier};
use keyhog_scanner::testing::thresholds;
#[test]
fn gpu_min_bytes_high_tier_2mb() {
    assert_eq!(
        gpu_min_bytes_for_tier(GpuTier::High),
        thresholds::GPU_MIN_BYTES_HIGH_TIER
    );
}
