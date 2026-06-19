use keyhog_scanner::hw_probe::testing::{gpu_min_bytes_for_tier, GpuTier};
use keyhog_scanner::testing::thresholds;
#[test]
fn gpu_min_bytes_mid_tier_256mb() {
    assert_eq!(
        gpu_min_bytes_for_tier(GpuTier::Mid),
        thresholds::GPU_MIN_BYTES_MID_TIER
    );
    assert_eq!(thresholds::GPU_MIN_BYTES_MID_TIER, 256 * 1024 * 1024);
}
