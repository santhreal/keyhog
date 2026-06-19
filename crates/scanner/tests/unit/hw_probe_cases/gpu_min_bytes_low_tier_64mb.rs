use keyhog_scanner::hw_probe::testing::{gpu_min_bytes_for_tier, GpuTier};
use keyhog_scanner::testing::thresholds;
#[test]
fn gpu_min_bytes_low_tier_64mb() {
    assert_eq!(
        gpu_min_bytes_for_tier(GpuTier::Low),
        thresholds::GPU_MIN_BYTES
    );
}
