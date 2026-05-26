use keyhog_scanner::hw_probe::{gpu_min_bytes_for_tier, GpuTier, thresholds};
#[test]
fn gpu_min_bytes_mid_tier_16mb() {
    assert_eq!(gpu_min_bytes_for_tier(GpuTier::Mid), thresholds::GPU_MIN_BYTES_MID_TIER);
}
