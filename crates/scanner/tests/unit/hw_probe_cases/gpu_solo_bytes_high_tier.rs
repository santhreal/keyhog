use keyhog_scanner::hw_probe::{gpu_solo_bytes_for_tier, thresholds, GpuTier};
#[test]
fn gpu_solo_bytes_high_tier() {
    assert_eq!(
        gpu_solo_bytes_for_tier(GpuTier::High),
        thresholds::GPU_BYTES_BREAKEVEN_SOLO_HIGH_TIER
    );
}
