use keyhog_scanner::hw_probe::{classify_gpu_tier, GpuTier};
#[test]
fn classify_gpu_tier_none_is_low() {
    assert_eq!(classify_gpu_tier(None), GpuTier::Low);
}
