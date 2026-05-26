use keyhog_scanner::hw_probe::{classify_gpu_tier, GpuTier};
#[test]
fn classify_gpu_tier_rtx3060_mid() {
    assert_eq!(
        classify_gpu_tier(Some("NVIDIA GeForce RTX 3060")),
        GpuTier::Mid
    );
}
