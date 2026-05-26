use keyhog_scanner::hw_probe::{classify_gpu_tier, GpuTier};
#[test]
fn classify_gpu_tier_intel_arc_mid() {
    assert_eq!(classify_gpu_tier(Some("Intel(R) Arc A770 Graphics")), GpuTier::Mid);
}
