use keyhog_scanner::hw_probe::{classify_gpu_tier, GpuTier};
#[test]
fn classify_gpu_tier_a100_high() {
    assert_eq!(classify_gpu_tier(Some("NVIDIA A100-SXM4-40GB")), GpuTier::High);
}
