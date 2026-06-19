use keyhog_scanner::hw_probe::testing::{classify_gpu_tier, GpuTier};
#[test]
fn classify_gpu_tier_rtx4090_high() {
    assert_eq!(
        classify_gpu_tier(Some("NVIDIA GeForce RTX 4090")),
        GpuTier::High
    );
}
