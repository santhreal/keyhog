use keyhog_scanner::hw_probe::testing::{classify_gpu_tier, GpuTier};
#[test]
fn classify_gpu_tier_uhd_low() {
    assert_eq!(
        classify_gpu_tier(Some("Intel UHD Graphics 630")),
        GpuTier::Low
    );
}
