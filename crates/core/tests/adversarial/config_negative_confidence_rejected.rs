//! Adversarial: negative min_confidence must fail validation.

use keyhog_core::ScanConfig;

#[test]
fn config_negative_confidence_rejected() {
    let config = ScanConfig {
        min_confidence: -0.1,
        ..Default::default()
    };
    keyhog_core::testing::CoreTestApi::scan_config_validate(
        &keyhog_core::testing::TestApi,
        &config,
    )
    .expect_err("negative confidence must fail");
}
