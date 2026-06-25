//! min_confidence > 1.0 must fail validation.

use keyhog_core::ScanConfig;

#[test]
fn min_confidence_above_one_rejected() {
    let config = ScanConfig {
        min_confidence: 1.01,
        ..Default::default()
    };
    keyhog_core::testing::CoreTestApi::scan_config_validate(
        &keyhog_core::testing::TestApi,
        &config,
    )
    .expect_err("confidence above 1.0 must fail");
}
