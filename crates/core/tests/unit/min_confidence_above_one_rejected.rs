//! min_confidence > 1.0 must fail validation.

use keyhog_core::ScanConfig;

#[test]
fn min_confidence_above_one_rejected() {
    let config = ScanConfig {
        min_confidence: 1.01,
        ..Default::default()
    };
    config.validate().expect_err("confidence above 1.0 must fail");
}
