//! Boundary oracle: min_confidence=0.0 is valid per ScanConfig contract.

use keyhog_core::ScanConfig;

#[test]
fn min_confidence_zero_accepted() {
    let config = ScanConfig {
        min_confidence: 0.0,
        ..Default::default()
    };
    keyhog_core::testing::CoreTestApi::scan_config_validate(&keyhog_core::testing::TestApi, &config)
        .expect("min_confidence=0.0 must be accepted");
}
