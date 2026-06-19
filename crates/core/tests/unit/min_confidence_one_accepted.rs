//! Boundary oracle: min_confidence=1.0 is valid per ScanConfig contract.

use keyhog_core::ScanConfig;

#[test]
fn min_confidence_one_accepted() {
    let config = ScanConfig {
        min_confidence: 1.0,
        ..Default::default()
    };
    keyhog_core::testing::CoreTestApi::scan_config_validate(&keyhog_core::testing::TestApi, &config)
        .expect("min_confidence=1.0 must be accepted");
}
