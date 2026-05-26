//! Boundary oracle: min_confidence=1.0 is valid per ScanConfig contract.

use keyhog_core::ScanConfig;

#[test]
fn min_confidence_one_accepted() {
    let config = ScanConfig {
        min_confidence: 1.0,
        ..Default::default()
    };
    config
        .validate()
        .expect("min_confidence=1.0 must be accepted");
}
