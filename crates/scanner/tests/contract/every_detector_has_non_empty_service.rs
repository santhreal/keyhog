//! Contract: every loaded detector declares a non-empty `service` field.

use crate::support::paths::detector_dir;

#[test]
fn every_detector_has_non_empty_service() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let empty: Vec<_> = detectors
        .iter()
        .filter(|d| d.service.trim().is_empty())
        .map(|d| d.id.as_str())
        .collect();

    assert!(
        empty.is_empty(),
        "detectors with empty service field: {:?}",
        empty
    );
}
