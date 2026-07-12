//! Contract: every detector declares a human-readable `name`.

use crate::support::paths::detector_dir;

#[test]
fn every_detector_has_non_empty_name() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let empty: Vec<_> = detectors
        .iter()
        .filter(|d| d.name.trim().is_empty())
        .map(|d| d.id.as_str())
        .collect();

    assert!(
        empty.is_empty(),
        "detectors with empty name field: {:?}",
        empty
    );
}
