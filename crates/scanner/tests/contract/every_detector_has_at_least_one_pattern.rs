//! Contract: every detector ships at least one regex pattern.

use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn every_detector_has_at_least_one_pattern() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let bare: Vec<_> = detectors
        .iter()
        .filter(|d| d.patterns.is_empty())
        .map(|d| d.id.as_str())
        .collect();

    assert!(
        bare.is_empty(),
        "detectors with zero patterns (unmatchable): {:?}",
        bare
    );
}
