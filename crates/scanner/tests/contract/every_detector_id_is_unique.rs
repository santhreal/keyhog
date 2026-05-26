//! Contract: detector ids are unique across the loaded catalog.

use std::collections::BTreeMap;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

#[test]
fn every_detector_id_is_unique() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &detectors {
        *seen.entry(d.id.as_str()).or_insert(0) += 1;
    }
    let dupes: Vec<_> = seen
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(id, n)| format!("{id}×{n}"))
        .collect();

    assert!(dupes.is_empty(), "duplicate detector ids: {:?}", dupes);
}
