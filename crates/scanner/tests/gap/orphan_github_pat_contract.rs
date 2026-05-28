//! KH-GAP-127: Orphan contract TOML `github-pat` has no matching detector id.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/contracts")
}

#[test]
fn every_contract_stem_maps_to_loaded_detector_id() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let ids: BTreeSet<&str> = detectors.iter().map(|d| d.id.as_str()).collect();

    let mut orphans: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(contracts_dir()).expect("contracts dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
        if !ids.contains(stem.as_str()) {
            orphans.push(stem);
        }
    }

    assert!(
        orphans.is_empty(),
        "KH-GAP-127: contract TOMLs without matching detector id: {orphans:?}"
    );
}
