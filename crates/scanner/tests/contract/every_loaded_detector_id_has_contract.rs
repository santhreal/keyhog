//! Contract: every loaded detector id has `tests/contracts/<id>.toml`.

use crate::support::paths::detector_dir;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

fn contract_stems_on_disk() -> BTreeSet<String> {
    let dir = contracts_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read contracts dir {}: {e}", dir.display()));
    entries
        .map(|entry| {
            entry.unwrap_or_else(|e| panic!("read contracts dir entry {}: {e}", dir.display()))
        })
        .filter_map(|e| {
            let p = e.path();
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                return None;
            }
            p.file_stem().and_then(|s| s.to_str()).map(str::to_string)
        })
        .collect()
}

#[test]
fn every_loaded_detector_id_has_contract() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let contracts = contract_stems_on_disk();

    let missing: Vec<String> = detectors
        .iter()
        .filter(|d| !contracts.contains(d.id.as_str()))
        .map(|d| d.id.clone())
        .collect();

    assert!(
        missing.is_empty(),
        "{}/{} loaded detectors missing tests/contracts/<id>.toml - first 20:\n  - {}",
        missing.len(),
        detectors.len(),
        missing
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  - ")
    );
}
