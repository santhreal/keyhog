//! Contract: every loaded detector id has `tests/contracts/<id>.toml`.

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
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

fn contract_stems_on_disk() -> BTreeSet<String> {
    std::fs::read_dir(contracts_dir())
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| {
                    let p = e.path();
                    if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                        return None;
                    }
                    p.file_stem()
                        .and_then(|s| s.to_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
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
        "{}/{} loaded detectors missing tests/contracts/<id>.toml — first 20:\n  - {}",
        missing.len(),
        detectors.len(),
        missing.iter().take(20).cloned().collect::<Vec<_>>().join("\n  - ")
    );
}
