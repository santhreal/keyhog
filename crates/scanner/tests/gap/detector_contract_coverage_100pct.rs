//! KH-GAP-011: Every loaded detector id must have a contract TOML (100% by id).

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
fn every_detector_id_has_contract() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load");
    let ids: BTreeSet<String> = detectors.into_iter().map(|d| d.id.to_string()).collect();

    let contract_stems: BTreeSet<String> = std::fs::read_dir(contracts_dir())
        .expect("contracts dir")
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            (p.extension().and_then(|s| s.to_str()) == Some("toml"))
                .then(|| p.file_stem()?.to_str()?.to_string())
        })
        .collect();

    let missing: Vec<_> = ids.difference(&contract_stems).collect();
    assert!(
        missing.is_empty(),
        "KH-GAP-011: {} detector ids lack tests/contracts/<id>.toml: {:?}",
        missing.len(),
        missing.iter().take(20).collect::<Vec<_>>()
    );
}
