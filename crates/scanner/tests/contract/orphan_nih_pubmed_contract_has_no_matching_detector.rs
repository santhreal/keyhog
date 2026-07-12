//! Contract: every top-level contract TOML maps to a loaded detector id.

use crate::support::paths::detector_dir;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

#[test]
fn orphan_nih_pubmed_contract_has_no_matching_detector() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let ids: BTreeSet<&str> = detectors.iter().map(|d| d.id.as_str()).collect();

    let mut orphans: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(contracts_dir()).expect("contracts dir") {
        let path = entry.expect("dir entry").path();
        if path.parent().and_then(|p| p.file_name()) != Some(std::ffi::OsStr::new("contracts")) {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_string_lossy();
        if !ids.contains(stem.as_ref()) {
            orphans.push(stem.into_owned());
        }
    }

    assert!(
        orphans.is_empty(),
        "contract TOMLs without matching detector id: {:?}",
        orphans
    );
}
