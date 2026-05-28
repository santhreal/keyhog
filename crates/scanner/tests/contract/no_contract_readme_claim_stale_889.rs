//! Contract: no contract TOML pins the stale `889 service-specific detectors` claim.

use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

#[test]
fn no_contract_readme_claim_stale_889() {
    const STALE: &str = "889 service-specific detectors";

    let mut stale: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(contracts_dir()).expect("contracts dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        if path.parent().and_then(|p| p.file_name()) != Some(std::ffi::OsStr::new("contracts")) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read contract");
        if text.contains(STALE) {
            stale.push(path.file_stem().unwrap().to_string_lossy().into_owned());
        }
    }

    assert!(
        stale.is_empty(),
        "{}/{} contracts still pin stale readme_claim {:?} - first 20: {:?}",
        stale.len(),
        stale.len(),
        STALE,
        stale.iter().take(20).collect::<Vec<_>>()
    );
}
