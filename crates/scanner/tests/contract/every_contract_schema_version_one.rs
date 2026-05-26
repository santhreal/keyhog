//! Contract: every top-level contract TOML declares `schema_version = 1`.

use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

#[test]
fn every_contract_schema_version_one() {
    let mut bad: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(contracts_dir()).expect("contracts dir") {
        let path = entry.expect("dir entry").path();
        if path.parent().and_then(|p| p.file_name()) != Some(std::ffi::OsStr::new("contracts")) {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read contract");
        if !text.contains("schema_version = 1") {
            bad.push(path.file_stem().unwrap().to_string_lossy().into_owned());
        }
    }

    assert!(
        bad.is_empty(),
        "contracts missing schema_version = 1: {:?}",
        bad.iter().take(20).collect::<Vec<_>>()
    );
}
