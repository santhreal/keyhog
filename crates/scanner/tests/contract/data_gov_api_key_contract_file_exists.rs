//! Contract: `data-gov-api-key` ships a per-detector contract TOML.

use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

#[test]
fn data_gov_api_key_contract_file_exists() {
    let path = contracts_dir().join("data-gov-api-key.toml");
    assert!(
        path.is_file(),
        "missing contract for data-gov-api-key at {}",
        path.display()
    );
}
