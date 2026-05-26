//! Contract: `npm-access-token` ships a per-detector contract TOML.

use std::path::PathBuf;

fn contracts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
}

#[test]
fn npm_access_token_contract_file_exists() {
    let path = contracts_dir().join("npm-access-token.toml");
    assert!(
        path.is_file(),
        "missing contract for npm-access-token at {}",
        path.display()
    );
}
