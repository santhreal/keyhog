//! Contract: `scripts/generate_contracts.py` pins the same detector count as README.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn generate_contracts_script_readme_claim_is_902() {
    let script = repo_root().join("scripts/generate_contracts.py");
    let text = std::fs::read_to_string(&script)
        .unwrap_or_else(|e| panic!("read {}: {e}", script.display()));

    assert!(
        text.contains("README_CLAIM = \"902 service-specific detectors\""),
        "generate_contracts.py must pin README_CLAIM to 902 - stale counts poison new contract TOMLs"
    );
}
