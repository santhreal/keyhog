//! KH-GAP-145: SARIF tool driver `informationUri` pointed at github.com/keyhog/keyhog.

use crate::e2e::support::binary;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d
}

#[test]
fn sarif_information_uri_is_santhreal_keyhog() {
    let demo = repo_root().join("demo/config/demo-secret.env");
    let out = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "sarif",
        ])
        .arg(&demo)
        .output()
        .expect("spawn sarif scan");
    assert_eq!(out.status.code(), Some(0));
    let sarif: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("sarif stdout is JSON");
    let uri = sarif["runs"][0]["tool"]["driver"]["informationUri"]
        .as_str()
        .expect("informationUri");
    assert_eq!(
        uri, "https://github.com/santhreal/keyhog",
        "SARIF informationUri must match the published repo"
    );
}
