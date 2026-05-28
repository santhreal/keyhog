//! Contract: SARIF `tool.driver.version` tracks the keyhog-core crate semver.

use keyhog_core::{Reporter, SarifReporter};

#[test]
fn sarif_tool_driver_version_matches_crate() {
    let mut buf = Vec::new();
    SarifReporter::new(&mut buf).finish().expect("finish");
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    let version = json["runs"][0]["tool"]["driver"]["version"]
        .as_str()
        .expect("runs[0].tool.driver.version must be a string");
    assert_eq!(
        version,
        env!("CARGO_PKG_VERSION"),
        "SARIF tool.driver.version must match keyhog-core semver"
    );
}
