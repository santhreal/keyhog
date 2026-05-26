//! Contract: SARIF document version field is exactly 2.1.0.

use keyhog_core::{Reporter, SarifReporter};

#[test]
fn sarif_version_is_2_1_0() {
    let mut buf = Vec::new();
    SarifReporter::new(&mut buf).finish().expect("finish");
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("json");
    assert_eq!(json["version"].as_str(), Some("2.1.0"));
}
