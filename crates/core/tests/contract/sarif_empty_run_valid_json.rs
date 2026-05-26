//! Contract: empty SARIF run still emits schema version 2.1.0 and empty results.

use keyhog_core::{Reporter, SarifReporter};

#[test]
fn sarif_empty_run_still_produces_valid_sarif() {
    let mut buf = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.finish().expect("finish empty run");
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    assert_eq!(json["version"].as_str(), Some("2.1.0"));
    assert!(json["runs"][0]["results"].as_array().expect("results").is_empty());
}
