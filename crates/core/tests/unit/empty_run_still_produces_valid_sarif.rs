//! Migrated from `src/report/sarif.rs` inline tests.
use crate::support::reporters::SarifReporter;
#[test]
fn empty_run_still_produces_valid_sarif() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.finish().unwrap();
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    assert_eq!(json["version"].as_str(), Some("2.1.0"));
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert!(results.is_empty());
}
