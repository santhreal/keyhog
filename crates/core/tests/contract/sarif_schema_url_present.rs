//! Contract: SARIF document exposes the OASIS 2.1.0 schema URL in `$schema`.

use keyhog_core::{Reporter, SarifReporter};

const SARIF_SCHEMA_URL: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json";

#[test]
fn sarif_schema_url_present() {
    let mut buf = Vec::new();
    SarifReporter::new(&mut buf).finish().expect("finish");
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    assert_eq!(
        json["$schema"].as_str(),
        Some(SARIF_SCHEMA_URL),
        "SARIF $schema must reference the OASIS 2.1.0 schema URL"
    );
}
