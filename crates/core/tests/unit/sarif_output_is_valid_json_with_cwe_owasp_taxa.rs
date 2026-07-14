//! Migrated from `src/report/sarif.rs` inline tests.
use crate::support::reporters::SarifReporter;
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;
fn synthetic_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential_redacted: std::borrow::Cow::Borrowed("****redacted"),
        credential_hash: [0; 32].into(),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config.env")),
            line: Some(42),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: Some(0.9),
    }
}
#[test]
fn sarif_output_is_valid_json_with_cwe_owasp_taxa() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.report(&synthetic_finding()).unwrap();
        r.finish().unwrap();
    }
    let json: serde_json::Value =
        serde_json::from_slice(&buf).expect("SARIF output must parse as JSON");

    // Per-result properties carry CWE and OWASP refs.
    let cwe = json["runs"][0]["results"][0]["properties"]["cwe"].as_str();
    assert_eq!(cwe, Some("CWE-798"));
    let owasp = json["runs"][0]["results"][0]["properties"]["owasp"].as_str();
    assert_eq!(owasp, Some("A07:2021"));

    // runs[0].taxonomies block resolves the CWE/OWASP references.
    let tax_name = json["runs"][0]["taxonomies"][0]["name"].as_str();
    assert_eq!(tax_name, Some("CWE"));
    let cwe_taxa_id = json["runs"][0]["taxonomies"][0]["taxa"][0]["id"].as_str();
    assert_eq!(cwe_taxa_id, Some("CWE-798"));
    let owasp_name = json["runs"][0]["taxonomies"][1]["name"].as_str();
    assert_eq!(owasp_name, Some("OWASP"));

    // SARIF v2.2 fixes[]: a replacement suggestion for the leaked
    // credential. With service="test" we expect ${TEST_KEY} fallback.
    let fix_replacement = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
        ["replacements"][0]["insertedContent"]["text"]
        .as_str();
    assert_eq!(fix_replacement, Some("${TEST_KEY}"));
    let fix_uri = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
        ["artifactLocation"]["uri"]
        .as_str();
    assert_eq!(fix_uri, Some("config.env"));
}
