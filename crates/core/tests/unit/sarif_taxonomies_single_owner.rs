//! Migrated from `src/report/sarif_taxonomies.rs` inline tests (KH-GAP-004).
//!
//! The inline test reached into the private `sarif_taxonomies_json()` builder
//! and the `pub(super)` id constants. Here the SAME cross-reference guarantee
//! is asserted end-to-end through the public SARIF report output: the
//! `runs[0].taxonomies[*].taxa[0].id` values MUST equal the per-result
//! `properties.cwe` / `.owasp` refs, or consuming dashboards silently fail to
//! resolve the taxonomy links.

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

fn sarif_json() -> serde_json::Value {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.report(&synthetic_finding()).unwrap();
        r.finish().unwrap();
    }
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

#[test]
fn taxonomies_block_has_exactly_two_entries() {
    let json = sarif_json();
    let taxonomies = json["runs"][0]["taxonomies"]
        .as_array()
        .expect("taxonomies is a JSON array");
    assert_eq!(
        taxonomies.len(),
        2,
        "expected exactly CWE + OWASP taxonomies"
    );
}

#[test]
fn cwe_taxa_id_equals_result_cwe_property() {
    let json = sarif_json();
    let taxa_id = json["runs"][0]["taxonomies"][0]["taxa"][0]["id"].as_str();
    let result_cwe = json["runs"][0]["results"][0]["properties"]["cwe"].as_str();
    assert_eq!(taxa_id, Some("CWE-798"));
    assert_eq!(result_cwe, Some("CWE-798"));
    assert_eq!(
        taxa_id, result_cwe,
        "the CWE taxa id must equal the per-result cwe ref or the link fails to resolve"
    );
}

#[test]
fn owasp_taxa_id_equals_result_owasp_property() {
    let json = sarif_json();
    let taxa_id = json["runs"][0]["taxonomies"][1]["taxa"][0]["id"].as_str();
    let result_owasp = json["runs"][0]["results"][0]["properties"]["owasp"].as_str();
    assert_eq!(taxa_id, Some("A07:2021"));
    assert_eq!(result_owasp, Some("A07:2021"));
    assert_eq!(
        taxa_id, result_owasp,
        "the OWASP taxa id must equal the per-result owasp ref or the link fails to resolve"
    );
}
