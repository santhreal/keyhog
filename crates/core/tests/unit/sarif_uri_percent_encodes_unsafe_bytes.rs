//! Migrated from `src/report/sarif.rs` inline tests.
use keyhog_core::{
    MatchLocation, Reporter, SarifReporter, Severity, VerificationResult, VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;
fn synthetic_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential_redacted: std::borrow::Cow::Borrowed("****redacted"),
        credential_hash: [0; 32],
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
        confidence: Some(0.9),
    }
}
#[test]
fn sarif_uri_percent_encodes_unsafe_bytes() {
    assert_eq!(
        keyhog_core::report::sarif_uri::file_path_to_sarif_uri("/tmp/file with space.env"),
        "file:///tmp/file%20with%20space.env"
    );
    assert_eq!(
        keyhog_core::report::sarif_uri::file_path_to_sarif_uri("/tmp/réport.json"),
        "file:///tmp/r%C3%A9port.json"
    );
    assert_eq!(
        keyhog_core::report::sarif_uri::file_path_to_sarif_uri("/tmp/foo?bar#baz"),
        "file:///tmp/foo%3Fbar%23baz"
    );
}
