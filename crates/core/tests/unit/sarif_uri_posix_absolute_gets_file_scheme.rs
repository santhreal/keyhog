//! Migrated from `src/report/sarif.rs` inline tests.
use keyhog_core::{Reporter, MatchLocation, SarifReporter, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;
fn synthetic_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential_redacted: std::borrow::Cow::Borrowed("****redacted"),
        credential_hash: "abcdefabcdefabcdef".into(),
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
    fn sarif_uri_posix_absolute_gets_file_scheme() {
        assert_eq!(
            keyhog_core::report::sarif_uri::file_path_to_sarif_uri("/etc/secrets.env"),
            "file:///etc/secrets.env"
        );
        assert_eq!(
            keyhog_core::report::sarif_uri::file_path_to_sarif_uri("/home/u/.aws/credentials"),
            "file:///home/u/.aws/credentials"
        );
    }
