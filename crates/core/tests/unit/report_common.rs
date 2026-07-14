use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;

pub fn sample_finding() -> VerifiedFinding {
    let mut metadata = HashMap::new();
    metadata.insert("account_id".to_string(), "123456789012".to_string());

    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key, \"prod\" <a&b>"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: std::borrow::Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [
            0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]
        .into(),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config/app.env")),
            line: Some(12),
            offset: 5,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata,
        additional_locations: vec![],
        confidence: Some(0.875),
    }
}
