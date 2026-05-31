use keyhog_core::{dedup_cross_detector, DedupedMatch, MatchLocation, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn make_deduped(detector: &str, service: &str, conf: f64) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: Severity::High,
        credential: Arc::from("AIza_FAKE_KEY_NOT_REAL_VALUE_1234567890"),
        credential_hash: [0; 32],
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("test"),
            file_path: Some(Arc::from("config.js")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        confidence: Some(conf),
    }
}

#[test]
fn cross_detector_dedup_does_not_cross_files() {
    let a = make_deduped("aws-access-key", "aws", 0.9);
    let mut b = make_deduped("aws-access-key", "aws", 0.9);
    b.primary_location.file_path = Some(Arc::from("other.js"));
    let out = dedup_cross_detector(vec![a, b]);
    assert_eq!(out.len(), 2, "same credential in two files = two findings");
}
