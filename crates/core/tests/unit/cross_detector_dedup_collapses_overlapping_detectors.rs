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
fn cross_detector_dedup_collapses_overlapping_detectors() {
    let input = vec![
        make_deduped("google-api-key", "google-api", 0.85),
        make_deduped("google-maps-api-key", "google-maps", 0.75),
        make_deduped("google-places-api-key", "google-places", 0.70),
    ];
    let out = dedup_cross_detector(input);
    assert_eq!(out.len(), 1, "three same-credential matches → one finding");
    let winner = &out[0];
    assert_eq!(winner.detector_id.as_ref(), "google-api-key");
    assert!(winner.companions.contains_key("cross_detector.0"));
    assert!(winner.companions.contains_key("cross_detector.1"));
}
