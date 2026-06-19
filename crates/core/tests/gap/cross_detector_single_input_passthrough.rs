//! Single-element cross-detector dedup must pass through unchanged cardinality.

use keyhog_core::{dedup_cross_detector, DedupedMatch, MatchLocation, Severity};
use std::collections::HashMap;
use std::sync::Arc;

#[test]
fn cross_detector_single_input_passthrough() {
    let one = DedupedMatch {
        detector_id: Arc::from("solo"),
        detector_name: Arc::from("solo"),
        service: Arc::from("solo"),
        severity: Severity::Low,
        credential: keyhog_core::SensitiveString::from("x"),
        credential_hash: [0; 32],
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("t"),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        confidence: None,
    };
    let out = dedup_cross_detector(vec![one]);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].detector_id.as_ref(), "solo");
}
