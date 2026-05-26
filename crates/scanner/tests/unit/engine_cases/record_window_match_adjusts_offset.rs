use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::engine::record_window_match;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

#[test]
fn record_window_match_adjusts_offset() {
    let text = "0123456789";
    let mut seen = HashSet::new();
    let mut order = VecDeque::new();
    let mut m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("demo"),
        service: Arc::from("test"),
        severity: Severity::Low,
        credential: Arc::from("345"),
        credential_hash: "345".into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: None,
            line: Some(1),
            offset: 1,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };
    assert!(record_window_match(text, 3, &mut m, &mut seen, &mut order));
    assert_eq!(m.location.offset, 4);
}
