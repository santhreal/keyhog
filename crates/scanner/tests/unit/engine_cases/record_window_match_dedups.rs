use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::engine::record_window_match;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

fn demo_match(offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("demo"),
        service: Arc::from("test"),
        severity: Severity::Low,
        credential: Arc::from("abc"),
        credential_hash: "abc".into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: None,
            line: Some(1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    }
}

#[test]
fn record_window_match_dedups() {
    let text = "abc abc";
    let mut seen = HashSet::new();
    let mut order = VecDeque::new();
    let mut m = demo_match(0);
    assert!(record_window_match(text, 0, &mut m, &mut seen, &mut order));
    let mut m2 = demo_match(0);
    assert!(!record_window_match(text, 0, &mut m2, &mut seen, &mut order));
}
