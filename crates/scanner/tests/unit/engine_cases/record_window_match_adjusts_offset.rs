use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::testing::compute_line_offsets;
use keyhog_scanner::testing::record_window_match;
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
        credential: keyhog_core::SensitiveString::from("345"),
        credential_hash: [3u8; 32],
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
    let line_offsets = compute_line_offsets(text);
    assert!(record_window_match(
        &line_offsets,
        0,
        3,
        text.len(),
        &mut m,
        &mut seen,
        &mut order
    ));
    assert_eq!(m.location.offset, 4);
}

#[test]
fn record_window_match_rejects_synthesized_offsets_outside_window() {
    let text = "0123456789";
    let mut seen = HashSet::new();
    let mut order = VecDeque::new();
    let mut m = RawMatch {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("demo"),
        service: Arc::from("test"),
        severity: Severity::Low,
        credential: keyhog_core::SensitiveString::from("synthetic"),
        credential_hash: [4u8; 32],
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("test"),
            file_path: None,
            line: Some(1),
            offset: text.len(),
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    };
    let line_offsets = compute_line_offsets(text);
    assert!(!record_window_match(
        &line_offsets,
        0,
        3,
        text.len(),
        &mut m,
        &mut seen,
        &mut order
    ));
    assert!(seen.is_empty());
}
