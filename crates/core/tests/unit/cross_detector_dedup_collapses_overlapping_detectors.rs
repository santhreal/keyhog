use keyhog_core::{dedup_cross_detector, DedupedMatch, MatchLocation, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn make_deduped(detector: &str, service: &str, conf: f64) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("AIza_FAKE_KEY_NOT_REAL_VALUE_1234567890"),
        credential_hash: [0; 32].into(),
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

fn loc(line: usize, offset: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from("test"),
        file_path: Some(Arc::from("config.js")),
        line: Some(line),
        offset,
        commit: None,
        author: None,
        date: None,
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

#[test]
fn cross_detector_dedup_preserves_loser_locations() {
    let winner = make_deduped("google-api-key", "google-api", 0.95);
    let mut loser = make_deduped("google-maps-api-key", "google-maps", 0.75);
    loser.primary_location = loc(2, 40);
    loser.additional_locations = vec![loc(1, 0), loc(3, 80)];

    let out = dedup_cross_detector(vec![winner, loser]);

    assert_eq!(out.len(), 1);
    let lines: Vec<Option<usize>> = out[0]
        .additional_locations
        .iter()
        .map(|loc| loc.line)
        .collect();
    assert_eq!(
        lines,
        vec![Some(2), Some(3)],
        "loser primary and additional locations must survive, but duplicate winner primary must not"
    );
}
