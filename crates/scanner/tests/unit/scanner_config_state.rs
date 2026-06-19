use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::scanner_config::{RawMatchPriority, ScanState};
use std::collections::HashMap;
use std::sync::Arc;

fn raw_match(confidence: f64, credential: &'static str, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("gate"),
        detector_name: Arc::from("Gate"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: credential.into(),
        credential_hash: [0u8; 32],
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("unit"),
            file_path: Some(Arc::from("unit.env")),
            line: Some(offset + 1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(confidence),
    }
}

#[test]
fn push_match_keeps_highest_confidence_when_capped() {
    let mut state = ScanState::default();
    state.push_match(raw_match(0.10, "low", 1), 2);
    state.push_match(raw_match(0.90, "high", 2), 2);
    state.push_match(raw_match(0.50, "mid", 3), 2);

    let kept: Vec<_> = state
        .into_matches()
        .into_iter()
        .map(|m| m.credential.to_string())
        .collect();
    assert_eq!(kept, ["high", "mid"]);
}

#[test]
fn push_match_lazy_builds_only_for_admitted_candidates() {
    let mut state = ScanState::default();
    state.push_match(raw_match(0.90, "retained", 1), 1);

    let mut rejected_built = false;
    state.push_match_lazy(
        RawMatchPriority {
            confidence: Some(0.10),
            severity: Severity::High,
            detector_id: "gate",
            credential: "rejected",
            offset: 2,
            line: Some(2),
        },
        1,
        |_| {
            rejected_built = true;
            raw_match(0.10, "rejected", 2)
        },
    );
    assert!(
        !rejected_built,
        "lazy admission must not build a RawMatch for rejected candidates"
    );

    let mut admitted_built = false;
    state.push_match_lazy(
        RawMatchPriority {
            confidence: Some(0.99),
            severity: Severity::High,
            detector_id: "gate",
            credential: "admitted",
            offset: 3,
            line: Some(3),
        },
        1,
        |_| {
            admitted_built = true;
            raw_match(0.99, "admitted", 3)
        },
    );
    assert!(
        admitted_built,
        "lazy admission must build exactly when the candidate enters the heap"
    );
    let kept: Vec<_> = state
        .into_matches()
        .into_iter()
        .map(|m| m.credential.to_string())
        .collect();
    assert_eq!(kept, ["admitted"]);
}
