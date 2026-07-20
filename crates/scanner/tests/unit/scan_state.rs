use keyhog_core::{MatchLocation, RawMatch, Severity};
use keyhog_scanner::scan_state::{RawMatchPriority, ScanState};
#[cfg(feature = "ml")]
use keyhog_scanner::testing::ml_context_for_candidate;
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "ml")]
fn confidence_policy() -> keyhog_core::DetectorMatchConfidenceSpec {
    keyhog_core::detector_spec_by_id("datadog-api-key")
        .and_then(|detector| detector.match_confidence)
        .expect("embedded Datadog confidence policy")
}
#[cfg(feature = "ml")]
fn push_pattern_pending(
    state: &mut ScanState,
    raw: RawMatch,
    confidence: f64,
    features: [f32; keyhog_scanner::ml_scorer::NUM_FEATURES],
) -> bool {
    let policy = confidence_policy();
    state.push_detector_ml_pending(
        raw,
        confidence,
        keyhog_scanner::context::CodeContext::Assignment,
        policy.assignment_context_multiplier,
        Some(policy.soft_context_suppression_threshold),
        policy.post_match,
        features,
        0.35,
        0.2,
        true,
        false,
        false,
        false,
        keyhog_scanner::checksum::ChecksumConfidenceDecision::not_applicable(),
        keyhog_scanner::detector_ml_policy::ActiveMlMode::Blend,
    )
}

fn raw_match(confidence: f64, credential: &'static str, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("gate"),
        detector_name: Arc::from("Gate"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: credential.into(),
        credential_hash: [0u8; 32].into(),
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
        .map(|m| m.credential.as_str().to_string())
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
        .map(|m| m.credential.as_str().to_string())
        .collect();
    assert_eq!(kept, ["admitted"]);
}

#[test]
fn push_match_lazy_zero_limit_never_builds_or_retains() {
    let mut state = ScanState::default();
    let mut built = false;

    state.push_match_lazy(
        RawMatchPriority {
            confidence: Some(1.0),
            severity: Severity::Critical,
            detector_id: "gate",
            credential: "must-not-build",
            offset: 0,
            line: Some(1),
        },
        0,
        |_| {
            built = true;
            raw_match(1.0, "must-not-build", 0)
        },
    );

    assert!(
        !built,
        "a zero-capacity heap must reject before construction"
    );
    assert_eq!(state.into_matches(), Vec::<RawMatch>::new());
}

#[test]
#[cfg(feature = "ml")]
fn ml_context_for_candidate_has_one_path_prefix_owner() {
    let text = "zero\none\ntwo\nthree\nfour";

    assert_eq!(
        ml_context_for_candidate(text, 3, Some("src/lib.rs"), 5),
        "file:src/lib.rs\nzero\none\ntwo\nthree\nfour"
    );
    assert_eq!(
        ml_context_for_candidate(text, 3, None, 5),
        "zero\none\ntwo\nthree\nfour"
    );
}

#[test]
#[cfg(feature = "ml")]
fn pending_ml_queue_deduplicates_only_execution_equivalent_candidates() {
    let mut state = ScanState::default();
    let features = [0.25; keyhog_scanner::ml_scorer::NUM_FEATURES];

    assert!(push_pattern_pending(
        &mut state,
        raw_match(0.5, "candidate", 7),
        0.5,
        features,
    ));
    assert!(!push_pattern_pending(
        &mut state,
        raw_match(0.5, "candidate", 7),
        0.5,
        features,
    ));
    assert_eq!(state.ml_pending.len(), 1);

    assert!(push_pattern_pending(
        &mut state,
        raw_match(0.9, "candidate", 7),
        0.9,
        features,
    ));
    assert_eq!(state.ml_pending.len(), 1);
    assert_eq!(state.ml_pending[0].raw_match.confidence, Some(0.9));

    let mut distinct_features = features;
    distinct_features[0] = 0.75;
    assert!(push_pattern_pending(
        &mut state,
        raw_match(0.9, "candidate", 7),
        0.9,
        distinct_features,
    ));
    assert_eq!(state.ml_pending.len(), 2);
}

#[test]
#[cfg(all(feature = "ml", feature = "entropy"))]
fn pending_ml_queue_keeps_pattern_and_entropy_evidence_separate() {
    let mut state = ScanState::default();
    let features = [0.5; keyhog_scanner::ml_scorer::NUM_FEATURES];
    let raw = raw_match(0.7, "candidate", 11);

    assert!(push_pattern_pending(&mut state, raw.clone(), 0.7, features));
    let policy = confidence_policy();
    assert!(state.push_entropy_ml_pending(
        raw,
        0.7,
        policy.unknown_context_multiplier,
        Some(policy.soft_context_suppression_threshold),
        policy.post_match,
        features,
        0.35,
        0.2,
        false,
        keyhog_scanner::checksum::ChecksumConfidenceDecision::not_applicable(),
        keyhog_scanner::detector_ml_policy::ActiveMlMode::Blend,
    ));
    assert_eq!(state.ml_pending.len(), 2);
}
