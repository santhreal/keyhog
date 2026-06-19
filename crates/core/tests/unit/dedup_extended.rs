/// Extended dedup tests: cross-detector dedup, confidence max selection,
/// companion merge stability, empty input, same-location collapse,
/// file-scope commit separation, and large batch determinism.
use keyhog_core::{
    dedup_cross_detector, dedup_matches, DedupScope, MatchLocation, RawMatch, Severity,
};
use std::collections::HashMap;
use std::sync::Arc;

fn loc(file: &str, line: usize, offset: usize) -> MatchLocation {
    MatchLocation {
        source: Arc::from("fs"),
        file_path: Some(Arc::from(file)),
        line: Some(line),
        offset,
        commit: None,
        author: None,
        date: None,
    }
}

fn make(detector: &str, cred: &str, file: &str, line: usize, conf: Option<f64>) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from("svc"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(cred),
        credential_hash: [0; 32],
        companions: HashMap::new(),
        location: loc(file, line, 0),
        entropy: None,
        confidence: conf,
    }
}

// ── dedup_matches: empty ──────────────────────────────────────────────────────

#[test]
fn dedup_empty_input_any_scope_returns_empty() {
    assert!(dedup_matches(vec![], &DedupScope::Credential).is_empty());
    assert!(dedup_matches(vec![], &DedupScope::File).is_empty());
    assert!(dedup_matches(vec![], &DedupScope::None).is_empty());
}

// ── dedup_matches: confidence max selection ───────────────────────────────────

#[test]
fn dedup_credential_scope_keeps_max_confidence() {
    let mut m1 = make("det", "FAKE_SECRET_VALUE_ALPHA", "f.env", 1, Some(0.6));
    let mut m2 = make("det", "FAKE_SECRET_VALUE_ALPHA", "f2.env", 1, Some(0.9));
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert_eq!(
        deduped[0].confidence,
        Some(0.9),
        "max confidence should be kept"
    );
}

#[test]
fn dedup_both_none_confidence_stays_none() {
    let m1 = make("det", "FAKE_SECRET_VALUE_BETA", "f.env", 1, None);
    let m2 = make("det", "FAKE_SECRET_VALUE_BETA", "f2.env", 1, None);
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].confidence, None);
}

#[test]
fn dedup_one_none_one_some_takes_some() {
    let m1 = make("det", "FAKE_SECRET_VALUE_GAMMA", "f.env", 1, None);
    let m2 = make("det", "FAKE_SECRET_VALUE_GAMMA", "f2.env", 1, Some(0.75));
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    assert_eq!(deduped[0].confidence, Some(0.75));
}

// ── dedup_matches: same (file, line) collapse ─────────────────────────────────

#[test]
fn same_file_line_two_matches_produce_one_primary_no_additional() {
    // Two matches at exactly the same (file, line) — must collapse to 1 finding
    // with no additional_locations (the second is the same location).
    let m1 = make("det", "FAKE_CRED_DELTA_0000000000", "env.txt", 2, Some(0.8));
    let m2 = make("det", "FAKE_CRED_DELTA_0000000000", "env.txt", 2, Some(0.8));
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert_eq!(
        deduped[0].additional_locations.len(),
        0,
        "same (file, line) must not produce additional_locations"
    );
}

// ── dedup_matches: multi-file credential scope ────────────────────────────────

#[test]
fn credential_scope_accumulates_additional_locations() {
    let files = ["a.env", "b.env", "c.env"];
    let matches: Vec<RawMatch> = files
        .iter()
        .map(|f| make("det", "FAKE_CRED_EPSILON_0000000000", f, 1, Some(0.9)))
        .collect();
    let deduped = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert_eq!(
        deduped[0].additional_locations.len(),
        2,
        "3 files → 1 primary + 2 additional"
    );
}

// ── dedup_matches: output is deterministic ─────────────────────────────────────

#[test]
fn dedup_credential_scope_output_is_deterministic() {
    let m1 = make("alpha", "FAKE_CRED_ZETA_0000000000", "x.env", 1, Some(0.5));
    let m2 = make("beta", "FAKE_CRED_ETA_00000000000", "y.env", 1, Some(0.5));
    let order1 = dedup_matches(vec![m1.clone(), m2.clone()], &DedupScope::Credential);
    let order2 = dedup_matches(vec![m2, m1], &DedupScope::Credential);
    let ids1: Vec<&str> = order1.iter().map(|m| m.detector_id.as_ref()).collect();
    let ids2: Vec<&str> = order2.iter().map(|m| m.detector_id.as_ref()).collect();
    assert_eq!(
        ids1, ids2,
        "dedup output must be deterministic regardless of input order"
    );
}

// ── dedup_cross_detector ──────────────────────────────────────────────────────

#[test]
fn cross_detector_dedup_single_item_passes_through() {
    let m = make("det", "FAKE_CRED_THETA_000000000", "f.env", 1, Some(0.9));
    let deduped_first = dedup_matches(vec![m], &DedupScope::Credential);
    let cross = dedup_cross_detector(deduped_first);
    assert_eq!(cross.len(), 1);
}

#[test]
fn cross_detector_dedup_empty_passes_through() {
    let cross = dedup_cross_detector(vec![]);
    assert!(cross.is_empty());
}

#[test]
fn cross_detector_collapses_same_cred_two_detectors() {
    // Two matches with the SAME credential hash but different detectors → should collapse to 1.
    let m1 = make(
        "detector-a",
        "FAKE_CRED_IOTA_000000000",
        "f.env",
        1,
        Some(0.9),
    );
    let m2 = make(
        "detector-b",
        "FAKE_CRED_IOTA_000000000",
        "f.env",
        1,
        Some(0.7),
    );
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let cross = dedup_cross_detector(deduped);
    assert_eq!(
        cross.len(),
        1,
        "same credential + same file → 1 entry after cross-detector dedup"
    );
    // Winner should be detector-a (higher confidence)
    assert_eq!(cross[0].detector_id.as_ref(), "detector-a");
    // Loser's metadata should appear in companions under cross_detector.0
    assert!(
        cross[0].companions.contains_key("cross_detector.0"),
        "loser should appear in cross_detector.0 companion"
    );
}

#[test]
fn cross_detector_dedup_distinct_creds_stays_separate() {
    let m1 = make("det-a", "FAKE_CRED_KAPPA_0000000000", "f.env", 1, Some(0.9));
    let m2 = make("det-b", "FAKE_CRED_LAMBDA_000000000", "f.env", 1, Some(0.7));
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let cross = dedup_cross_detector(deduped);
    assert_eq!(
        cross.len(),
        2,
        "distinct credentials must not be merged by cross-detector dedup"
    );
}

#[test]
fn cross_detector_picks_highest_severity_as_tiebreak() {
    // Same credential, same confidence → severity decides winner
    let mut m1 = make("det-a", "FAKE_CRED_MU_00000000000", "f.env", 1, Some(0.8));
    m1.severity = Severity::Critical;
    let mut m2 = make("det-b", "FAKE_CRED_MU_00000000000", "f.env", 1, Some(0.8));
    m2.severity = Severity::Low;
    let deduped = dedup_matches(vec![m1, m2], &DedupScope::Credential);
    let cross = dedup_cross_detector(deduped);
    assert_eq!(cross.len(), 1);
    assert_eq!(
        cross[0].detector_id.as_ref(),
        "det-a",
        "Critical severity should win tiebreak"
    );
}

#[test]
fn cross_detector_output_is_deterministic() {
    let m1 = make("det-a", "FAKE_CRED_NU_000000000000", "f.env", 1, Some(0.9));
    let m2 = make("det-b", "FAKE_CRED_XI_000000000000", "f.env", 1, Some(0.7));
    let deduped_a = dedup_matches(vec![m1.clone(), m2.clone()], &DedupScope::Credential);
    let deduped_b = dedup_matches(vec![m2, m1], &DedupScope::Credential);
    let cross_a = dedup_cross_detector(deduped_a);
    let cross_b = dedup_cross_detector(deduped_b);
    let ids_a: Vec<&str> = cross_a.iter().map(|m| m.detector_id.as_ref()).collect();
    let ids_b: Vec<&str> = cross_b.iter().map(|m| m.detector_id.as_ref()).collect();
    assert_eq!(ids_a, ids_b);
}
