//! Proving test: DedupScope::None preserves every match unchanged.
//! Contract: With DedupScope::None, identical credentials in identical files
//! remain as separate findings (no grouping, no primary/additional split).

use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn make_match(detector: &str, cred: &str, path: &str, line: usize, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: Arc::from(cred),
        credential_hash: [0; 32],
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from(path)),
            line: Some(line),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
    }
}

#[test]
fn dedup_none_scope_returns_every_match_as_separate_finding() {
    // Input: 3 identical (detector, credential, file, line, offset)
    // With None scope: output must be 3 separate DedupedMatches with no additional_locations.
    let m1 = make_match("det1", "secret", "file.env", 10, 0);
    let m2 = make_match("det1", "secret", "file.env", 10, 0);
    let m3 = make_match("det1", "secret", "file.env", 10, 0);

    let deduped = dedup_matches(vec![m1, m2, m3], &DedupScope::None);

    assert_eq!(deduped.len(), 3, "None scope must preserve all 3 matches");

    // Each must be a separate primary (no additional_locations).
    for (i, finding) in deduped.iter().enumerate() {
        assert_eq!(
            finding.additional_locations.len(),
            0,
            "match {} must have zero additional_locations (None scope never groups)",
            i
        );
        assert_eq!(
            finding.credential.as_ref(),
            "secret",
            "match {} credential must be preserved",
            i
        );
    }
}

#[test]
fn dedup_none_scope_identical_matches_remain_distinct() {
    // Input: Two matches with same detector, credential, location.
    // With None scope: output must remain 2 separate findings, not 1 with 1 additional.
    let input = vec![
        make_match("det", "FAKE_SECRET_X", "a.env", 1, 0),
        make_match("det", "FAKE_SECRET_X", "a.env", 1, 0),
    ];

    let deduped = dedup_matches(input, &DedupScope::None);

    assert_eq!(deduped.len(), 2, "None scope: 2 input = 2 output, not 1 grouped");
    assert_eq!(deduped[0].additional_locations.len(), 0);
    assert_eq!(deduped[1].additional_locations.len(), 0);
}

#[test]
fn dedup_none_scope_count_equals_input_count() {
    // Property: None scope must always return a DedupedMatch for each RawMatch.
    let input = vec![
        make_match("d1", "c1", "f1.txt", 1, 0),
        make_match("d1", "c1", "f2.txt", 1, 0),
        make_match("d1", "c2", "f1.txt", 1, 0),
        make_match("d2", "c1", "f1.txt", 1, 0),
    ];

    let deduped = dedup_matches(input.clone(), &DedupScope::None);

    assert_eq!(
        deduped.len(),
        input.len(),
        "None scope must preserve input count exactly"
    );
}

#[test]
fn dedup_none_scope_respects_offset_sorting() {
    // None scope doesn't group, but it still sorts by offset for primary_location selection.
    // Input unsorted by offset; output must show the lowest offset was selected as primary.
    let m_high = make_match("det", "secret", "file.env", 1, 100);
    let m_low = make_match("det", "secret", "file.env", 1, 10);

    let forward = dedup_matches(vec![m_high.clone(), m_low.clone()], &DedupScope::None);
    let reverse = dedup_matches(vec![m_low.clone(), m_high.clone()], &DedupScope::None);

    // Both orderings should produce 2 separate findings in deterministic order.
    assert_eq!(forward.len(), 2);
    assert_eq!(reverse.len(), 2);

    // Primary locations should be sorted deterministically.
    assert_eq!(forward[0].primary_location.offset, 10);
    assert_eq!(reverse[0].primary_location.offset, 10);
}
