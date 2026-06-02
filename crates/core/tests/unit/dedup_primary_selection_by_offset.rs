//! Proving test: primary_location selection by offset within a dedup group.
//! Contract: When multiple matches with the same (detector, credential, file)
//! are deduped, the match with the LOWEST offset becomes primary_location,
//! and higher-offset duplicates land in additional_locations.

use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn make_match(cred: &str, path: &str, line: usize, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("det1"),
        detector_name: Arc::from("det1"),
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
fn dedup_selects_lowest_offset_as_primary_in_credential_scope() {
    // Three matches: offsets 100, 50, 75. Lowest (50) must become primary.
    let m100 = make_match("SECRET", "file.env", 1, 100);
    let m50 = make_match("SECRET", "file.env", 1, 50);
    let m75 = make_match("SECRET", "file.env", 1, 75);

    let deduped = dedup_matches(vec![m100, m50, m75], &DedupScope::Credential);

    assert_eq!(deduped.len(), 1, "same credential → one group");
    assert_eq!(
        deduped[0].primary_location.offset, 50,
        "lowest offset must be primary"
    );
    assert_eq!(
        deduped[0].additional_locations.len(),
        2,
        "two higher offsets must be additional"
    );

    // Verify the additional offsets are 75 and 100 (in order).
    let additional_offsets: Vec<usize> = deduped[0]
        .additional_locations
        .iter()
        .map(|loc| loc.offset)
        .collect();
    assert_eq!(additional_offsets, vec![75, 100]);
}

#[test]
fn dedup_primary_offset_stable_across_input_order() {
    // Input order: [offset 100, 50, 75]. Output should have primary at 50.
    // Reverse input order: [offset 75, 50, 100]. Output should still have primary at 50.
    let m100 = make_match("SECRET", "file.env", 1, 100);
    let m50 = make_match("SECRET", "file.env", 1, 50);
    let m75 = make_match("SECRET", "file.env", 1, 75);

    let forward = dedup_matches(vec![m100.clone(), m50.clone(), m75.clone()], &DedupScope::Credential);
    let backward = dedup_matches(vec![m75, m50, m100], &DedupScope::Credential);

    assert_eq!(forward[0].primary_location.offset, 50);
    assert_eq!(backward[0].primary_location.offset, 50);
}

#[test]
fn dedup_file_scope_selects_primary_per_file() {
    // Same credential in two files at different offsets.
    // Each file should have its own primary selection.
    let m1_offset10 = make_match("SECRET", "file1.env", 1, 10);
    let m1_offset20 = make_match("SECRET", "file1.env", 1, 20);
    let m2_offset50 = make_match("SECRET", "file2.env", 1, 50);

    let deduped = dedup_matches(
        vec![m1_offset10, m1_offset20, m2_offset50],
        &DedupScope::File,
    );

    assert_eq!(deduped.len(), 2, "File scope: 2 files → 2 groups");

    // Find the groups by file.
    let group1 = deduped
        .iter()
        .find(|m| m.primary_location.file_path.as_deref() == Some("file1.env"))
        .unwrap();
    let group2 = deduped
        .iter()
        .find(|m| m.primary_location.file_path.as_deref() == Some("file2.env"))
        .unwrap();

    assert_eq!(group1.primary_location.offset, 10, "file1: primary at lower offset");
    assert_eq!(group1.additional_locations.len(), 1);
    assert_eq!(group2.primary_location.offset, 50, "file2: only one match");
}

#[test]
fn dedup_offset_selection_with_same_line_different_offsets() {
    // Multiple matches on the same line but different offsets.
    // This can happen with overlapping regex matches or synthetic-line aliases.
    // Contract: lowest offset becomes primary.
    let m_offset_90 = make_match("TOKEN", "config.yaml", 5, 90);
    let m_offset_100 = make_match("TOKEN", "config.yaml", 5, 100);

    let deduped = dedup_matches(vec![m_offset_100, m_offset_90], &DedupScope::Credential);

    assert_eq!(deduped[0].primary_location.offset, 90);
    assert_eq!(deduped[0].additional_locations[0].offset, 100);
}
