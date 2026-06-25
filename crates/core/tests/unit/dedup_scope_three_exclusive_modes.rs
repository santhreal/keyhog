//! Proving test: DedupScope enum provides three mutually exclusive deduplication modes.
//! Contract: For the same input, DedupScope::None, DedupScope::File, and
//! DedupScope::Credential must produce different (and correct) survivor counts.

use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;
use std::sync::Arc;

fn make_match(detector: &str, cred: &str, path: &str, line: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(cred),
        credential_hash: [0; 32].into(),
        companions: HashMap::new(),
        location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from(path)),
            line: Some(line),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: Some(0.9),
    }
}

#[test]
fn dedup_scope_none_no_grouping_three_identical_returns_three() {
    // Input: 3 identical matches (same detector, cred, file).
    // DedupScope::None: returns 3 (no grouping).
    let input = vec![
        make_match("det", "secret", "file.txt", 1),
        make_match("det", "secret", "file.txt", 1),
        make_match("det", "secret", "file.txt", 1),
    ];

    let result = dedup_matches(input, &DedupScope::None);
    assert_eq!(result.len(), 3, "None scope: 3 input → 3 output");
}

#[test]
fn dedup_scope_file_groups_by_file_three_identical_returns_one() {
    // Input: 3 identical matches in the same file.
    // DedupScope::File: groups by (detector, cred, file) → 1 group.
    let input = vec![
        make_match("det", "secret", "file.txt", 1),
        make_match("det", "secret", "file.txt", 2),
        make_match("det", "secret", "file.txt", 3),
    ];

    let result = dedup_matches(input, &DedupScope::File);
    assert_eq!(result.len(), 1, "File scope: same file → 1 group");
    assert_eq!(result[0].additional_locations.len(), 2);
}

#[test]
fn dedup_scope_credential_groups_across_files_three_identical_returns_one() {
    // Input: 3 identical (detector, credential) but in different files.
    // DedupScope::Credential: groups by (detector, cred) → 1 group.
    let input = vec![
        make_match("det", "secret", "file1.txt", 1),
        make_match("det", "secret", "file2.txt", 1),
        make_match("det", "secret", "file3.txt", 1),
    ];

    let result = dedup_matches(input, &DedupScope::Credential);
    assert_eq!(result.len(), 1, "Credential scope: same cred → 1 group");
    assert_eq!(result[0].additional_locations.len(), 2);
}

#[test]
fn dedup_scope_three_modes_produce_different_counts() {
    // Input: same cred in 2 files, 3 times in file1, 2 times in file2.
    // None: 5 separate findings
    // File: 2 findings (one per file)
    // Credential: 1 finding (all same cred)
    let input = vec![
        make_match("det", "secret", "file1.txt", 1),
        make_match("det", "secret", "file1.txt", 2),
        make_match("det", "secret", "file1.txt", 3),
        make_match("det", "secret", "file2.txt", 1),
        make_match("det", "secret", "file2.txt", 2),
    ];

    let none_result = dedup_matches(input.clone(), &DedupScope::None);
    let file_result = dedup_matches(input.clone(), &DedupScope::File);
    let cred_result = dedup_matches(input, &DedupScope::Credential);

    assert_eq!(none_result.len(), 5, "None: every match is separate");
    assert_eq!(file_result.len(), 2, "File: one per file");
    assert_eq!(cred_result.len(), 1, "Credential: one for all");

    // Verify the ordering: None > File > Credential
    assert!(none_result.len() > file_result.len());
    assert!(file_result.len() > cred_result.len());
}

#[test]
fn dedup_scope_distinct_credentials_same_file_behavior() {
    // Input: 2 different credentials in the same file.
    // All three scopes should return 2 findings (credentials are distinct).
    let input = vec![
        make_match("det", "secret1", "file.txt", 1),
        make_match("det", "secret2", "file.txt", 2),
    ];

    let none_result = dedup_matches(input.clone(), &DedupScope::None);
    let file_result = dedup_matches(input.clone(), &DedupScope::File);
    let cred_result = dedup_matches(input, &DedupScope::Credential);

    assert_eq!(none_result.len(), 2);
    assert_eq!(file_result.len(), 2);
    assert_eq!(cred_result.len(), 2);
}
