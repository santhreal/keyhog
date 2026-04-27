use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

fn sample_match(id: &str, cred: &str, path: &str) -> RawMatch {
    RawMatch {
        detector_id: id.into(),
        detector_name: id.into(),
        service: "test".into(),
        severity: Severity::High,
        credential: cred.into(),
        credential_hash: format!("hash-{}", cred),
        companions: HashMap::new(),
        location: MatchLocation {
            source: "fs".into(),
            file_path: Some(path.into()),
            line: Some(1),
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
fn dedup_credential_scope() {
    let matches = vec![
        sample_match("det1", "secret1", "file1.txt"),
        sample_match("det1", "secret1", "file2.txt"),
        sample_match("det1", "secret2", "file1.txt"),
    ];

    let deduped = dedup_matches(matches, &DedupScope::Credential);
    assert_eq!(deduped.len(), 2);

    let secret1_group = deduped
        .iter()
        .find(|m| m.credential.as_ref() == "secret1")
        .unwrap();
    assert_eq!(secret1_group.additional_locations.len(), 1);
}

#[test]
fn dedup_file_scope() {
    let matches = vec![
        sample_match("det1", "secret1", "file1.txt"),
        sample_match("det1", "secret1", "file1.txt"),
        sample_match("det1", "secret1", "file2.txt"),
    ];

    let deduped = dedup_matches(matches, &DedupScope::File);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_file_scope_keeps_commits_separate() {
    let mut first = sample_match("det1", "secret1", "file1.txt");
    first.location.commit = Some("abc123".into());
    let mut second = sample_match("det1", "secret1", "file1.txt");
    second.location.commit = Some("def456".into());

    let deduped = dedup_matches(vec![first, second], &DedupScope::File);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_merges_distinct_companion_values() {
    let mut first = sample_match("det1", "secret1", "file1.txt");
    first.companions.insert("client_id".into(), "one".into());
    let mut second = sample_match("det1", "secret1", "file2.txt");
    second.companions.insert("client_id".into(), "two".into());

    let deduped = dedup_matches(vec![first, second], &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert_eq!(
        deduped[0].companions.get("client_id").map(String::as_str),
        Some("one | two")
    );
}

#[test]
fn dedup_none_scope() {
    let matches = vec![
        sample_match("det1", "secret1", "file1.txt"),
        sample_match("det1", "secret1", "file1.txt"),
    ];

    let deduped = dedup_matches(matches, &DedupScope::None);
    assert_eq!(deduped.len(), 2);
}
