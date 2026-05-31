use keyhog_core::{dedup_matches, DedupScope, MatchLocation, RawMatch, Severity};
use std::collections::HashMap;

fn sample_match(id: &str, cred: &str, path: &str) -> RawMatch {
    RawMatch {
        detector_id: id.into(),
        detector_name: id.into(),
        service: "test".into(),
        severity: Severity::High,
        credential: cred.into(),
        credential_hash: [0; 32],
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
fn dedup_same_offset_uses_total_location_tiebreak() {
    let mut low_line = sample_match("det1", "secret1", "file1.txt");
    low_line.location.offset = 4096;
    low_line.location.line = Some(17);

    let mut high_line = low_line.clone();
    high_line.location.line = Some(42);

    let forward = dedup_matches(
        vec![high_line.clone(), low_line.clone()],
        &DedupScope::Credential,
    );
    let reverse = dedup_matches(vec![low_line, high_line], &DedupScope::Credential);

    for deduped in [forward, reverse] {
        assert_eq!(deduped.len(), 1);
        assert_eq!(
            deduped[0].primary_location.line,
            Some(17),
            "same-offset overlapping-window aliases need a deterministic primary"
        );
        assert_eq!(deduped[0].additional_locations.len(), 1);
        assert_eq!(deduped[0].additional_locations[0].line, Some(42));
    }
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

#[test]
fn dedup_prefers_original_location_over_nearby_decoder_alias() {
    let mut original = sample_match(
        "devcycle-api-credentials",
        "DVC_CTRL_REG3_SW_PROG",
        "drivers/i2c/busses/i2c-tegra.c",
    );
    original.location.source = "filesystem".into();
    original.location.line = Some(612);
    original.location.offset = 19000;

    let mut decoded = original.clone();
    decoded.location.source = "filesystem/json".into();
    decoded.location.line = Some(613);
    decoded.location.offset = 18999;

    let deduped = dedup_matches(vec![decoded, original], &DedupScope::Credential);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].primary_location.source.as_ref(), "filesystem");
    assert_eq!(deduped[0].primary_location.line, Some(612));
    assert_eq!(deduped[0].primary_location.offset, 19000);
    assert!(
        deduped[0].additional_locations.is_empty(),
        "nearby decoded aliases should not report as extra locations"
    );
}
