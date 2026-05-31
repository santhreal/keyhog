use keyhog::subcommands::scan_system::{FindingSink, MAX_RESIDENT_FINDINGS};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;

fn raw_match(i: usize) -> RawMatch {
    let credential = format!("AKIA_SECRET_PLAINTEXT_{i:08}");
    RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential: Arc::from(credential.as_str()),
        credential_hash: raw_hash(i),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(format!("/tmp/leak{i}.env").as_str())),
            line: Some(i + 1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.2),
        confidence: Some(0.9),
    }
}

fn raw_hash(i: usize) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
    hash
}

#[test]
fn sink_starts_empty() {
    let sink = FindingSink::new();
    assert!(sink.is_empty());
    assert_eq!(sink.total(), 0);
    assert_eq!(sink.retained_len(), 0);
}

#[test]
fn sink_absorbs_and_counts_below_cap() {
    let mut sink = FindingSink::new();
    sink.absorb((0..10).map(raw_match).collect());
    assert_eq!(sink.total(), 10);
    assert_eq!(sink.retained_len(), 10);
    assert!(!sink.is_empty());
}

#[test]
fn sink_retains_only_redacted_never_plaintext() {
    let mut sink = FindingSink::new();
    sink.absorb(vec![raw_match(7)]);
    let json = sink.retained_json().expect("serialize retained findings");
    assert!(
        !json.contains("AKIA_SECRET_PLAINTEXT_00000007"),
        "plaintext credential leaked into retained findings: {json}"
    );
    assert_eq!(sink.retained_len(), 1);
    assert_eq!(sink.retained_hash(0), Some(raw_hash(7)));
}

#[test]
fn sink_caps_resident_set_but_keeps_counting() {
    let cap = 3;
    let mut sink = FindingSink::with_cap(cap);

    sink.absorb((0..2).map(raw_match).collect());
    sink.absorb((2..50).map(raw_match).collect());

    assert_eq!(sink.total(), 50);
    assert_eq!(sink.retained_len(), cap);
    assert!(sink.capped_warned());
    assert!(!sink.is_empty());
    assert_eq!(sink.retained_hash(0), Some(raw_hash(0)));
    assert_eq!(sink.retained_hash(cap - 1), Some(raw_hash(cap - 1)));
}

#[test]
fn default_cap_is_the_module_ceiling() {
    let sink = FindingSink::new();
    assert_eq!(sink.cap(), MAX_RESIDENT_FINDINGS);
}
