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

#[test]
fn skipped_chunks_start_at_zero_and_accumulate() {
    // Law 10: an unreadable source chunk (corrupt git object, perm-denied path)
    // is unscanned bytes. The sink counts each one so the final summary can warn
    // the audit did NOT cover everything, instead of the old silent
    // `Err(_) => continue` that made a partial scan look complete.
    let mut sink = FindingSink::new();
    assert_eq!(sink.skipped_chunks(), 0, "a fresh sink has skipped nothing");

    for _ in 0..5 {
        sink.record_skipped_chunk();
    }
    assert_eq!(
        sink.skipped_chunks(),
        5,
        "every dropped chunk must be counted so the recall loss is surfaced"
    );

    // Skips are tracked independently of findings: a scan can drop chunks AND
    // still surface findings, and both counts must be honest.
    sink.absorb(vec![raw_match(1)]);
    assert_eq!(sink.total(), 1, "findings count is unaffected by skip tracking");
    assert_eq!(sink.skipped_chunks(), 5, "skip count is unaffected by findings");
}
