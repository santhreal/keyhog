use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;

fn raw_match(i: usize) -> RawMatch {
    let credential = format!("AKIA_SECRET_PLAINTEXT_{i:08}");
    RawMatch {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Access Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from(credential.as_str()),
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
    let sink = API.finding_sink_new();
    assert!(API.finding_sink_is_empty(&sink));
    assert_eq!(API.finding_sink_total(&sink), 0);
    assert_eq!(API.finding_sink_retained_len(&sink), 0);
}

#[test]
fn sink_absorbs_and_counts_below_cap() {
    let mut sink = API.finding_sink_new();
    API.finding_sink_absorb(&mut sink, (0..10).map(raw_match).collect());
    assert_eq!(API.finding_sink_total(&sink), 10);
    assert_eq!(API.finding_sink_retained_len(&sink), 10);
    assert!(!API.finding_sink_is_empty(&sink));
}

#[test]
fn sink_retains_only_redacted_never_plaintext() {
    let mut sink = API.finding_sink_new();
    API.finding_sink_absorb(&mut sink, vec![raw_match(7)]);
    let json = API
        .finding_sink_retained_json(&sink)
        .expect("serialize retained findings");
    assert!(
        !json.contains("AKIA_SECRET_PLAINTEXT_00000007"),
        "plaintext credential leaked into retained findings: {json}"
    );
    assert_eq!(API.finding_sink_retained_len(&sink), 1);
    assert_eq!(API.finding_sink_retained_hash(&sink, 0), Some(raw_hash(7)));
}

#[test]
fn sink_caps_resident_set_but_keeps_counting() {
    let cap = 3;
    let mut sink = API.finding_sink_with_cap(cap);

    API.finding_sink_absorb(&mut sink, (0..2).map(raw_match).collect());
    API.finding_sink_absorb(&mut sink, (2..50).map(raw_match).collect());

    assert_eq!(API.finding_sink_total(&sink), 50);
    assert_eq!(API.finding_sink_retained_len(&sink), cap);
    assert!(API.finding_sink_capped_warned(&sink));
    assert!(!API.finding_sink_is_empty(&sink));
    assert_eq!(API.finding_sink_retained_hash(&sink, 0), Some(raw_hash(0)));
    assert_eq!(
        API.finding_sink_retained_hash(&sink, cap - 1),
        Some(raw_hash(cap - 1))
    );
}

#[test]
fn default_cap_is_the_module_ceiling() {
    let sink = API.finding_sink_new();
    assert_eq!(API.finding_sink_cap(&sink), API.max_resident_findings());
}

#[test]
fn skipped_chunks_start_at_zero_and_accumulate() {
    // Law 10: an unreadable source chunk (corrupt git object, perm-denied path)
    // is unscanned bytes. The sink counts each one so the final summary can warn
    // the audit did NOT cover everything, instead of the old silent
    // `Err(_) => continue` that made a partial scan look complete.
    let mut sink = API.finding_sink_new();
    assert_eq!(
        API.finding_sink_skipped_chunks(&sink),
        0,
        "a fresh sink has skipped nothing"
    );

    for _ in 0..5 {
        API.finding_sink_record_skipped_chunk(&mut sink);
    }
    assert_eq!(
        API.finding_sink_skipped_chunks(&sink),
        5,
        "every dropped chunk must be counted so the recall loss is surfaced"
    );

    // Skips are tracked independently of findings: a scan can drop chunks AND
    // still surface findings, and both counts must be honest.
    API.finding_sink_absorb(&mut sink, vec![raw_match(1)]);
    assert_eq!(
        API.finding_sink_total(&sink),
        1,
        "findings count is unaffected by skip tracking"
    );
    assert_eq!(
        API.finding_sink_skipped_chunks(&sink),
        5,
        "skip count is unaffected by findings"
    );
}

#[test]
fn git_repo_discovery_does_not_flatten_read_dir_errors() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    ))
    .expect("scan-system source readable");
    assert!(
        !src.contains("entries.flatten()"),
        "scan-system repo discovery must match read_dir entry errors explicitly so skipped subtrees are logged"
    );
    assert!(
        src.contains("cannot read directory entry while discovering git repositories")
            && src.contains("cannot read directory while discovering git repositories"),
        "scan-system repo discovery must warn for per-entry and whole-directory read failures"
    );
}
