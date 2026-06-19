use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::scan_coalesced_phase2_with_admission_for_test;
use keyhog_scanner::CompiledScanner;

fn detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "coalesced-row-token".into(),
        name: "Coalesced Row Token".into(),
        service: "coalesced-row".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "tok_[A-Za-z0-9]{3}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["tok_".into()],
        min_confidence: None,
        ..Default::default()
    }
}

fn chunk(data: &str, path: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "unit".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

#[test]
fn phase2_short_trigger_rows_preserve_chunk_count_and_scan_missing_rows() {
    let scanner = CompiledScanner::compile(vec![detector()]).expect("scanner compile");
    let chunks = vec![
        chunk("no credential here", "first.txt"),
        chunk("value = tok_ABC", "second.txt"),
    ];

    let results =
        scan_coalesced_phase2_with_admission_for_test(&scanner, &chunks, vec![None], None);

    assert_eq!(
        results.len(),
        2,
        "phase-2 must return one result row per chunk"
    );
    assert!(
        results[0].is_empty(),
        "first chunk has no credential and must remain empty"
    );
    assert_eq!(results[1].len(), 1, "second chunk must still be scanned");
    let found = &results[1][0];
    assert_eq!(found.detector_id.as_ref(), "coalesced-row-token");
    assert_eq!(found.credential.as_ref(), "tok_ABC");
    assert_eq!(found.location.file_path.as_deref(), Some("second.txt"));
}
