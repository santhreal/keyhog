use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn partial_alternation_detector() -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "partial-alt".into(),
        name: "Partial Alternation".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "(AKIA|[A-Z0-9]{4})TESTSECRET".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        min_confidence: None,
        ..Default::default()
    }
}

#[test]
fn partial_alternation_unprefixed_branch_still_scans() {
    let scanner = CompiledScanner::compile(vec![partial_alternation_detector()])
        .expect("compile detector with partial alternation");
    let chunk = Chunk {
        data: "prefix 1234TESTSECRET suffix".into(),
        metadata: ChunkMetadata {
            path: Some("partial-alt.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    assert!(
        matches
            .iter()
            .any(|m| m.credential.as_ref() == "1234TESTSECRET"),
        "unprefixed alternation branch must not be silently dead; matches={matches:?}"
    );
}
