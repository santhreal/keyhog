use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn scan_scans_keyhogignore_path_when_source_hands_it_over() {
    let d = DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "secret".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunk = Chunk {
        data: "secret=abc".into(),
        metadata: ChunkMetadata {
            path: Some(".keyhogignore".into()),
            ..Default::default()
        },
    };
    let matches = s.scan(&chunk);
    assert_eq!(
        matches.len(),
        1,
        "scanner must not own source exclusion policy; chunks handed to it are scanned: {matches:?}"
    );
}
