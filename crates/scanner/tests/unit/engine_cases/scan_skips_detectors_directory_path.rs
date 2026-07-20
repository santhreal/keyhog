use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn scan_scans_detectors_directory_path() {
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
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["secret".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunk = Chunk {
        data: "secret=abc".into(),
        metadata: ChunkMetadata {
            path: Some("repo/detectors/foo.toml".into()),
            ..Default::default()
        },
    };
    let matches = s.scan(&chunk);
    assert_eq!(
        matches.len(),
        1,
        "scanner must scan caller-provided chunks even when the user path contains detectors/: {matches:?}"
    );
}
