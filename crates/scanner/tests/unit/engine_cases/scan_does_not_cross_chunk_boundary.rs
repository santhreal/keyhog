use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn scan_does_not_cross_chunk_boundary() {
    let d = DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunks = vec![
        Chunk {
            data: "ab".into(),
            metadata: ChunkMetadata::default(),
        },
        Chunk {
            data: "c".into(),
            metadata: ChunkMetadata::default(),
        },
    ];
    let out = s.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    assert!(out.iter().all(|v| v.is_empty()));
}
