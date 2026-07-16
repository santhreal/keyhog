use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn scan_cpu_fallback_finds_match() {
    let d = DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "tok".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["tok".into()],
        min_confidence: None,
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunk = Chunk {
        data: "tok=abc".into(),
        metadata: ChunkMetadata::default(),
    };
    let m = s.scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert_eq!(m.len(), 1);
}
