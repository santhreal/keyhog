use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn scan_simd_cpu_empty_chunk() {
    let d = DetectorSpec {
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "x".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["x".into()],
        min_confidence: None,
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunk = Chunk {
        data: "".into(),
        metadata: ChunkMetadata::default(),
    };
    assert!(s.scan_with_backend(&chunk, ScanBackend::SimdCpu).is_empty());
}
