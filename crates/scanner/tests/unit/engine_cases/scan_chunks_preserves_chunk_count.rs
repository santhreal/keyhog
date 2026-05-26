use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn scan_chunks_preserves_chunk_count() {
    let d = DetectorSpec {
        id: "a".into(), name: "A".into(), service: "s".into(), severity: Severity::Low,
        patterns: vec![PatternSpec { regex: "x".into(), description: None, group: None }],
        companions: vec![], verify: None, keywords: vec!["x".into()], ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunks = vec![
        Chunk { data: "clean".into(), metadata: ChunkMetadata::default() },
        Chunk { data: "also clean".into(), metadata: ChunkMetadata::default() },
    ];
    let out = s.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    assert_eq!(out.len(), 2);
}
