use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
fn default_scan_matches_explicit_portable_cpu_reference() {
    let detector = DetectorSpec {
        id: "reference-route-token".into(),
        name: "Reference route token".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"REF_[A-Z0-9]{16}".into(),
            description: Some("reference route fixture".into()),
            group: None,
            client_safe: false,
        }],
        keywords: vec!["REF_".into()],
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile fixture detector");
    let chunk = Chunk {
        data: "token = REF_1A2B3C4D5E6F7G8H".into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("reference.env".into()),
            ..Default::default()
        },
    };

    assert_eq!(
        scanner.scan(&chunk),
        scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback),
    );
}
