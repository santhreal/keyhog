use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn demo_scanner() -> CompiledScanner {
    CompiledScanner::compile(vec![DetectorSpec {
        tests: Vec::new(),
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
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
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }])
    .unwrap()
}

fn chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

#[test]
fn backend_does_not_report_matches_across_chunk_boundaries() {
    let scanner = demo_scanner();
    let chunks = vec![chunk("ab"), chunk("c")];

    let matches = scanner.scan_chunks_with_backend(
        &chunks,
        keyhog_scanner::hw_probe::testing::ScanBackend::CpuFallback,
    );

    assert!(matches.iter().all(Vec::is_empty));
}

#[test]
fn backend_reports_matches_inside_a_single_chunk() {
    let scanner = demo_scanner();

    let matches = scanner.scan_with_backend(
        &chunk("abc"),
        keyhog_scanner::hw_probe::testing::ScanBackend::CpuFallback,
    );

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].credential.as_ref(), "abc");
}
