use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn scan_simd_cpu_empty_chunk() {
    // The literal MUST be >= MIN_LITERAL_PREFIX_CHARS (3) so the scanner builds a
    // SIMD/Hyperscan plan and selected-peer initialization succeeds. With a
    // sub-floor literal (e.g. `x`) no prefilter is built, and explicitly
    // requesting `SimdCpu` is a fail-closed `process::exit` (Law 10: no silent
    // cpu-fallback), not a normal scan (which would abort the whole test binary).
    let d = DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "xyz_marker".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["xyz_marker".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let chunk = Chunk {
        data: "".into(),
        metadata: ChunkMetadata::default(),
    };
    assert!(s.scan_with_backend(&chunk, ScanBackend::SimdCpu).is_empty());
}
