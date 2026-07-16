use keyhog_core::{Chunk, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner_for(service: &str) -> CompiledScanner {
    CompiledScanner::compile(vec![DetectorSpec {
        id: "opaque-detector-id".into(),
        name: "Opaque detector".into(),
        service: service.into(),
        severity: Severity::High,
        min_confidence: Some(0.0),
        patterns: vec![PatternSpec {
            regex: "opaque=([a]{24})".into(),
            group: Some(1),
            ..PatternSpec::default()
        }],
        keywords: vec!["opaque".into()],
        ..DetectorSpec::default()
    }])
    .expect("compile custom detector")
}

#[test]
fn active_detector_service_controls_generic_policy_without_id_conventions() {
    let chunk = Chunk {
        data: "opaque=aaaaaaaaaaaaaaaaaaaaaaaa".into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };

    let generic = scanner_for("generic").scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert!(
        generic.is_empty(),
        "a TOML-generic detector must apply the generic plausibility gate"
    );

    let named = scanner_for("opaque-service").scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert_eq!(named.len(), 1, "service policy must not depend on the ID");
    assert_eq!(named[0].detector_id.as_ref(), "opaque-detector-id");
    assert_eq!(named[0].credential.as_ref(), "aaaaaaaaaaaaaaaaaaaaaaaa");
}
