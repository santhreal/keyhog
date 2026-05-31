use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn warm_backend_cpu_paths_succeed() {
    let d = DetectorSpec {
        id: "t".into(),
        name: "T".into(),
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
    assert!(s.warm_backend(ScanBackend::CpuFallback));
    assert!(s.warm_backend(ScanBackend::SimdCpu));
}
