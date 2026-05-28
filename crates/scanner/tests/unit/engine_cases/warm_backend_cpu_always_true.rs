use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
#[test]
fn warm_backend_cpu_always_true() {
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
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    assert!(s.warm_backend(ScanBackend::CpuFallback));
    assert!(s.warm_backend(ScanBackend::SimdCpu));
}
