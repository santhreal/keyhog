use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
fn gpu_stack_usable_false_without_literals() {
    let d = DetectorSpec {
        tests: Vec::new(),
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
    let message = crate::engine::gpu_forced_unavailable_message(&s, ScanBackend::Gpu)
        .expect("GPU without literals must produce an explicit forced-backend error");
    assert!(
        message.contains("gpu-region-presence selected but GPU stack unavailable"),
        "forced GPU message must name the selected backend and stack state, got {message:?}"
    );
    assert!(
        message.contains("silent CPU fallback is forbidden")
            && message.contains("choose --backend simd/auto"),
        "forced GPU message must name the operator controls, got {message:?}"
    );
}
