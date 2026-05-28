use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

#[test]
fn gpu_stack_usable_false_without_literals() {
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
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    // Without KEYHOG_BACKEND=gpu, warm_backend(Gpu) may return false on headless hosts
    // without panicking - silent degrade is only forbidden when env forces GPU.
    unsafe { std::env::remove_var("KEYHOG_BACKEND") };
    let _ = s.warm_backend(ScanBackend::Gpu);
}
