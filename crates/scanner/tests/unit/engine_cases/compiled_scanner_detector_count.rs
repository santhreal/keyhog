use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn compiled_scanner_detector_count() {
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
    let s = CompiledScanner::compile(vec![d.clone(), d]).unwrap();
    assert_eq!(s.detector_count(), 2);
}
