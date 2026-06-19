use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn compiled_scanner_pattern_count() {
    let d = DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![
            PatternSpec {
                regex: "x".into(),
                description: None,
                group: None,
                client_safe: false,
            },
            PatternSpec {
                regex: "y".into(),
                description: None,
                group: None,
                client_safe: false,
            },
        ],
        companions: vec![],
        verify: None,
        keywords: vec!["x".into(), "y".into()],
        min_confidence: None,
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    assert!(s.runtime_status().pattern_count >= 2);
}
