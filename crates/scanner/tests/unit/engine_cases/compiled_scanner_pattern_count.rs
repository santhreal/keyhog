use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn compiled_scanner_pattern_count() {
    let d = DetectorSpec {
        id: "a".into(), name: "A".into(), service: "s".into(), severity: Severity::Low,
        patterns: vec![
            PatternSpec { regex: "x".into(), description: None, group: None },
            PatternSpec { regex: "y".into(), description: None, group: None },
        ],
        companions: vec![], verify: None, keywords: vec!["x".into(), "y".into()], ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    assert!(s.pattern_count() >= 2);
}
