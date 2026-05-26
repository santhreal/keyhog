use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn preferred_backend_label_nonempty() {
    let d = DetectorSpec {
        id: "a".into(), name: "A".into(), service: "s".into(), severity: Severity::Low,
        patterns: vec![PatternSpec { regex: "x".into(), description: None, group: None }],
        companions: vec![], verify: None, keywords: vec!["x".into()], ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    assert!(!s.preferred_backend_label().is_empty());
}
