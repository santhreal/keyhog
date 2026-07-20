use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn clear_fragment_cache_idempotent() {
    let d = DetectorSpec {
        tests: Vec::new(),
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "x".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["x".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    s.clear_fragment_cache();
    s.clear_fragment_cache();
}
