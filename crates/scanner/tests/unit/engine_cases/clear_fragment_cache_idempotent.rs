use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn clear_fragment_cache_idempotent() {
    let d = DetectorSpec {
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "x".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["x".into()],
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    s.clear_fragment_cache();
    s.clear_fragment_cache();
}
