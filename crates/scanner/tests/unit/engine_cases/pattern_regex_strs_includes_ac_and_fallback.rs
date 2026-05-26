use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn pattern_regex_strs_includes_ac_and_fallback() {
    let d = DetectorSpec {
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        ..Default::default()
    };
    let s = CompiledScanner::compile(vec![d]).unwrap();
    let strs = s.pattern_regex_strs();
    assert!(strs.iter().any(|r| r.contains("abc")));
}
