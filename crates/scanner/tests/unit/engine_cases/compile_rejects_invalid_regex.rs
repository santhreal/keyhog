use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
#[test]
fn compile_rejects_invalid_regex() {
    let d = DetectorSpec {
        id: "a".into(),
        name: "A".into(),
        service: "s".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "(unclosed".into(),
            description: None,
            group: None,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![],
        ..Default::default()
    };
    assert!(CompiledScanner::compile(vec![d]).is_err());
}
