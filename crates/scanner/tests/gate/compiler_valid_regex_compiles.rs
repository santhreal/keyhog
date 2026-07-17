//! LR1-A8 replacement gate: `compiler.rs` valid regex compiles.

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::testing::compile_state_error;

#[test]
fn build_compile_state_accepts_valid_detector() {
    let det = DetectorSpec {
        tests: Vec::new(),
        id: "gate".into(),
        name: "Gate".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..Default::default()
    };
    let error = compile_state_error(&[det]);
    assert!(
        error.is_none(),
        "valid detector regex must compile: {error:?}"
    );
}
