//! LR1-A8 replacement gate: `compiler.rs` valid regex compiles.

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::compiler::build_compile_state;

#[test]
fn build_compile_state_accepts_valid_detector() {
    let det = DetectorSpec {
        id: "gate".into(),
        name: "Gate".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        ..Default::default()
    };
    let state = build_compile_state(&[det]);
    assert!(
        state.is_ok(),
        "valid detector regex must compile: {:?}",
        state.err()
    );
}
