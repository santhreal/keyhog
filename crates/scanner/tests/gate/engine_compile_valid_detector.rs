//! LR1-A8 replacement gate: `engine/mod.rs` valid detector compiles.

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::engine::CompiledScanner;

#[test]
fn compiled_scanner_accepts_minimal_detector() {
    let det = DetectorSpec {
        id: "gate".into(),
        name: "Gate".into(),
        service: "demo".into(),
        severity: Severity::High,
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
    let scanner = CompiledScanner::compile(vec![det]);
    assert!(
        scanner.is_ok(),
        "minimal detector must compile: {:?}",
        scanner.err()
    );
}
