//! LR1-A8 replacement gate: `engine/mod.rs` valid detector compiles.

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::engine::CompiledScanner;

#[test]
fn compiled_scanner_accepts_minimal_detector() {
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
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![det]);
    assert!(
        scanner.is_ok(),
        "minimal detector must compile: {:?}",
        scanner.err()
    );
}
