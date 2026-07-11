use crate::engine::{CompiledScanner, CsrU32};
use crate::telemetry::{invalid_pattern_index_skip_count, testing::reset};
use keyhog_core::{DetectorSpec, PatternSpec, Severity};

fn aws_shaped_detector() -> DetectorSpec {
    DetectorSpec {
        id: "corrupt-pattern-index-probe".into(),
        name: "Corrupt Pattern Index Probe".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"AKIA[0-9A-Z]{16}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["AKIA".into()],
        min_confidence: None,
        tests: Vec::new(),
        ..Default::default()
    }
}

#[test]
fn invalid_pattern_index_same_prefix_skip_is_counted() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    reset();
    let mut scanner = CompiledScanner::compile(vec![aws_shaped_detector()]).expect("compile");
    assert!(
        !scanner.ac_map.is_empty(),
        "test setup needs an AC-backed compiled pattern to corrupt"
    );

    scanner.same_prefix_patterns = CsrU32::from(vec![vec![scanner.ac_map.len() + 128]]);
    let _expanded = scanner.expand_triggered_patterns(&[1]);
    assert!(
        invalid_pattern_index_skip_count() > 0,
        "invalid same-prefix sibling pattern indices must be scanner coverage-gap telemetry"
    );

    reset();
    scanner.same_prefix_patterns = CsrU32::from(Vec::<Vec<usize>>::new());
    let _expanded = scanner.expand_triggered_patterns(&[1]);
    assert!(
        invalid_pattern_index_skip_count() > 0,
        "missing same-prefix rows for triggered patterns must be scanner coverage-gap telemetry"
    );
    reset();
}
