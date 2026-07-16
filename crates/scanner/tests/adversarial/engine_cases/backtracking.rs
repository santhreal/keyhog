use super::support::*;

#[test]
fn catastrophic_backtracking_input_does_not_hang() {
    // Create a detector with a regex that could backtrack on malicious input.
    // The regex engine (regex crate) guarantees linear time, but we verify
    // the scan completes in bounded time.
    let detector = DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
        tests: Vec::new(),
        id: "complex-pattern".into(),
        name: "Complex".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"token[=:]\s*[a-zA-Z0-9+/]{20,}={0,2}".into(),
            description: None,
            group: None,
            client_safe: false,
            weak_anchor: false,
        }],
        companions: Vec::new(),
        verify: None,
        keywords: vec!["token".into()],
        min_confidence: None,
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();

    // Input designed to cause backtracking in NFA engines.
    let adversarial = format!("token={}\n", "a".repeat(100_000));
    let chunk = make_chunk(&adversarial);

    let start = std::time::Instant::now();
    let _ = scanner.scan(&chunk);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 5,
        "scan took {elapsed:?} - possible catastrophic backtracking"
    );
}
