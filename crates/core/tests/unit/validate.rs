use keyhog_core::{
    validate_detector, CompanionSpec, DetectorSpec, PatternSpec, QualityIssue, Severity,
};

fn detector_with_pattern(regex: &str) -> DetectorSpec {
    DetectorSpec {
        id: "test-detector".into(),
        name: "Test Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        keywords: vec!["token".into()],
        patterns: vec![PatternSpec {
            regex: regex.into(),
            description: None,
            group: None,
        }],
        verify: None,
        companions: Vec::new(),
    }
}

#[test]
fn rejects_excessive_alternation_fanout() {
    let regex = (0..65)
        .map(|i| format!("opt{i}"))
        .collect::<Vec<_>>()
        .join("|");
    let issues = validate_detector(&detector_with_pattern(&regex));

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("alternation branches")
    )));
}

#[test]
fn rejects_excessive_counted_repetition() {
    let issues = validate_detector(&detector_with_pattern("token[a-z]{10001}"));

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("counted repetition bound")
    )));
}

#[test]
fn rejects_nested_quantifiers() {
    let issues = validate_detector(&detector_with_pattern("(a+)+b"));

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("nested quantifiers")
    )));
}

#[test]
fn rejects_quantified_overlapping_alternation() {
    let issues = validate_detector(&detector_with_pattern("(ab|a)+z"));

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("overlapping alternations")
    )));
}

#[test]
fn rejects_invalid_companion_regexes() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: "(".into(),
        within_lines: 3,
        required: false,
    });

    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("companion 0 regex does not compile")
    )));
}

#[test]
fn rejects_broad_companion_character_class() {
    // Wide search radius (>5 lines) STILL rejects pure character classes
    // — without a textual anchor the search becomes too permissive.
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: "[A-Za-z0-9+/=]{40,}".into(),
        within_lines: 12,
        required: false,
    });

    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("pure character class")
    )));
}

#[test]
fn warns_but_accepts_companion_character_class_with_tight_radius() {
    // within_lines ≤ TIGHT_COMPANION_RADIUS (5) — positional anchor
    // substitutes for textual context. Should warn, not reject.
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: "[A-Za-z0-9+/=]{40,}".into(),
        within_lines: 5,
        required: false,
    });

    let issues = validate_detector(&detector);
    assert!(
        issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Warning(message) if message.contains("pure character class")
        )),
        "expected a warning (not an error) for tight-radius pure character class"
    );
    assert!(
        !issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("pure character class")
        )),
        "tight-radius pure character class must NOT trip the rejection error"
    );
}
