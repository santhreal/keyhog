use keyhog_core::{
    validate_detector, CompanionSpec, DetectorSpec, PatternSpec, QualityIssue, Severity,
};

fn detector_with_pattern(regex: &str) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: "test-detector".into(),
        name: "Test Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        keywords: vec!["token".into()],
        min_confidence: None,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            ..Default::default()
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
fn rejects_cumulative_nested_counted_repetition() {
    let issues = validate_detector(&detector_with_pattern("token(?:[A-Z]{500}){3}"));

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("counted repetition bound")
    )));
}

#[test]
fn deeply_nested_regex_validation_is_iterative() {
    let mut regex = format!("token{}", "a{1}".repeat(300));
    for _ in 0..120 {
        regex = format!("(?:{regex}){{1}}");
    }
    let issues = validate_detector(&detector_with_pattern(&regex));

    assert!(
        issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("too complex")
        )),
        "expected deep but bounded-size regex to hit the validator complexity gate, got: {issues:?}"
    );
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
fn rejects_unsupported_lookaround_at_parse() {
    let issues = validate_detector(&detector_with_pattern("token(?=secret)"));

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("does not compile")
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
    // - without a textual anchor the search becomes too permissive.
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
    // within_lines ≤ TIGHT_COMPANION_RADIUS (5) - positional anchor
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

#[test]
fn grouped_literal_prefix_satisfies_pattern_specificity() {
    let mut detector = detector_with_pattern("(?:demo_)[A-Z0-9]{8}");
    detector.keywords.clear();

    let issues = validate_detector(&detector);

    assert!(
        !issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Warning(message) if message.contains("no literal prefix")
        )),
        "AST literal prefix inside a group must count as pattern context; got {issues:?}"
    );
}

#[test]
fn grouped_companion_literal_satisfies_context_anchor() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: "(?:api_key=)[A-Z0-9]{8}".into(),
        within_lines: 12,
        required: false,
    });

    let issues = validate_detector(&detector);

    assert!(
        !issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Warning(message) if message.contains("too broad")
        )),
        "AST literal run inside a group must count as companion context; got {issues:?}"
    );
}

#[test]
fn regex_validator_uses_one_iterative_ast_walk() {
    let source = std::fs::read_to_string("src/spec/validate/regex_complexity.rs")
        .expect("read regex complexity source");

    assert!(source.contains("struct RegexWalkFrame"));
    assert!(source.contains("fn collect_regex_stats"));
    assert!(!source.contains("collect_regex_complexity("));
    assert!(!source.contains("collect_redos_risks("));
    assert!(!source.contains("literalish_prefix(&group.ast)"));
    assert!(!source.contains(".any(ast_contains_repetition)"));
}

#[test]
fn literal_specificity_uses_ast_not_raw_regex_scans() {
    let source = std::fs::read_to_string("src/spec/validate.rs").expect("read validate source");

    assert!(source.contains("fn ast_literal_runs("));
    assert!(source.contains("fn combine_literal_runs("));
    assert!(!source.contains("fn is_escaped_literal("));
    assert!(!source.contains("for ch in pattern.chars()"));
}

#[test]
fn verify_template_checks_use_one_field_visitor() {
    let source = std::fs::read_to_string("src/spec/validate.rs").expect("read validate source");

    assert!(source.contains("struct VerifyTemplateField"));
    assert!(source.contains("fn visit_verify_template_fields"));
    assert_eq!(
        source.matches("for step in &verify.steps").count(),
        1,
        "step URL/body/header traversal should live only in the template-field visitor"
    );
    assert!(source.contains("validate_verify_urls(verify, issues);"));
    assert!(source.contains("visit_verify_template_fields(verify, |field|"));
}
