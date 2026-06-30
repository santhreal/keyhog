use keyhog_core::{
    validate_detector, AuthSpec, CompanionSpec, DetectorSpec, HttpMethod, PatternSpec,
    QualityIssue, Severity, StepSpec, SuccessSpec, VerifySpec,
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
fn accepts_unbounded_simple_class_nested_in_counted_group() {
    // An UNBOUNDED char-class repeat is a self-loop on keyhog's linear engines,
    // not a finite unrolling, so it must NOT inflate the counted-repetition
    // product even when nested inside a counted group. This is exactly the
    // canonical inter-keyword separator `[_\-\s]*` inside a `(?:…){1,3}` anchor
    // (deepnote-api-credentials); before the fix it scored a fictitious
    // 3 x 1000 = 3000 and rejected the whole corpus. A genuinely COUNTED
    // explosion (`(?:X{500}){3}`) is still rejected (test above).
    let issues = validate_detector(&detector_with_pattern(
        "(?:DEEPNOTE)(?:[_\\-\\s]*(?:API|KEY)){1,3}[=:](secret_[a-z]{20,})",
    ));
    assert!(
        !issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("counted repetition bound")
        )),
        "unbounded simple-class repeat nested in a counted group must not trip the \
         counted-repetition guard: {issues:?}"
    );
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
fn rejects_pattern_group_index_past_regex_capture_count() {
    let mut detector = detector_with_pattern("token_([A-Z0-9]{8})");
    detector.patterns[0].group = Some(2);

    let issues = validate_detector(&detector);

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("pattern 0 capture group 2 is out of range")
    )));
}

#[test]
fn accepts_pattern_group_zero_and_existing_capture_group() {
    let mut whole_match = detector_with_pattern("token_[A-Z0-9]{8}");
    whole_match.patterns[0].group = Some(0);

    let mut capture = detector_with_pattern("token_([A-Z0-9]{8})");
    capture.patterns[0].group = Some(1);

    for detector in [whole_match, capture] {
        let issues = validate_detector(&detector);
        assert!(
            !issues.iter().any(|issue| matches!(
                issue,
                QualityIssue::Error(message) if message.contains("capture group")
            )),
            "valid capture group must not be rejected, got {issues:?}"
        );
    }
}

#[test]
fn rejects_companion_search_window_above_cap() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: "api_key=".into(),
        within_lines: 101,
        required: false,
    });

    let issues = validate_detector(&detector);

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("within_lines=101 exceeds 100 search-window limit")
    )));
}

#[test]
fn rejects_verify_success_statuses_outside_http_range() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        url: Some("https://example.com/verify".into()),
        success: Some(SuccessSpec {
            status: Some(99),
            status_not: Some(600),
            ..Default::default()
        }),
        ..Default::default()
    });

    let issues = validate_detector(&detector);

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("verify.success.status=99")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("verify.success.status_not=600")
    )));
}

#[test]
fn rejects_step_success_statuses_outside_http_range() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        steps: vec![StepSpec {
            name: "probe".into(),
            method: HttpMethod::Get,
            url: "https://example.com/verify".into(),
            auth: AuthSpec::None {},
            headers: Vec::new(),
            body: None,
            success: SuccessSpec {
                status: Some(700),
                ..Default::default()
            },
            extract: Vec::new(),
        }],
        ..Default::default()
    });

    let issues = validate_detector(&detector);

    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("verify.steps[0].success.status=700")
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
fn rejects_escaped_closing_bracket_character_class_pattern() {
    let detector = detector_with_pattern(r"[A-Z\]]+");

    let issues = validate_detector(&detector);

    assert!(
        issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("pure character class")
        )),
        "escaped class terminators must not hide a pure character-class pattern: {issues:?}"
    );
}

#[test]
fn rejects_anchored_character_class_pattern() {
    let detector = detector_with_pattern(r"^[A-Z0-9]{32}$");

    let issues = validate_detector(&detector);

    assert!(
        issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("pure character class")
        )),
        "anchors do not add textual context to a pure character-class pattern: {issues:?}"
    );
}

#[test]
fn literal_suffix_keeps_character_class_pattern_contextual() {
    let detector = detector_with_pattern(r"[A-Z\]]+TOKEN");

    let issues = validate_detector(&detector);

    assert!(
        !issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("pure character class")
        )),
        "literal suffix gives the pattern textual context; got {issues:?}"
    );
}

#[test]
fn rejects_escaped_closing_bracket_character_class_companion() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.companions.push(CompanionSpec {
        name: "secret".into(),
        regex: r"[A-Z\]]+".into(),
        within_lines: 12,
        required: false,
    });

    let issues = validate_detector(&detector);

    assert!(
        issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("pure character class")
        )),
        "escaped class terminators must not hide a broad companion class: {issues:?}"
    );
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
    let source = keyhog_core::testing::read_crate_source("src/spec/validate/regex_complexity.rs");

    assert!(source.contains("struct RegexWalkFrame"));
    assert!(source.contains("fn collect_regex_stats"));
    assert!(!source.contains("collect_regex_complexity("));
    assert!(!source.contains("collect_redos_risks("));
    assert!(!source.contains("literalish_prefix(&group.ast)"));
    assert!(!source.contains(".any(ast_contains_repetition)"));
}

#[test]
fn literal_specificity_uses_ast_not_raw_regex_scans() {
    let source = keyhog_core::testing::read_crate_source("src/spec/validate.rs");

    assert!(source.contains("fn ast_literal_runs("));
    assert!(source.contains("enum LiteralFrame"));
    assert!(source.contains("fn combine_literal_runs("));
    assert!(source.contains("fn pure_character_class_ast("));
    assert!(source.contains("enum PureFrame"));
    assert!(source.contains("fn is_regex_metadata_node("));
    assert!(source.contains("is_pure_character_class(regex_cache,"));
    assert!(!source.contains("ast_literal_runs(&group.ast)"));
    assert!(!source.contains(".map(|child| ast_literal_runs(child).max)"));
    assert!(!source.contains("pure_character_class_ast(&group.ast)"));
    assert!(!source.contains(".map(|child| pure_character_class_ast(child))"));
    assert!(!source.contains("fn is_escaped_literal("));
    assert!(!source.contains("for ch in pattern.chars()"));
    assert!(!source.contains(".find(']')"));
}

#[test]
fn regex_validation_uses_typed_kinds_not_string_labels() {
    let source = keyhog_core::testing::read_crate_source("src/spec/validate.rs");

    assert!(source.contains("enum RegexKind"));
    assert!(source.contains("RegexKind::Pattern"));
    assert!(source.contains("RegexKind::Companion"));
    assert!(!source.contains("kind: &str"));
    assert!(!source.contains("validate_regex_definition(\"pattern\""));
    assert!(!source.contains("validate_regex_definition(\"companion\""));
}

#[test]
fn pattern_group_bounds_are_validated_before_scanner_compile() {
    let source = keyhog_core::testing::read_crate_source("src/spec/validate.rs");

    assert!(source.contains("fn validate_pattern_groups<'a>("));
    assert!(source.contains("fn ast_captures_len(ast: &ast::Ast) -> usize"));
    assert!(source.contains("fn ast_max_capture_index(ast: &ast::Ast) -> Option<u32>"));
    assert!(source.contains("let mut stack = vec![ast];"));
    assert!(!source.contains("chain(ast_max_capture_index(&group.ast))"));
    assert!(!source.contains("filter_map(ast_max_capture_index)"));
    assert!(source.contains("group >= captures"));
    assert!(!source.contains("regex::Regex::new(&pat.regex)"));
}

#[test]
fn spec_field_bounds_are_named_and_validated() {
    let source = keyhog_core::testing::read_crate_source("src/spec/validate.rs");

    assert!(source.contains("const MAX_COMPANION_WITHIN_LINES: usize = 100;"));
    assert!(source.contains("const MIN_HTTP_STATUS: u16 = 100;"));
    assert!(source.contains("const MAX_HTTP_STATUS: u16 = 599;"));
    assert!(source.contains("fn validate_verify_success_statuses("));
    assert!(source.contains("fn validate_http_status("));
}

#[test]
fn verify_template_checks_use_one_field_visitor() {
    let source = keyhog_core::testing::read_crate_source("src/spec/validate.rs");

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
