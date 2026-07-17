use keyhog_core::{
    validate_detector, AuthSpec, CompanionSpec, DetectorSpec, HttpMethod, MetadataSpec,
    PatternSpec, QualityIssue, Severity, StepSpec, SuccessSpec, VerifySpec,
};

fn detector_with_pattern(regex: &str) -> DetectorSpec {
    DetectorSpec {
        kind: Default::default(),
        entropy_floor: Vec::new(),
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
        ..Default::default()
    }
}

#[test]
fn entropy_policy_priority_owns_policy_independently_of_reporting_service() {
    let mut detector = detector_with_pattern("token_([A-Z0-9]{12})");
    detector.entropy_policy_priority = Some(10);
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("active entropy owner must declare entropy_fallback")
    )));

    detector.service = "generic".into();
    assert!(
        validate_detector(&detector).iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message)
                if message.contains("active entropy owner must declare entropy_fallback")
        )),
        "reporting service must not change explicit entropy-policy ownership"
    );
}

#[test]
fn active_entropy_owner_must_declare_fallback_metadata() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.service = "generic".into();
    detector.kind = keyhog_core::DetectorKind::Phase2Generic;
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("active entropy owner must declare entropy_fallback")
    )));
}

#[test]
fn pattern_weak_anchor_policy_is_local_and_unambiguous() {
    let mut detector = detector_with_pattern("token_([A-Z0-9]{12})");
    detector.patterns.push(PatternSpec {
        regex: "user=([A-Za-z0-9_-]+)".into(),
        ..Default::default()
    });
    detector.entropy_high = Some(4.5);
    detector.entropy_floor = vec![keyhog_core::EntropyFloorBucket {
        max_len: None,
        floor: 3.5,
    }];

    detector.patterns[1].weak_anchor = true;
    let valid = validate_detector(&detector);
    assert!(!valid.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("weak_anchor")
    )));

    detector.weak_anchor = true;
    let redundant = validate_detector(&detector);
    assert!(redundant.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("remove redundant pattern")
    )));
}

#[test]
fn vendor_suffix_fallback_is_restricted_to_generic_phase2_detectors() {
    let mut detector = detector_with_pattern("token_([A-Z0-9]{12})");
    detector.generic_vendor_suffix_fallback = true;
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("generic_vendor_suffix_fallback is only valid")
    )));

    detector.kind = keyhog_core::DetectorKind::Phase2Generic;
    assert!(!validate_detector(&detector).iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("generic_vendor_suffix_fallback is only valid")
    )));
}

#[test]
fn detector_ml_policy_rejects_invalid_weight_radius_and_entropy_ownership() {
    let mut detector = detector_with_pattern("token_([A-Z0-9]{12})");
    detector.ml.weight = f64::NAN;
    detector.ml.context_radius_lines = 65;
    detector.ml.entropy_mode = keyhog_core::DetectorMlMode::Authoritative;
    let issues = validate_detector(&detector);
    for expected in ["ml.weight", "ml.context_radius_lines", "ml.entropy_mode"] {
        assert!(
            issues.iter().any(|issue| matches!(
                issue,
                QualityIssue::Error(message) if message.contains(expected)
            )),
            "missing {expected} validation error: {issues:#?}"
        );
    }
}

#[test]
fn sensitive_path_entropy_threshold_cannot_exceed_detector_threshold() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.entropy_very_high = Some(5.0);
    detector.sensitive_path_entropy_very_high = Some(5.1);
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("sensitive_path_entropy_very_high")
                && message.contains("must not exceed entropy_very_high")
    )));
}

#[test]
fn plausibility_policy_fields_reject_invalid_ranges() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.plausibility = Some(keyhog_core::DetectorPlausibilityPolicySpec {
        mixed_alnum_floor: 4.0,
        symbolic_entropy_floor: 9.0,
        second_half_entropy_floor: f64::NAN,
        mixed_alnum_min_len: 0,
        isolated_mixed_entropy_floor: 9.0,
        isolated_symbolic_min_len: 0,
        isolated_symbolic_min_symbols: 0,
        isolated_symbolic_requires_non_underscore: true,
        isolated_colon_left_min_len: 0,
        isolated_colon_right_min_len: 0,
        leading_slash_base64_entropy_floor: f64::NAN,
        reject_repeated_blocks: true,
        allow_alphabetic_credential: true,
        reject_program_identifiers: true,
        reject_source_symbol_identifiers: true,
        reject_dash_segmented_alnum: true,
    });
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("symbolic_entropy_floor")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("second_half_entropy_floor")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("mixed_alnum_min_len")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("isolated_symbolic_min_symbols")
    )));
}

#[test]
fn entropy_fallback_metadata_requires_entropy_identity_and_labels() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.entropy_fallback = Some(keyhog_core::EntropyFallbackMetadata {
        class: keyhog_core::EntropyFallbackClass::Generic,
        id: "generic-secret".into(),
        name: "".into(),
        service: "".into(),
    });
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("entropy_fallback.id")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("entropy_fallback.name")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("entropy_fallback.service")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("requires an active detector-owned entropy policy")
    )));
}

#[test]
fn entropy_shape_policy_rejects_invalid_bounds_and_duplicate_kinds() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.entropy_shapes = vec![
        keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
            entropy_floor: 8.1,
            group_count: 0,
            group_length: 4,
            special_min_length: 20,
        },
        keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
            entropy_floor: 3.9,
            group_count: 4,
            group_length: 4,
            special_min_length: 16,
        },
    ];
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("duplicate kind")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("entropy_floor")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("group_count and group_length")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("special_min_length")
    )));
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("entropy_shapes require an active")
    )));
}

#[test]
fn entropy_shape_policy_rejects_derived_length_overflow() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.entropy_shapes = vec![keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
        entropy_floor: 3.9,
        group_count: usize::MAX,
        group_length: 2,
        special_min_length: 1,
    }];
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("overflow the derived candidate length")
    )));
}

#[test]
fn phase2_generic_max_len_must_be_positive_and_not_below_min_len() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.kind = keyhog_core::DetectorKind::Phase2Generic;
    detector.min_len = Some(16);
    detector.max_len = Some(8);
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("min_len 16 exceeds max_len 8")
    )));

    detector.min_len = Some(1);
    detector.max_len = Some(0);
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("max_len must be greater than 0")
    )));

    detector.max_len = Some(7);
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("generic assignment path minimum of 8")
    )));
}

#[test]
fn regex_detector_without_entropy_ownership_rejects_max_len() {
    let mut detector = detector_with_pattern("token=([A-Za-z0-9]+)");
    detector.max_len = Some(80);
    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("only valid for detectors that own generic entropy policy")
    )));
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
fn rejects_invalid_response_selectors_at_every_verification_surface() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        url: Some("https://example.com/verify".into()),
        success: Some(SuccessSpec {
            json_path: Some("/legacy-pointer".into()),
            ..Default::default()
        }),
        metadata: vec![MetadataSpec {
            name: "account".into(),
            json_path: "account.email".into(),
            sensitivity: Default::default(),
        }],
        steps: vec![StepSpec {
            name: "probe".into(),
            method: HttpMethod::Get,
            url: "https://example.com/verify".into(),
            auth: AuthSpec::None {},
            headers: Vec::new(),
            body: None,
            success: SuccessSpec {
                json_path: Some("$.items[*]".into()),
                ..Default::default()
            },
            extract: vec![MetadataSpec {
                name: "owner".into(),
                json_path: "$.owner.".into(),
                sensitivity: Default::default(),
            }],
        }],
        ..Default::default()
    });

    let errors: Vec<_> = validate_detector(&detector)
        .into_iter()
        .filter_map(|issue| match issue {
            QualityIssue::Error(message) => Some(message),
            QualityIssue::Warning(_) => None,
        })
        .collect();
    for scope in [
        "verify.success.json_path",
        "verify.metadata[0].json_path",
        "verify.steps[0].success.json_path",
        "verify.steps[0].extract[0].json_path",
    ] {
        assert!(
            errors.iter().any(|error| error.contains(scope)),
            "missing selector error for {scope}: {errors:?}"
        );
    }
}

#[test]
fn rejects_unreviewed_or_duplicate_provider_evidence_roles() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        metadata: vec![
            MetadataSpec {
                name: "provider_dynamic_key".into(),
                json_path: "$.dynamic".into(),
                sensitivity: Default::default(),
            },
            MetadataSpec {
                name: "account_id".into(),
                json_path: "$.account.id".into(),
                sensitivity: Default::default(),
            },
            MetadataSpec {
                name: "accountID".into(),
                json_path: "$.legacyAccountId".into(),
                sensitivity: Default::default(),
            },
        ],
        steps: vec![StepSpec {
            name: "exchange".into(),
            method: HttpMethod::Get,
            url: "https://example.com/verify".into(),
            auth: AuthSpec::None {},
            headers: Vec::new(),
            body: None,
            success: SuccessSpec::default(),
            extract: vec![MetadataSpec {
                name: "provider_flow_nonce".into(),
                json_path: "$.nonce".into(),
                sensitivity: Default::default(),
            }],
        }],
        ..Default::default()
    });

    let errors: Vec<_> = validate_detector(&detector)
        .into_iter()
        .filter_map(|issue| match issue {
            QualityIssue::Error(message) => Some(message),
            QualityIssue::Warning(_) => None,
        })
        .collect();
    assert!(errors.iter().any(|error| {
        error.contains("provider_dynamic_key")
            && error.contains("not a supported provider evidence role")
    }));
    assert!(errors.iter().any(|error| {
        error.contains("repeats provider evidence role") && error.contains("account_id")
    }));
    assert!(
        errors
            .iter()
            .all(|error| !error.contains("provider_flow_nonce")),
        "multi-step scratch names must remain flow-local, got {errors:?}"
    );
}

#[test]
fn rejects_equals_without_a_response_selector() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        url: Some("https://example.com/verify".into()),
        success: Some(SuccessSpec {
            equals: Some("true".into()),
            ..Default::default()
        }),
        ..Default::default()
    });

    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("verify.success.equals requires verify.success.json_path")
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
fn literal_verify_url_host_must_match_the_runtime_domain_policy() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        url: Some("https://api.example.com/v1/{{match}}".into()),
        allowed_domains: vec!["example.com".into()],
        ..Default::default()
    });
    let valid = validate_detector(&detector);
    assert!(
        !valid.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("outside verify.allowed_domains")
        )),
        "an exact permitted subdomain must pass compile validation: {valid:?}"
    );

    detector.verify.as_mut().expect("verify spec").url =
        Some("https://example.com.attacker.test/v1/{{match}}".into());
    let invalid = validate_detector(&detector);
    assert!(invalid.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("verify.url host")
                && message.contains("outside verify.allowed_domains")
    )));
}

#[test]
fn broad_parent_allowlist_cannot_cross_a_shared_tenant_boundary() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        url: Some("https://openai.azure.com/v1/{{match}}".into()),
        allowed_domains: vec!["azure.com".into()],
        ..Default::default()
    });
    let blocked = validate_detector(&detector);
    assert!(blocked.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("openai.azure.com")
                && message.contains("outside verify.allowed_domains")
    )));

    detector
        .verify
        .as_mut()
        .expect("verify spec")
        .allowed_domains = vec!["openai.azure.com".into()];
    let exact = validate_detector(&detector);
    assert!(!exact.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("outside verify.allowed_domains")
    )));
}

#[test]
fn omitted_verify_service_inherits_the_detector_service_domain_policy() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.service = "github".into();
    detector.verify = Some(VerifySpec {
        url: Some("https://api.github.com/user".into()),
        ..Default::default()
    });
    let inherited = validate_detector(&detector);
    assert!(
        !inherited.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message)
                if message.contains("no domain policy")
                    || message.contains("outside verify.allowed_domains")
        )),
        "the runtime and compile path must share detector-service inheritance: {inherited:?}"
    );

    detector.service = "unknown-service".into();
    let unknown = validate_detector(&detector);
    assert!(unknown.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("verify.url host")
            && message.contains("no domain policy")
    )));
}

#[test]
fn every_selected_step_url_is_checked_with_field_context() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    let step = |name: &str, url: &str| StepSpec {
        name: name.into(),
        method: HttpMethod::Get,
        url: url.into(),
        auth: AuthSpec::None {},
        headers: Vec::new(),
        body: None,
        success: SuccessSpec::default(),
        extract: Vec::new(),
    };
    detector.verify = Some(VerifySpec {
        url: Some("https://unused.attacker.test/".into()),
        allowed_domains: vec!["example.com".into()],
        steps: vec![
            step("session", "https://auth.example.com/session"),
            step("profile", "https://api.example.net/profile"),
        ],
        ..Default::default()
    });

    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("verify.steps[1].url host")
                && message.contains("api.example.net")
    )));
    assert!(!issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message) if message.contains("unused.attacker.test")
    )));
}

#[test]
fn invalid_domain_policy_entries_fail_before_runtime() {
    let mut detector = detector_with_pattern("token_[A-Z0-9]{8}");
    detector.verify = Some(VerifySpec {
        url: Some("https://api.example.com/v1".into()),
        allowed_domains: vec!["https://example.com/path".into()],
        ..Default::default()
    });

    let issues = validate_detector(&detector);
    assert!(issues.iter().any(|issue| matches!(
        issue,
        QualityIssue::Error(message)
            if message.contains("verify.allowed_domains[0]")
                && message.contains("host-only URL")
    )));
}
