use super::DetectorSuppressionPolicy;

#[test]
fn detector_local_policy_compilation_preserves_empty_and_active_cases() {
    let detectors = [
        keyhog_core::DetectorSpec {
            id: "no-policy".into(),
            ..Default::default()
        },
        keyhog_core::DetectorSpec {
            id: "value-policy".into(),
            allowlist_values: vec!["^allowed$".into()],
            ..Default::default()
        },
        keyhog_core::DetectorSpec {
            id: "stopword-policy".into(),
            stopwords: vec!["example".into()],
            ..Default::default()
        },
    ];

    assert!(DetectorSuppressionPolicy::compile(&detectors[0])
        .expect("compile empty policy")
        .is_none());
    assert!(DetectorSuppressionPolicy::compile(&detectors[1])
        .expect("compile value policy")
        .is_some());
    assert!(DetectorSuppressionPolicy::compile(&detectors[2])
        .expect("compile stopword policy")
        .is_some());
}

#[test]
fn invalid_programmatic_policy_regex_has_detector_and_field_context() {
    let detectors = [keyhog_core::DetectorSpec {
        id: "broken-policy".into(),
        allowlist_paths: vec!["[".into()],
        ..Default::default()
    }];

    let error = DetectorSuppressionPolicy::compile(&detectors[0])
        .err()
        .expect("invalid regex must fail compilation");
    assert!(error.contains("broken-policy"), "missing detector: {error}");
    assert!(error.contains("allowlist_paths"), "missing field: {error}");
    assert!(
        error.contains("failed to compile"),
        "missing cause: {error}"
    );
}

#[cfg(feature = "decode")]
#[test]
fn decoded_source_family_uses_only_registered_decoder_suffixes() {
    let detector = keyhog_core::DetectorSpec {
        id: "source-admitted".into(),
        name: "Source admitted".into(),
        service: "fixture".into(),
        source_admission: keyhog_core::SourceAdmissionSpec {
            source_types: vec!["fixture-source".into()],
            ..Default::default()
        },
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let plans = crate::unit::compiled_detector_plans(&[detector]);
    let registered = plans
        .decoder_plan()
        .decoders()
        .iter()
        .map(|decoder| decoder.name())
        .collect::<Vec<_>>();

    for decoder in registered {
        let derived = format!("fixture-source/{decoder}");
        assert_eq!(
            plans.decoded_source_family(&derived),
            "fixture-source",
            "registered sibling decoder {decoder} must preserve the root source family",
        );
    }

    assert_eq!(
        plans.decoded_source_family("fixture-source/base64/hex"),
        "fixture-source",
        "nested registered decoder chains must resolve to their source family",
    );
    assert_eq!(
        plans.decoded_source_family("other-source/base64"),
        "other-source",
        "decoder canonicalization must not admit an unrelated source root",
    );
    assert_eq!(
        plans.decoded_source_family("fixture-source/unregistered"),
        "fixture-source/unregistered",
        "unknown slash suffixes must remain fail-closed",
    );
}

#[test]
fn filter_pattern_exact_and_literal_optimizations() {
    use super::FilterPattern;

    let exact = FilterPattern::compile("^exact_val$").expect("compile exact");
    assert!(matches!(exact, FilterPattern::Exact(_)));
    assert!(exact.is_match("exact_val"));
    assert!(!exact.is_match("exact_val_extra"));
    assert!(!exact.is_match("pre_exact_val"));

    let prefix = FilterPattern::compile("^prefix_.*").expect("compile prefix");
    assert!(matches!(prefix, FilterPattern::Prefix(_)));
    assert!(prefix.is_match("prefix_123"));
    assert!(!prefix.is_match("other_prefix_123"));

    let suffix = FilterPattern::compile("_suffix$").expect("compile suffix");
    assert!(matches!(suffix, FilterPattern::Suffix(_)));
    assert!(suffix.is_match("file_suffix"));
    assert!(!suffix.is_match("file_suffix_extra"));

    let substring = FilterPattern::compile(".*needle.*").expect("compile substring");
    assert!(matches!(substring, FilterPattern::Substring(_)));
    assert!(substring.is_match("haystack_needle_end"));
    assert!(!substring.is_match("haystack_other_end"));

    let plain = FilterPattern::compile("vendor/").expect("compile plain");
    assert!(matches!(plain, FilterPattern::Substring(_)));
    assert!(plain.is_match("path/to/vendor/file.rs"));
    assert!(!plain.is_match("path/to/app/file.rs"));

    let complex_re = FilterPattern::compile(r"^test_[0-9]+\.rs$").expect("compile regex");
    assert!(matches!(complex_re, FilterPattern::Regex(_)));
    assert!(complex_re.is_match("test_42.rs"));
    assert!(!complex_re.is_match("test_abc.rs"));
}

#[test]
fn detector_policy_allowlist_matching() {
    let spec = keyhog_core::DetectorSpec {
        id: "opt-policy".into(),
        allowlist_paths: vec!["^fixtures/.*".into(), "^test_exact\\.json$".into()],
        allowlist_values: vec!["^demo_token$".into()],
        ..Default::default()
    };

    let policy = DetectorSuppressionPolicy::compile(&spec)
        .expect("compile policy")
        .expect("policy must be Some");

    let path_match = policy.allowlist_stage(Some("fixtures/test.rs"), None, "real_secret");
    assert!(path_match.is_some());

    let path_exact = policy.allowlist_stage(Some("test_exact.json"), None, "real_secret");
    assert!(path_exact.is_some());

    let val_match = policy.allowlist_stage(Some("src/main.rs"), None, "demo_token");
    assert!(val_match.is_some());

    let no_match = policy.allowlist_stage(Some("src/main.rs"), None, "real_secret");
    assert!(no_match.is_none());
}
