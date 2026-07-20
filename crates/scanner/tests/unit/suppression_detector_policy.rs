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
