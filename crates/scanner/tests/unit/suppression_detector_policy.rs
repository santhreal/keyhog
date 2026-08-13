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
