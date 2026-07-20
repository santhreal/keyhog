#[test]
fn compiled_execution_policy_matches_every_embedded_detector() {
    let detectors = keyhog_core::embedded_detector_specs();
    let compiled = super::compiled_detector_plans(detectors);

    for (index, detector) in detectors.iter().enumerate() {
        let policy = &compiled.get(index).execution;
        assert_eq!(policy.is_generic, detector.owns_entropy_policy());
        assert_eq!(policy.length.min_len, detector.min_len);
        assert_eq!(policy.length.max_len, detector.max_len);
        assert_eq!(policy.min_confidence, detector.min_confidence);
        assert_eq!(policy.severity, detector.severity);
        assert_eq!(
            policy.structural_password_slot,
            detector.structural_password_slot
        );

        for keyword in &detector.keywords {
            let text = format!("prefix {keyword} suffix");
            assert!(
                policy.keyword_nearby(text.as_bytes(), text.as_bytes()),
                "compiled keyword drifted for detector={} keyword={keyword:?}",
                detector.id
            );
        }

        for marker in &detector.public_identifier_assignment_markers {
            let line = format!("prefix {} value", marker.to_ascii_lowercase());
            assert!(
                policy.line_has_public_identifier_assignment(line.as_bytes()),
                "compiled public-identifier marker drifted for detector={} marker={marker:?}",
                detector.id
            );
        }
    }
}

#[test]
fn compiled_keyword_probe_checks_preprocessed_text_only_when_it_differs() {
    let detector = keyhog_core::DetectorSpec {
        id: "compiled-keyword-probe".to_string(),
        name: "Compiled keyword probe".to_string(),
        service: "generic".to_string(),
        keywords: vec!["api_key".to_string()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let compiled = super::compiled_detector_plans(&[detector]);
    let policy = &compiled.get(0).execution;

    assert!(policy.keyword_nearby(b"api_key=value", b"api_key=value"));
    assert!(policy.keyword_nearby(b"decoded wrapper", b"api_key=value"));
    assert!(!policy.keyword_nearby(b"API_KEY=value", b"API_KEY=value"));
    assert!(!policy.keyword_nearby(b"ordinary=value", b"ordinary=value"));
}

#[test]
fn compiled_length_policy_has_exact_inclusive_boundaries() {
    use crate::detector_execution_policy::CandidateLengthRejection;

    let detector = keyhog_core::DetectorSpec {
        id: "compiled-length-policy".to_string(),
        name: "Compiled length policy".to_string(),
        service: "generic".to_string(),
        min_len: Some(8),
        max_len: Some(10),
        ..Default::default()
    };
    let policy = crate::detector_execution_policy::CompiledDetectorLengthPolicy::compile(&detector);

    assert_eq!(
        policy.rejection(7),
        Some(CandidateLengthRejection::TooShort)
    );
    assert_eq!(policy.rejection(8), None);
    assert_eq!(policy.rejection(9), None);
    assert_eq!(policy.rejection(10), None);
    assert_eq!(
        policy.rejection(11),
        Some(CandidateLengthRejection::TooLong)
    );
}

#[cfg(feature = "entropy")]
#[test]
fn entropy_generation_rejects_above_max_before_scoring() {
    let detectors = keyhog_core::embedded_detector_specs();
    let detector_index = detectors
        .iter()
        .position(|detector| detector.id == "generic-api-key")
        .expect("generic API-key detector");
    let plans = super::compiled_detector_plans(detectors);
    let policy = *plans
        .get(detector_index)
        .entropy
        .as_ref()
        .expect("compiled entropy policy");
    let context = crate::entropy::keywords::KeywordContext {
        keyword: "api_key".to_string(),
        threshold: 0.0,
        min_len: policy.length.min_len,
        is_credential_context: true,
        plausibility_policy: policy,
    };
    let at_max = "A".repeat(policy.length.max_len);
    let above_max = "A".repeat(policy.length.max_len + 1);

    assert_eq!(
        crate::entropy::scanner::candidate_max_length_stage(&at_max, &context),
        None,
    );
    let stage = crate::entropy::scanner::candidate_max_length_stage(&above_max, &context)
        .expect("max + 1 must be rejected");
    assert_eq!(stage.as_str(), "value_too_long");
}

#[test]
fn compiled_public_identifier_markers_preserve_boundary_bytes() {
    let detector = keyhog_core::DetectorSpec {
        id: "compiled-marker-boundary".to_string(),
        name: "Compiled marker boundary".to_string(),
        service: "generic".to_string(),
        public_identifier_assignment_markers: vec!["_ADDR=".to_string()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let compiled = super::compiled_detector_plans(&[detector]);
    let policy = &compiled.get(0).execution;

    assert!(policy.line_has_public_identifier_assignment(b"SOLANA_ADDR=value"));
    assert!(!policy.line_has_public_identifier_assignment(b"SOLANA_ADDRESS=value"));
    assert!(!policy.line_has_public_identifier_assignment(b"SOLANA_ADDR: value"));
}
