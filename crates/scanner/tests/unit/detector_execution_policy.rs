#[test]
fn compiled_execution_policy_matches_every_embedded_detector() {
    let detectors = keyhog_core::embedded_detector_specs();
    let compiled = super::compiled_detector_plans(detectors);

    for (index, detector) in detectors.iter().enumerate() {
        let policy = &compiled.get(index).execution;
        assert_eq!(policy.is_generic, detector.service == "generic");
        assert_eq!(policy.min_len, detector.min_len);
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
        ..Default::default()
    };
    let compiled = super::compiled_detector_plans(&[detector]);
    let policy = &compiled.get(0).execution;

    assert!(policy.keyword_nearby(b"api_key=value", b"api_key=value"));
    assert!(policy.keyword_nearby(b"decoded wrapper", b"api_key=value"));
    assert!(!policy.keyword_nearby(b"API_KEY=value", b"API_KEY=value"));
    assert!(!policy.keyword_nearby(b"ordinary=value", b"ordinary=value"));
}

#[test]
fn compiled_public_identifier_markers_preserve_boundary_bytes() {
    let detector = keyhog_core::DetectorSpec {
        id: "compiled-marker-boundary".to_string(),
        name: "Compiled marker boundary".to_string(),
        service: "generic".to_string(),
        public_identifier_assignment_markers: vec!["_ADDR=".to_string()],
        ..Default::default()
    };
    let compiled = super::compiled_detector_plans(&[detector]);
    let policy = &compiled.get(0).execution;

    assert!(policy.line_has_public_identifier_assignment(b"SOLANA_ADDR=value"));
    assert!(!policy.line_has_public_identifier_assignment(b"SOLANA_ADDRESS=value"));
    assert!(!policy.line_has_public_identifier_assignment(b"SOLANA_ADDR: value"));
}
