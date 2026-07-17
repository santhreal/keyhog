#[test]
fn unified_plan_preserves_every_detector_local_compilation_owner() {
    let detectors = keyhog_core::embedded_detector_specs();
    let state = crate::compiler::build_compile_state(detectors)
        .expect("embedded detector compile state must build");
    let strings = detectors
        .iter()
        .flat_map(|detector| {
            [
                detector.id.as_str(),
                detector.name.as_str(),
                detector.service.as_str(),
            ]
            .into_iter()
            .chain(
                detector
                    .entropy_fallback
                    .as_ref()
                    .into_iter()
                    .flat_map(|metadata| {
                        [
                            metadata.id.as_str(),
                            metadata.name.as_str(),
                            metadata.service.as_str(),
                        ]
                    }),
            )
        })
        .collect::<Vec<_>>();
    let interner = crate::static_intern::StaticInterner::from_detector_strings(strings);
    let plans = crate::detector_plan::CompiledDetectorPlans::compile(
        detectors,
        &interner,
        state.companions,
    )
    .expect("embedded detector plans must compile");

    assert_eq!(plans.len(), detectors.len());
    for (index, detector) in detectors.iter().enumerate() {
        let plan = plans.get(index);
        assert_eq!(plan.metadata.0.as_ref(), detector.id);
        assert_eq!(plan.metadata.1.as_ref(), detector.name);
        assert_eq!(plan.metadata.2.as_ref(), detector.service);
        assert_eq!(
            plan.entropy_metadata.as_ref().map(|metadata| (
                metadata.0.as_ref(),
                metadata.1.as_ref(),
                metadata.2.as_ref(),
            )),
            detector.entropy_fallback.as_ref().map(|metadata| (
                metadata.id.as_str(),
                metadata.name.as_str(),
                metadata.service.as_str(),
            ))
        );
        assert_eq!(plan.entropy.is_some(), detector.owns_entropy_policy());
        assert_eq!(
            plan.entropy_floor.is_some(),
            !detector.entropy_floor.is_empty()
        );
        assert_eq!(
            plan.credential_shape.is_some(),
            detector.credential_shape.is_some()
        );
        assert_eq!(
            plan.suppression.is_some(),
            !detector.allowlist_paths.is_empty()
                || !detector.allowlist_values.is_empty()
                || !detector.stopwords.is_empty()
        );
        assert_eq!(plan.companions.len(), detector.companions.len());
        assert_eq!(
            plan.weak_anchor_base,
            crate::suppression::detector_weak_anchor_base(detector)
        );
        #[cfg(feature = "ml")]
        {
            assert_eq!(plan.ml.weight, detector.ml.weight);
            assert_eq!(
                plan.ml.context_radius_lines,
                detector.ml.context_radius_lines
            );
        }
    }
}

#[test]
fn unified_plan_rejects_missing_interned_detector_identity() {
    let detector = keyhog_core::DetectorSpec {
        id: "missing-identity".into(),
        name: "Missing identity".into(),
        service: "test".into(),
        ..Default::default()
    };
    let interner = crate::static_intern::StaticInterner::default();
    let error = crate::detector_plan::CompiledDetectorPlans::compile(
        &[detector],
        &interner,
        vec![Vec::new()],
    )
    .expect_err("missing interned identity must fail scanner construction");

    assert!(
        error.contains("missing-identity"),
        "missing detector: {error}"
    );
    assert!(error.contains("primary id"), "missing field: {error}");
    assert!(
        error.contains("metadata interner"),
        "missing fix context: {error}"
    );
}

#[test]
fn unified_plan_rejects_unordered_detector_entropy_tiers() {
    let mut detector = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic-secret detector")
        .clone();
    detector.entropy_high = Some(6.0);
    detector.entropy_very_high = Some(5.0);
    detector.sensitive_path_entropy_very_high = Some(5.0);

    let error = match crate::CompiledScanner::compile(vec![detector]) {
        Ok(_) => panic!("unordered detector-owned entropy tiers must fail compilation"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("generic-secret"), "missing owner: {error}");
    assert!(
        error.contains("entropy_low <= entropy_high <= entropy_very_high"),
        "missing ordering fix: {error}"
    );
}
