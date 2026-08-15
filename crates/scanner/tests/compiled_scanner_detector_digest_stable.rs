use keyhog_core::{DetectorSpec, DetectorTestSpec, DetectorValidatorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn expected_digest(detectors: &[DetectorSpec], decoder_plan_identity: u64) -> [u8; 32] {
    fn update(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
        hasher.update(&(tag.len() as u64).to_le_bytes());
        hasher.update(tag);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = blake3::Hasher::new();
    update(&mut hasher, b"domain", b"keyhog-scanner-detector-digest-v3");
    update(
        &mut hasher,
        b"spec_hash",
        &keyhog_core::compute_spec_hash(detectors),
    );
    update(
        &mut hasher,
        b"decoder_plan",
        &decoder_plan_identity.to_le_bytes(),
    );
    *hasher.finalize().as_bytes()
}

fn detector(id: &str, regex: &str, keyword: &str) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: id.into(),
        name: id.into(),
        service: "digest".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![keyword.into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

/// The full execution-plan digest must be stable, order-independent, and retain its legacy projection.
#[test]
fn compiled_scanner_detector_digest_is_stable_and_boundary_aware() {
    let detectors = vec![
        detector("alpha", "AKIA[0-9A-Z]{16}", "AKIA"),
        detector("beta", "ghp_[0-9A-Za-z]{36}", "ghp_"),
    ];
    let first_status = CompiledScanner::compile(detectors.clone())
        .expect("compile first scanner")
        .runtime_status();
    let first = first_status.detector_digest;
    let first_plan = first_status.compiled_plan_digest;
    let second_status = CompiledScanner::compile(detectors.clone())
        .expect("compile second scanner")
        .runtime_status();
    let changed_status = CompiledScanner::compile(vec![
        detector("alpha", "AKIA[0-9A-Z]{16}", "AKIA"),
        detector("beta", "ghp_[0-9A-Za-z]{37}", "ghp_"),
    ])
    .expect("compile changed scanner")
    .runtime_status();

    assert_ne!(first, 0, "runtime detector digest must carry real identity");
    assert_ne!(
        first_plan, [0; 32],
        "full plan digest must carry real identity"
    );
    assert_eq!(
        first_plan, second_status.compiled_plan_digest,
        "same compiled detector runtime must produce the same full plan identity"
    );
    assert_ne!(
        first_plan, changed_status.compiled_plan_digest,
        "regex source changes must invalidate the full compiled-plan identity"
    );
    let expected = expected_digest(
        &detectors,
        keyhog_scanner::testing::decoder_plan_identity_for_test().expect("decoder plan identity"),
    );
    assert_eq!(first_plan, expected);
    let mut projected = [0_u8; 8];
    projected.copy_from_slice(&first_plan[..8]);
    assert_eq!(
        first,
        u64::from_le_bytes(projected),
        "legacy autoroute identity must project the complete compiled-plan digest"
    );

    let reordered = CompiledScanner::compile(detectors.iter().cloned().rev().collect())
        .expect("compile reordered scanner")
        .runtime_status()
        .detector_digest;
    assert_eq!(
        first, reordered,
        "detector file order must not create a different canonical identity"
    );
}

/// Routing, validation, and emission policy changes must invalidate compiled runtime identity.
#[test]
fn compiled_scanner_detector_digest_covers_routing_validation_and_policy() {
    let base = detector("beta", "ghp_[0-9A-Za-z]{36}", "ghp_");
    let base_digest = CompiledScanner::compile(vec![base.clone()])
        .expect("compile base scanner")
        .runtime_status()
        .detector_digest;

    let mut routed = base.clone();
    routed.patterns[0].required_literals = vec!["ghp_".into()];
    let routed_digest = CompiledScanner::compile(vec![routed])
        .expect("compile routed scanner")
        .runtime_status()
        .detector_digest;
    assert_ne!(
        base_digest, routed_digest,
        "detector-owned routing literals must invalidate autoroute evidence"
    );

    let mut validated = base.clone();
    validated.validators = vec![DetectorValidatorSpec::PatternShape {
        prefixes: vec!["ghp_".into()],
        allow_overlong: false,
    }];
    let validated_digest = CompiledScanner::compile(vec![validated])
        .expect("compile validated scanner")
        .runtime_status()
        .detector_digest;
    assert_ne!(
        base_digest, validated_digest,
        "detector-owned offline validation must invalidate autoroute evidence"
    );

    let mut policy = base.clone();
    policy.min_confidence = Some(0.91);
    let policy_digest = CompiledScanner::compile(vec![policy])
        .expect("compile policy scanner")
        .runtime_status()
        .detector_digest;
    assert_ne!(
        base_digest, policy_digest,
        "detector-local emission policy must invalidate autoroute evidence"
    );

    let mut fixtures_only = base;
    fixtures_only.tests.push(DetectorTestSpec {
        test_positive: Some("token = ghp_abcdefghijklmnopqrstuvwxyz0123456789".into()),
        test_negative: None,
        pattern_index: None,
        negative_class: None,
        test_path: None,
    });
    let fixtures_digest = CompiledScanner::compile(vec![fixtures_only])
        .expect("compile scanner with an inline fixture")
        .runtime_status()
        .detector_digest;
    assert_eq!(
        base_digest, fixtures_digest,
        "non-runtime detector fixtures must not invalidate performance evidence"
    );
}
