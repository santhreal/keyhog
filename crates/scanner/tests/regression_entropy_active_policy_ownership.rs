use keyhog_core::{
    CanonicalHexKeyMaterialSpec, Chunk, ChunkMetadata, DetectorKind, DetectorSpec,
    EntropyFallbackClass, EntropyFallbackMetadata, EntropyFloorBucket, EntropyShapeSpec,
    PatternSpec,
};
use keyhog_scanner::testing::entropy_scanner::{
    active_policy_match_values, active_policy_owner_id,
};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const KEYWORD: &str = "custom_credential";
const VALUE: &str = "a8Xk9mQ2pL5vR7tN3wE6yU1zAbCdEf0G";
const KEYWORD_FREE_VALUE: &str = "hmWtQ96MawiACRuKvJHIUxNGZDg5z1bVFodOE@07lkfBynYs";

fn detector(id: &str, keywords: &[&str], min_len: usize) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        name: id.to_string(),
        service: "generic".to_string(),
        kind: DetectorKind::Phase2Generic,
        keywords: keywords
            .iter()
            .map(|keyword| (*keyword).to_string())
            .collect(),
        min_len: Some(min_len),
        max_len: Some(512),
        entropy_policy_priority: Some(0),
        entropy_floor: vec![EntropyFloorBucket {
            max_len: None,
            floor: 0.0,
        }],
        entropy_low: Some(0.0),
        entropy_high: Some(4.5),
        entropy_very_high: Some(5.8),
        sensitive_path_entropy_very_high: Some(5.8),
        mixed_alnum_floor: Some(0.0),
        symbolic_entropy_floor: Some(3.5),
        second_half_entropy_floor: Some(2.5),
        mixed_alnum_min_len: Some(20),
        keyword_free_min_len: Some(20),
        bpe_enabled: Some(false),
        entropy_shapes: vec![EntropyShapeSpec::LowerDashAppPassword {
            entropy_floor: 3.9,
            group_count: 4,
            group_length: 4,
            special_min_length: 16,
        }],
        entropy_fallback: Some(EntropyFallbackMetadata {
            class: EntropyFallbackClass::Generic,
            id: format!("entropy-{id}"),
            name: format!("{id} entropy"),
            service: "generic".to_string(),
        }),
        ..Default::default()
    }
}

fn scan_with_owner_min_len(min_len: usize) -> Vec<String> {
    let detectors = vec![
        detector("custom-secret-owner", &[KEYWORD], min_len),
        detector("generic-secret", &["secret"], 8),
    ];
    active_policy_match_values(detectors, KEYWORD, &format!(r#"{KEYWORD} = "{VALUE}""#))
}

const CANONICAL_HEX_KEY: &str = "1868845451a4c85adb078195b768135b";

fn scan_custom_canonical_hex(policy: bool) -> Vec<String> {
    let mut owner = detector("custom-key-owner", &["custom_key"], 8);
    owner.patterns.clear();
    if policy {
        owner.canonical_hex_key_material = vec![CanonicalHexKeyMaterialSpec {
            lengths: vec![32],
            keywords: vec!["custom_key".into()],
            ..Default::default()
        }];
    }
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![owner, detector("generic-secret", &["secret"], 8)])
        .expect("compile custom canonical-hex policy corpus")
        .with_config(config);
    let chunk = Chunk {
        data: format!("custom_key = {CANONICAL_HEX_KEY}").into(),
        metadata: ChunkMetadata {
            source_type: "canonical-policy-probe".into(),
            path: Some("probe.conf".into()),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .into_iter()
        .filter(|finding| finding.credential.as_ref() == CANONICAL_HEX_KEY)
        .map(|finding| finding.credential.to_string())
        .collect()
}

#[test]
fn canonical_hex_admission_fails_closed_when_detector_policy_is_omitted() {
    assert!(
        scan_custom_canonical_hex(false).is_empty(),
        "a custom detector without canonical_hex_key_material must not inherit the old global hex-key lift"
    );
    assert_eq!(
        scan_custom_canonical_hex(true),
        vec![CANONICAL_HEX_KEY.to_string()],
        "the same detector must admit the exact value only after declaring its policy"
    );
}

#[test]
fn active_entropy_owner_without_metadata_fails_compilation() {
    let mut owner = detector("metadata-missing-owner", &["custom_secret"], 8);
    owner.entropy_fallback = None;
    let error =
        match CompiledScanner::compile(vec![owner, detector("generic-secret", &["secret"], 8)]) {
            Ok(_) => panic!("an active entropy owner without identity metadata must not compile"),
            Err(error) => error,
        };
    let message = error.to_string();
    assert!(
        message.contains("metadata-missing-owner")
            && message.contains("omits [detector.entropy_fallback]"),
        "compile must explain the missing detector-owned identity: {message}"
    );
}

fn scan_with_plausibility_policy(
    value: &str,
    symbolic_floor: f64,
    second_half_floor: f64,
    mixed_min_len: usize,
) -> Vec<String> {
    let mut owner = detector("plausibility-owner", &["custom_secret"], 8);
    owner.entropy_high = Some(8.0);
    owner.mixed_alnum_floor = Some(0.0);
    owner.symbolic_entropy_floor = Some(symbolic_floor);
    owner.second_half_entropy_floor = Some(second_half_floor);
    owner.mixed_alnum_min_len = Some(mixed_min_len);
    active_policy_match_values(
        vec![owner, detector("generic-secret", &["secret"], 8)],
        "custom_secret",
        &format!("custom_secret = \"{value}\""),
    )
}

#[test]
fn custom_symbolic_plausibility_floor_controls_assignment_admission() {
    let value = "1E1B3b4Ho$U4kYBi";
    let entropy = keyhog_scanner::entropy::shannon_entropy(value.as_bytes());
    assert!(entropy > 3.5 && entropy < 4.5, "fixture entropy: {entropy}");
    assert!(!scan_with_plausibility_policy(value, 4.5, 0.0, 8).contains(&value.to_string()));
    assert!(scan_with_plausibility_policy(value, 3.5, 0.0, 8).contains(&value.to_string()));
}

#[test]
fn custom_tail_entropy_floor_controls_assignment_admission() {
    let value = "A1b2C3d4E5f6G7h8aaaaaaaaaaaaaaaa";
    assert!(!scan_with_plausibility_policy(value, 0.0, 2.5, 8).contains(&value.to_string()));
    assert!(scan_with_plausibility_policy(value, 0.0, 0.0, 8).contains(&value.to_string()));
}

#[test]
fn custom_mixed_alnum_min_len_controls_assignment_admission() {
    let value = "A1b2C3d4E5f6G7h8";
    assert!(!scan_with_plausibility_policy(value, 0.0, 0.0, 20).contains(&value.to_string()));
    assert!(scan_with_plausibility_policy(value, 0.0, 0.0, 8).contains(&value.to_string()));
}

#[test]
fn malformed_entropy_fallback_metadata_fails_compilation() {
    let mut owner = detector("metadata-malformed-owner", &["custom_secret"], 8);
    owner.entropy_fallback = Some(EntropyFallbackMetadata {
        class: EntropyFallbackClass::Generic,
        id: "generic-secret".into(),
        name: String::new(),
        service: String::new(),
    });
    let error =
        match CompiledScanner::compile(vec![owner, detector("generic-secret", &["secret"], 8)]) {
            Ok(_) => panic!("malformed entropy fallback metadata must not compile"),
            Err(error) => error,
        };
    assert!(
        error
            .to_string()
            .contains("invalid entropy_fallback metadata"),
        "compile must explain malformed identity metadata: {error}"
    );
}

#[test]
fn custom_entropy_keyword_uses_the_active_corpus_owner() {
    assert!(
        scan_with_owner_min_len(64).is_empty(),
        "the custom owner's 64-byte minimum must suppress the shorter candidate"
    );
    let admitted = scan_with_owner_min_len(8);
    assert!(
        admitted.iter().any(|value| value == VALUE),
        "lowering the same active owner's minimum must admit the exact candidate: {admitted:?}"
    );
}

#[test]
fn overlapping_custom_keywords_use_declared_priority() {
    let mut lower_priority = detector("first-owner", &["custom-credential"], 64);
    lower_priority.entropy_policy_priority = Some(10);
    let mut higher_priority = detector("second-owner", &[KEYWORD], 8);
    higher_priority.entropy_policy_priority = Some(20);
    let detectors = vec![
        lower_priority,
        higher_priority,
        detector("generic-secret", &["secret"], 8),
    ];
    let matches =
        active_policy_match_values(detectors, KEYWORD, &format!(r#"{KEYWORD} = "{VALUE}""#));
    assert!(
        matches.iter().any(|value| value == VALUE),
        "the higher declared policy priority must win normalized overlap: {matches:?}"
    );
}

const ENTROPY_ONLY_KEYWORD: &str = "tenant_opaque_slot";
const WORD_LIKE_VALUE: &str = "CorrectHorseBatteryStaple!9";

fn entropy_only_owner(bpe_enabled: bool) -> DetectorSpec {
    let mut owner = detector("custom-secret-owner", &[ENTROPY_ONLY_KEYWORD], 8);
    owner.kind = DetectorKind::Regex;
    owner.max_len = None;
    owner.patterns = vec![PatternSpec {
        regex: "custom_owner_pattern_that_cannot_match_([0-9]{99})".to_string(),
        group: Some(1),
        ..Default::default()
    }];
    owner.entropy_policy_priority = Some(100);
    owner.bpe_enabled = Some(bpe_enabled);
    owner.bpe_max_bytes_per_token = bpe_enabled.then_some(2.3);
    owner
}

#[test]
fn phase2_owner_without_max_len_fails_scanner_construction() {
    let mut owner = detector("incomplete-phase2-owner", &["secret"], 8);
    owner.max_len = None;
    let error = match CompiledScanner::compile(vec![owner]) {
        Ok(_) => panic!("an incomplete phase-2 owner must not compile"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("max_len") && error.contains("incomplete-phase2-owner"),
        "construction error must name the detector and missing field: {error}"
    );
}

fn full_scan_findings(bpe_enabled: bool, backend: ScanBackend) -> Vec<(String, String, usize)> {
    let detectors = vec![
        entropy_only_owner(bpe_enabled),
        detector("generic-secret", &["secret"], 8),
    ];
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(detectors)
        .expect("compile custom generic corpus")
        .with_config(config);
    let chunk = Chunk {
        data: format!(r#"{ENTROPY_ONLY_KEYWORD} = "{WORD_LIKE_VALUE}""#).into(),
        metadata: ChunkMetadata::default(),
    };
    let mut findings = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .into_iter()
        .flatten()
        .map(|finding| {
            (
                finding.detector_id.to_string(),
                finding.credential.to_string(),
                finding.location.offset,
            )
        })
        .collect::<Vec<_>>();
    findings.sort_unstable();
    findings
}

fn full_scan_keyword_free_values(
    entropy_very_high: f64,
    path: &str,
    backend: ScanBackend,
) -> Vec<String> {
    let mut generic_secret = detector("generic-secret", &["secret"], 8);
    generic_secret.entropy_very_high = Some(entropy_very_high);
    let embedded_policy = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic-secret policy must load");
    let embedded_discount = embedded_policy
        .entropy_very_high
        .expect("generic-secret must declare entropy_very_high")
        - embedded_policy
            .sensitive_path_entropy_very_high
            .expect("generic-secret must declare sensitive path entropy policy");
    generic_secret.sensitive_path_entropy_very_high = Some(entropy_very_high - embedded_discount);
    generic_secret.keyword_free_min_len = Some(20);
    generic_secret.bpe_enabled = Some(false);
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    // Keep one nonmatching phase-1 detector so explicit Hyperscan and GPU
    // routes execute their real production paths before the shared entropy
    // fallback evaluates the keyword-free candidate.
    let scanner = CompiledScanner::compile(vec![generic_secret, entropy_only_owner(false)])
        .expect("compile detector-owned entropy threshold corpus")
        .with_config(config);
    assert!(
        scanner.warm_backend(backend),
        "backend {} must be usable for the detector-policy boundary matrix",
        backend.label()
    );
    let chunk = Chunk {
        data: format!("x:\"{KEYWORD_FREE_VALUE}\"").into(),
        metadata: ChunkMetadata {
            source_type: "detector-threshold-boundary".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner
        .scan_with_backend(&chunk, backend)
        .into_iter()
        .map(|finding| finding.credential.to_string())
        .collect()
}

#[test]
fn keyword_free_full_scan_uses_detector_owned_very_high_boundary() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    assert!(
        (entropy - 48_f64.log2()).abs() < 1e-12,
        "the boundary fixture must contain 48 equiprobable bytes"
    );
    let admitted = full_scan_keyword_free_values(entropy, "payload.yaml", ScanBackend::CpuFallback);
    assert!(
        admitted.iter().any(|value| value == KEYWORD_FREE_VALUE),
        "a candidate exactly at the detector TOML threshold must be admitted: {admitted:?}"
    );
    assert!(
        !full_scan_keyword_free_values(entropy + 0.001, "payload.yaml", ScanBackend::CpuFallback,)
            .iter()
            .any(|value| value == KEYWORD_FREE_VALUE),
        "raising only the detector TOML threshold above the candidate must suppress it"
    );
}

#[test]
fn sensitive_path_discount_is_relative_to_detector_owned_threshold() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    let generic_secret = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic-secret policy must load");
    let sensitive_discount = generic_secret
        .entropy_very_high
        .expect("generic-secret must declare entropy_very_high")
        - generic_secret
            .sensitive_path_entropy_very_high
            .expect("generic-secret must declare sensitive path entropy policy");
    assert!(
        full_scan_keyword_free_values(
            entropy + sensitive_discount,
            "secrets.yaml",
            ScanBackend::CpuFallback,
        )
        .iter()
        .any(|value| value == KEYWORD_FREE_VALUE),
        "the sensitive-path discount must admit the exact detector-relative boundary"
    );
    assert!(
        !full_scan_keyword_free_values(
            entropy + sensitive_discount + 0.001,
            "secrets.yaml",
            ScanBackend::CpuFallback,
        )
            .iter()
            .any(|value| value == KEYWORD_FREE_VALUE),
        "the sensitive-path discount must not replace a stricter detector threshold with a global constant"
    );
}

#[test]
fn entropy_fallback_identity_comes_from_active_detector_policy() {
    let mut generic_secret = detector("generic-secret", &["secret"], 8);
    generic_secret.entropy_fallback = Some(EntropyFallbackMetadata {
        class: EntropyFallbackClass::Generic,
        id: "entropy-custom-policy".into(),
        name: "Custom Policy Entropy".into(),
        service: "custom-service".into(),
    });
    generic_secret.keyword_free_min_len = Some(20);
    generic_secret.bpe_enabled = Some(false);
    generic_secret.sensitive_path_entropy_very_high = Some(5.5);
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![generic_secret, entropy_only_owner(false)])
        .expect("compile detector-owned entropy metadata corpus")
        .with_config(config);
    let chunk = Chunk {
        data: format!("x:\"{KEYWORD_FREE_VALUE}\"").into(),
        metadata: ChunkMetadata {
            source_type: "detector-threshold-boundary".into(),
            path: Some("secrets.yaml".into()),
            ..Default::default()
        },
    };
    let finding = scanner
        .scan_with_backend(&chunk, ScanBackend::CpuFallback)
        .into_iter()
        .find(|finding| finding.credential.as_ref() == KEYWORD_FREE_VALUE)
        .expect("custom entropy metadata corpus must emit the keyword-free candidate");
    assert_eq!(finding.detector_id.as_ref(), "entropy-custom-policy");
    assert_eq!(finding.detector_name.as_ref(), "Custom Policy Entropy");
    assert_eq!(finding.service.as_ref(), "custom-service");
}

#[test]
fn lower_dash_entropy_exception_is_owned_by_the_active_detector_shape_policy() {
    let secret = "kp4q-x7rm-2sn5-tb8v";
    let mut detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load");
    let generic_keyword_secret = detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-keyword-secret")
        .expect("generic-keyword-secret policy must be present");
    generic_keyword_secret.entropy_shapes =
        vec![keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
            entropy_floor: 8.0,
            group_count: 4,
            group_length: 4,
            special_min_length: 16,
        }];

    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner_with_restrictive_shape = CompiledScanner::compile(detectors.clone())
        .expect("restrictive detector shape corpus must compile")
        .with_config(config.clone());
    let chunk = Chunk {
        data: format!("{secret}\n").into(),
        metadata: ChunkMetadata {
            path: Some("notes/sufficiency-probe.txt".into()),
            ..Default::default()
        },
    };
    assert!(
        scanner_with_restrictive_shape
            .scan(&chunk)
            .iter()
            .all(|finding| finding.credential.as_ref() != secret),
        "raising the detector-owned shape floor must remove the isolated exception"
    );

    let generic_keyword_secret = detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-keyword-secret")
        .expect("generic-keyword-secret policy must be present");
    generic_keyword_secret.entropy_shapes =
        vec![keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
            entropy_floor: 3.9,
            group_count: 4,
            group_length: 4,
            special_min_length: 16,
        }];
    detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-secret")
        .expect("generic-secret policy must be present")
        .entropy_shapes = generic_keyword_secret.entropy_shapes.clone();
    let scanner_with_shape = CompiledScanner::compile(detectors)
        .expect("detector-owned shape policy corpus must compile")
        .with_config(config);
    let with_shape = scanner_with_shape.scan(&chunk);
    assert!(
        with_shape
            .iter()
            .any(|finding| finding.credential.as_ref() == secret),
        "declaring the detector-owned shape must admit the exact structural exception: {with_shape:?}"
    );
}

#[cfg(feature = "gpu")]
#[test]
fn detector_owned_very_high_boundary_is_exact_on_every_accelerated_backend() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    let generic_secret = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic-secret policy must load");
    let sensitive_discount = generic_secret
        .entropy_very_high
        .expect("generic-secret must declare entropy_very_high")
        - generic_secret
            .sensitive_path_entropy_very_high
            .expect("generic-secret must declare sensitive path entropy policy");
    for backend in [
        ScanBackend::SimdCpu,
        ScanBackend::GpuCuda,
        ScanBackend::GpuWgpu,
    ] {
        let normal = full_scan_keyword_free_values(entropy, "payload.yaml", backend);
        assert!(
            normal.iter().any(|value| value == KEYWORD_FREE_VALUE),
            "{} must admit the exact detector-owned boundary: {normal:?}",
            backend.label()
        );
        assert!(
            !full_scan_keyword_free_values(entropy + 0.001, "payload.yaml", backend)
                .iter()
                .any(|value| value == KEYWORD_FREE_VALUE),
            "{} must reject above the detector-owned boundary",
            backend.label()
        );
        assert!(
            full_scan_keyword_free_values(entropy + sensitive_discount, "secrets.yaml", backend,)
                .iter()
                .any(|value| value == KEYWORD_FREE_VALUE),
            "{} must preserve the detector-relative sensitive-path discount",
            backend.label()
        );
    }
}

#[test]
fn custom_owner_bpe_policy_reaches_the_full_scan() {
    assert!(
        !full_scan_findings(true, ScanBackend::CpuFallback)
            .iter()
            .any(|(_, found, _)| found == WORD_LIKE_VALUE),
        "the active owner's enabled BPE policy must reject language-like material"
    );
    let disabled = full_scan_findings(false, ScanBackend::CpuFallback);
    assert!(
        disabled
            .iter()
            .any(|(_, found, _)| found == WORD_LIKE_VALUE),
        "disabling BPE on the same active owner must admit the exact value: {disabled:?}"
    );

    let probe = CompiledScanner::compile(vec![
        entropy_only_owner(false),
        detector("generic-secret", &["secret"], 8),
    ])
    .expect("compile parity probe");
    if probe.warm_backend(ScanBackend::SimdCpu) {
        assert_eq!(
            disabled,
            full_scan_findings(false, ScanBackend::SimdCpu),
            "CPU and Hyperscan must preserve the exact detector, credential, and offset"
        );
    }
    #[cfg(feature = "gpu")]
    {
        assert!(
            probe.warm_backend(ScanBackend::GpuWgpu),
            "GPU-enabled parity runs require a usable accelerator"
        );
        assert_eq!(
            disabled,
            full_scan_findings(false, ScanBackend::GpuWgpu),
            "CPU and GPU must preserve the exact detector, credential, and offset"
        );
    }
}

#[test]
fn shipped_policy_priorities_preserve_semantic_families_and_synthetic_paths() {
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("load embedded detector corpus");
    for keyword in ["password", "passwd", "pwd", "DB_PASSWORD"] {
        assert_eq!(
            active_policy_owner_id(&detectors, keyword).as_deref(),
            Some("generic-password"),
            "password-family policy must not be captured by a broader or regex-only detector"
        );
    }
    assert_eq!(
        active_policy_owner_id(&detectors, "api_key").as_deref(),
        Some("generic-api-key")
    );
    assert_eq!(
        active_policy_owner_id(&detectors, "passphrase").as_deref(),
        Some("generic-keyword-secret")
    );
    assert_eq!(
        active_policy_owner_id(&detectors, "none (isolated-token)").as_deref(),
        Some("generic-keyword-secret")
    );
    assert_eq!(
        active_policy_owner_id(&detectors, "none (high-entropy)").as_deref(),
        Some("generic-secret")
    );
    assert_eq!(
        active_policy_owner_id(&detectors, "bearer").as_deref(),
        Some("generic-api-key"),
        "an unclaimed Tier-A keyword must retain the compatibility policy"
    );
}
