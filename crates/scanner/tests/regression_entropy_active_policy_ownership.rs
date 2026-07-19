use keyhog_core::{
    CanonicalHexKeyMaterialSpec, Chunk, ChunkMetadata, DetectorKind,
    DetectorPlausibilityPolicySpec, DetectorSpec, EntropyDetectionRole, EntropyFallbackClass,
    EntropyFallbackMetadata, EntropyFloorBucket, EntropyShapeSpec, PatternSpec,
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
        plausibility: Some(DetectorPlausibilityPolicySpec {
            mixed_alnum_floor: 0.0,
            symbolic_entropy_floor: 3.5,
            second_half_entropy_floor: 2.5,
            second_half_min_len: 17,
            unique_chars_min_len: 17,
            min_unique_chars: 8,
            unanchored_hex_max_len: 10,
            identical_char_max_len: 4,
            structured_dotted_min_len: 40,
            mixed_alnum_min_len: 20,
            isolated_mixed_entropy_floor: 3.65,
            isolated_symbolic_min_len: 18,
            isolated_symbolic_min_symbols: 2,
            isolated_symbolic_requires_non_underscore: true,
            isolated_alpha_only_min_symbols: 3,
            isolated_alpha_only_min_alpha_ratio: 0.5,
            isolated_colon_left_min_len: 20,
            isolated_colon_right_min_len: 16,
            leading_slash_base64_entropy_floor: 4.8,
            leading_slash_base64_min_len: 40,
            keyword_free_operator_margin: None,
            reject_repeated_blocks: true,
            allow_alphabetic_credential: true,
            reject_program_identifiers: true,
            reject_source_symbol_identifiers: true,
            reject_dash_segmented_alnum: true,
        }),
        keyword_free_min_len: Some(20),
        bpe_enabled: Some(false),
        entropy_shapes: vec![EntropyShapeSpec {
            charset: keyhog_core::ShapeCharset::LowerAlnum,
            entropy_floor: 3.9,
            special_min_length: 16,
            grouping: Some(keyhog_core::ShapeGrouping {
                group_count: 4,
                group_length: 4,
                separator: '-',
            }),
            require_mixed_case: false,
            require_digit: false,
            min_symbols: 0,
            require_non_hex_alpha: true,
            require_group_alpha_digit: true,
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

fn full_scan_with_public_identifier_marker(marker_enabled: bool) -> Vec<String> {
    let mut owner = detector("public-marker-owner", &["secret"], 8);
    owner.entropy_roles = vec![EntropyDetectionRole::KeywordFree];
    owner
        .plausibility
        .as_mut()
        .expect("keyword-free owner declares plausibility")
        .keyword_free_operator_margin = Some(1.0);
    owner.bpe_enabled = Some(false);
    owner.sensitive_path_entropy_very_high = Some(5.5);
    if marker_enabled {
        owner.public_identifier_assignment_markers = vec!["PUBLIC_ADDR =".into()];
    }
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![owner])
        .expect("compile detector-local public identifier marker corpus")
        .with_config(config);
    let chunk = Chunk {
        data: format!("PUBLIC_ADDR = \"{KEYWORD_FREE_VALUE}\"").into(),
        metadata: ChunkMetadata {
            path: Some("secrets.yaml".into()),
            ..Default::default()
        },
    };
    scanner
        .scan(&chunk)
        .into_iter()
        .filter(|finding| {
            finding.detector_id.as_ref() == "entropy-public-marker-owner"
                && finding.credential.as_ref() == KEYWORD_FREE_VALUE
        })
        .map(|finding| finding.credential.to_string())
        .collect()
}

#[test]
fn public_identifier_assignment_suppression_is_detector_local() {
    assert_eq!(
        full_scan_with_public_identifier_marker(false),
        vec![KEYWORD_FREE_VALUE.to_string()],
        "omitting the marker must leave the detector's candidate eligible"
    );
    assert!(
        full_scan_with_public_identifier_marker(true).is_empty(),
        "declaring the exact marker in the owning detector must suppress the same candidate"
    );
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

#[test]
fn active_entropy_owner_with_multiple_shapes_fails_instead_of_ignoring_policy() {
    let mut owner = detector("ambiguous-shape-owner", &["custom_secret"], 8);
    owner.entropy_shapes.push(owner.entropy_shapes[0]);
    let error = CompiledScanner::compile(vec![owner])
        .err()
        .expect("multiple detector-owned shapes must not compile ambiguously");
    assert!(
        error.to_string().contains(
            "ambiguous-shape-owner\" owns entropy detection and must declare exactly one"
        ),
        "compile error must identify the detector and exact cardinality contract: {error}"
    );
}

fn plausibility_owner(
    symbolic_floor: f64,
    second_half_floor: f64,
    mixed_min_len: usize,
    reject_source_symbol_identifiers: bool,
) -> DetectorSpec {
    let mut owner = detector("plausibility-owner", &["custom_secret"], 8);
    owner.entropy_high = Some(8.0);
    owner.entropy_very_high = Some(8.0);
    owner.sensitive_path_entropy_very_high = Some(8.0);
    owner.plausibility = Some(DetectorPlausibilityPolicySpec {
        mixed_alnum_floor: 0.0,
        symbolic_entropy_floor: symbolic_floor,
        second_half_entropy_floor: second_half_floor,
        second_half_min_len: 17,
        unique_chars_min_len: 17,
        min_unique_chars: 8,
        unanchored_hex_max_len: 10,
        identical_char_max_len: 4,
        structured_dotted_min_len: 40,
        mixed_alnum_min_len: mixed_min_len,
        isolated_mixed_entropy_floor: 3.65,
        isolated_symbolic_min_len: 18,
        isolated_symbolic_min_symbols: 2,
        isolated_symbolic_requires_non_underscore: true,
        isolated_alpha_only_min_symbols: 3,
        isolated_alpha_only_min_alpha_ratio: 0.5,
        isolated_colon_left_min_len: 20,
        isolated_colon_right_min_len: 16,
        leading_slash_base64_entropy_floor: 4.8,
        leading_slash_base64_min_len: 40,
        keyword_free_operator_margin: None,
        reject_repeated_blocks: true,
        allow_alphabetic_credential: true,
        reject_program_identifiers: true,
        reject_source_symbol_identifiers,
        reject_dash_segmented_alnum: true,
    });
    owner
}

fn scan_with_plausibility_policy(
    value: &str,
    symbolic_floor: f64,
    second_half_floor: f64,
    mixed_min_len: usize,
    reject_source_symbol_identifiers: bool,
) -> Vec<String> {
    let owner = plausibility_owner(
        symbolic_floor,
        second_half_floor,
        mixed_min_len,
        reject_source_symbol_identifiers,
    );
    scan_assignment_with_owner(value, owner)
}

fn scan_assignment_with_owner(value: &str, owner: DetectorSpec) -> Vec<String> {
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
    assert!(!scan_with_plausibility_policy(value, 4.5, 0.0, 8, false).contains(&value.to_string()));
    assert!(scan_with_plausibility_policy(value, 3.5, 0.0, 8, false).contains(&value.to_string()));
}

#[test]
fn custom_tail_entropy_floor_controls_assignment_admission() {
    let value = "A1b2C3d4E5f6G7h8aaaaaaaaaaaaaaaa";
    assert!(!scan_with_plausibility_policy(value, 0.0, 2.5, 8, false).contains(&value.to_string()));
    assert!(scan_with_plausibility_policy(value, 0.0, 0.0, 8, false).contains(&value.to_string()));
}

#[test]
fn custom_mixed_alnum_min_len_controls_assignment_admission() {
    let value = "A1b2C3d4E5f6G7h8";
    assert!(!scan_with_plausibility_policy(value, 0.0, 0.0, 20, false).contains(&value.to_string()));
    assert!(scan_with_plausibility_policy(value, 0.0, 0.0, 8, false).contains(&value.to_string()));
}

#[test]
fn custom_source_symbol_rejection_controls_assignment_admission() {
    let value = "ClientSecretConfigValue2";
    assert!(scan_with_plausibility_policy(value, 0.0, 0.0, 8, true).is_empty());
    assert!(scan_with_plausibility_policy(value, 0.0, 0.0, 8, false).contains(&value.to_string()));
}

#[test]
fn custom_tail_and_diversity_boundaries_control_assignment_admission() {
    let tail_heavy = "A1b2C3d4E5f6G7h8aaaaaaaaaaaaaaaa";
    let mut strict_tail = plausibility_owner(0.0, 2.5, 8, false);
    assert!(scan_assignment_with_owner(tail_heavy, strict_tail.clone()).is_empty());
    strict_tail
        .plausibility
        .as_mut()
        .expect("test owner declares plausibility")
        .second_half_min_len = tail_heavy.len() + 1;
    assert!(scan_assignment_with_owner(tail_heavy, strict_tail).contains(&tail_heavy.to_string()));

    let nine_distinct = "A1A2A3A4A5A6A7A8A";
    let mut strict_diversity = plausibility_owner(0.0, 0.0, 8, false);
    let policy = strict_diversity
        .plausibility
        .as_mut()
        .expect("test owner declares plausibility");
    policy.reject_repeated_blocks = false;
    policy.min_unique_chars = 10;
    assert!(scan_assignment_with_owner(nine_distinct, strict_diversity.clone()).is_empty());
    strict_diversity
        .plausibility
        .as_mut()
        .expect("test owner declares plausibility")
        .min_unique_chars = 9;
    assert!(scan_assignment_with_owner(nine_distinct, strict_diversity)
        .contains(&nine_distinct.to_string()));
}

fn full_scan_plausibility_findings(
    value: &str,
    reject_source_symbol_identifiers: bool,
    backend: ScanBackend,
) -> Vec<(String, String, usize)> {
    let owner = plausibility_owner(0.0, 0.0, 8, reject_source_symbol_identifiers);
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![owner, detector("generic-secret", &["secret"], 8)])
        .expect("compile source-symbol policy corpus")
        .with_config(config);
    let chunk = Chunk {
        data: format!("custom_secret = \"{value}\"").into(),
        metadata: ChunkMetadata {
            path: Some("policy_probe.rs".into()),
            ..Default::default()
        },
    };
    let mut findings = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .into_iter()
        .flatten()
        .filter(|finding| finding.credential.as_ref() == value)
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

fn full_scan_bare_auth_findings(
    value: &str,
    symbolic_floor: f64,
    second_half_floor: f64,
    reject_repeated_blocks: bool,
    backend: ScanBackend,
) -> Vec<(String, String, usize)> {
    let mut owner = plausibility_owner(symbolic_floor, second_half_floor, 8, false);
    owner.keywords = vec!["auth".into()];
    owner
        .plausibility
        .as_mut()
        .expect("bare-auth owner declares plausibility")
        .reject_repeated_blocks = reject_repeated_blocks;
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![owner, entropy_only_owner(false)])
        .expect("compile bare-auth detector policy corpus")
        .with_config(config);
    assert!(
        scanner.warm_backend(backend),
        "backend {} must be usable for bare-auth policy coverage",
        backend.label()
    );
    let chunk = Chunk {
        data: format!("auth = \"{value}\"").into(),
        metadata: ChunkMetadata {
            path: Some("policy_probe.rs".into()),
            ..Default::default()
        },
    };
    let mut findings = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .into_iter()
        .flatten()
        .filter(|finding| finding.credential.as_ref() == value)
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

#[test]
fn bare_auth_bridge_uses_the_active_detector_symbolic_floor() {
    let value = "1E1B3b4Ho$U4kYBi";
    let entropy = keyhog_scanner::entropy::shannon_entropy(value.as_bytes());
    assert!(entropy > 3.5 && entropy < 4.5, "fixture entropy: {entropy}");
    assert!(
        full_scan_bare_auth_findings(value, 4.5, 0.0, true, ScanBackend::CpuFallback).is_empty()
    );
    assert_eq!(
        full_scan_bare_auth_findings(value, 3.5, 0.0, true, ScanBackend::CpuFallback),
        vec![("plausibility-owner".into(), value.into(), 8)]
    );
    let alphanumeric = full_scan_bare_auth_findings(
        "A1b2C3d4E5f6G7h8",
        0.0,
        0.0,
        false,
        ScanBackend::CpuFallback,
    );
    assert!(
        alphanumeric
            .iter()
            .all(|finding| finding.0 != "plausibility-owner"),
        "mixed-alphanumeric policy cannot bypass bare auth's structural symbol requirement"
    );
}

#[test]
fn bare_auth_owner_without_plausibility_policy_fails_construction() {
    let mut owner = plausibility_owner(0.0, 0.0, 8, false);
    owner.keywords = vec!["auth".into()];
    owner.plausibility = None;
    let error = match CompiledScanner::compile(vec![owner, entropy_only_owner(false)]) {
        Ok(_) => panic!("a bare-auth owner without compiled plausibility policy must not compile"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("plausibility-owner") && error.contains("omits [detector.plausibility]"),
        "construction error must identify the missing owner policy: {error}"
    );
}

#[test]
fn bare_auth_bridge_uses_tail_and_repetition_policy_from_the_same_owner() {
    // Low-randomness without a filler run or repeated-block mask, so the
    // detector-owned second-half floor is the only changing decision.
    let tailed = "1E1B3b4Ho$U4kYBiabacabadabacabae";
    assert!(
        full_scan_bare_auth_findings(tailed, 0.0, 2.5, false, ScanBackend::CpuFallback).is_empty(),
        "the detector-owned second-half floor must reject a low-randomness tail"
    );
    assert!(
        !full_scan_bare_auth_findings(tailed, 0.0, 0.0, false, ScanBackend::CpuFallback).is_empty(),
        "lowering only the detector-owned tail floor must admit the same value"
    );

    let repeated = "Ab1$Cd2%Ab1$Cd2%Ab1$Cd2%";
    assert!(
        full_scan_bare_auth_findings(repeated, 0.0, 0.0, true, ScanBackend::CpuFallback).is_empty(),
        "the detector-owned repeated-block gate must reject the periodic value"
    );
    assert!(
        !full_scan_bare_auth_findings(repeated, 0.0, 0.0, false, ScanBackend::CpuFallback)
            .is_empty(),
        "disabling only the detector-owned repeated-block gate must admit the same value"
    );
}

#[cfg(feature = "gpu")]
#[test]
fn bare_auth_detector_policy_is_exact_on_every_accelerated_backend() {
    let value = "1E1B3b4Ho$U4kYBi";
    let expected = full_scan_bare_auth_findings(value, 3.5, 0.0, true, ScanBackend::CpuFallback);
    for backend in [
        ScanBackend::SimdCpu,
        ScanBackend::GpuCuda,
        ScanBackend::GpuWgpu,
    ] {
        assert_eq!(
            full_scan_bare_auth_findings(value, 3.5, 0.0, true, backend),
            expected,
            "{} must preserve the active detector's bare-auth policy",
            backend.label()
        );
        assert!(
            full_scan_bare_auth_findings(value, 4.5, 0.0, true, backend).is_empty(),
            "{} must reject above the active detector's bare-auth boundary",
            backend.label()
        );
    }
}

#[test]
fn source_symbol_policy_reaches_every_full_backend_plan() {
    let value = "ClientSecretConfigValue2";
    assert!(full_scan_plausibility_findings(value, true, ScanBackend::CpuFallback).is_empty());
    let admitted = full_scan_plausibility_findings(value, false, ScanBackend::CpuFallback);
    assert_eq!(
        admitted,
        vec![("plausibility-owner".to_string(), value.to_string(), 17,)]
    );

    let probe = CompiledScanner::compile(vec![
        plausibility_owner(0.0, 0.0, 8, false),
        detector("generic-secret", &["secret"], 8),
    ])
    .expect("compile source-symbol backend probe");
    if probe.warm_backend(ScanBackend::SimdCpu) {
        assert_eq!(
            admitted,
            full_scan_plausibility_findings(value, false, ScanBackend::SimdCpu)
        );
    }
    #[cfg(feature = "gpu")]
    for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
        assert!(
            probe.warm_backend(backend),
            "{} must be usable on a GPU parity host",
            backend.label()
        );
        assert_eq!(
            admitted,
            full_scan_plausibility_findings(value, false, backend),
            "{} must preserve detector-owned source-symbol policy",
            backend.label()
        );
    }
}

fn scan_isolated_with_policy(
    value: &str,
    mixed_entropy_floor: f64,
    symbolic_min_len: usize,
    colon_left_min_len: usize,
    colon_right_min_len: usize,
    leading_slash_base64_entropy_floor: f64,
) -> Vec<String> {
    scan_isolated_with_symbol_policy(
        value,
        mixed_entropy_floor,
        symbolic_min_len,
        2,
        true,
        colon_left_min_len,
        colon_right_min_len,
        leading_slash_base64_entropy_floor,
    )
}

#[allow(clippy::too_many_arguments)]
fn scan_isolated_with_symbol_policy(
    value: &str,
    mixed_entropy_floor: f64,
    symbolic_min_len: usize,
    symbolic_min_symbols: usize,
    symbolic_requires_non_underscore: bool,
    colon_left_min_len: usize,
    colon_right_min_len: usize,
    leading_slash_base64_entropy_floor: f64,
) -> Vec<String> {
    scan_isolated_with_policy_mutation(value, |policy| {
        policy.isolated_mixed_entropy_floor = mixed_entropy_floor;
        policy.isolated_symbolic_min_len = symbolic_min_len;
        policy.isolated_symbolic_min_symbols = symbolic_min_symbols;
        policy.isolated_symbolic_requires_non_underscore = symbolic_requires_non_underscore;
        policy.isolated_colon_left_min_len = colon_left_min_len;
        policy.isolated_colon_right_min_len = colon_right_min_len;
        policy.leading_slash_base64_entropy_floor = leading_slash_base64_entropy_floor;
    })
}

fn scan_isolated_with_policy_mutation(
    value: &str,
    mutate: impl FnOnce(&mut DetectorPlausibilityPolicySpec),
) -> Vec<String> {
    scan_isolated_with_policy_mutation_and_threshold(value, 4.0, mutate)
}

fn scan_isolated_with_policy_mutation_and_threshold(
    value: &str,
    entropy_threshold: f64,
    mutate: impl FnOnce(&mut DetectorPlausibilityPolicySpec),
) -> Vec<String> {
    let mut owner = detector("isolated-policy-owner", &["secret"], 8);
    owner.entropy_roles = vec![EntropyDetectionRole::IsolatedBare];
    owner.entropy_high = Some(entropy_threshold);
    let policy = owner
        .plausibility
        .as_mut()
        .expect("test entropy owner must declare plausibility");
    mutate(policy);
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.entropy_threshold = entropy_threshold;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![owner])
        .expect("compile isolated detector-policy corpus")
        .with_config(config);
    let chunk = Chunk {
        data: value.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "isolated-policy-probe".into(),
            path: Some("probe.txt".into()),
            ..Default::default()
        },
    };
    scanner
        .scan_with_backend(&chunk, ScanBackend::CpuFallback)
        .into_iter()
        .filter(|finding| finding.credential.as_ref() == value)
        .map(|finding| finding.credential.to_string())
        .collect()
}

#[cfg(feature = "gpu")]
#[test]
fn isolated_shape_boundaries_are_exact_on_every_accelerated_backend() {
    let value = "a3f8b2c9d1e07546ABCD";
    let chunk = Chunk {
        data: value.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "isolated-policy-parity".into(),
            path: Some("probe.txt".into()),
            ..Default::default()
        },
    };
    let compile = |unanchored_hex_max_len| {
        let mut detectors = keyhog_core::embedded_detector_specs().to_vec();
        let owner = detectors
            .iter_mut()
            .find(|detector| detector.id == "generic-keyword-secret")
            .expect("embedded isolated-bare owner");
        owner
            .plausibility
            .as_mut()
            .expect("isolated-bare owner declares plausibility")
            .unanchored_hex_max_len = unanchored_hex_max_len;
        let mut config = ScannerConfig::default();
        config.entropy_enabled = true;
        config.entropy_in_source_files = true;
        config.entropy_threshold = 3.0;
        config.min_confidence = 0.0;
        CompiledScanner::compile(detectors)
            .expect("compile embedded detector-policy parity corpus")
            .with_config(config)
    };
    let admitted = compile(value.len());
    let rejected = compile(value.len() - 1);
    let exact = |scanner: &CompiledScanner, backend| {
        scanner
            .scan_with_backend(&chunk, backend)
            .into_iter()
            .filter(|finding| finding.credential.as_ref() == value)
            .map(|finding| {
                (
                    finding.detector_id.to_string(),
                    finding.credential.to_string(),
                )
            })
            .collect::<Vec<_>>()
    };
    let expected = exact(&admitted, ScanBackend::CpuFallback);
    assert_eq!(expected, vec![("entropy-token".into(), value.into())]);

    for backend in [
        ScanBackend::SimdCpu,
        ScanBackend::GpuCuda,
        ScanBackend::GpuWgpu,
    ] {
        assert!(
            admitted.warm_backend(backend),
            "{} must be usable on a GPU parity host",
            backend.label()
        );
        assert!(rejected.warm_backend(backend));
        assert_eq!(
            exact(&admitted, backend),
            expected,
            "{} must preserve detector-owned unanchored-hex admission",
            backend.label()
        );
        assert!(
            exact(&rejected, backend).is_empty(),
            "{} must preserve the detector-owned rejection boundary",
            backend.label()
        );
    }
}

#[test]
fn isolated_candidate_floors_are_owned_by_the_active_detector() {
    let mixed = "Ab1_Cd2_Ef3_Gh4_Ij5x";
    assert!(scan_isolated_with_policy(mixed, 3.9, 18, 20, 16, 4.8).contains(&mixed.to_string()));
    assert!(scan_isolated_with_policy(mixed, 4.0, 18, 20, 16, 4.8).is_empty());

    let symbolic = "Xzqk-pvbg-wmjz-rql";
    assert!(
        scan_isolated_with_policy(symbolic, 3.65, 18, 20, 16, 4.8).contains(&symbolic.to_string())
    );
    assert!(scan_isolated_with_policy(symbolic, 3.65, 19, 20, 16, 4.8).is_empty());

    let mixed_symbolic = "BadCbc0#-DE&1$FA";
    assert!(
        scan_isolated_with_policy(mixed_symbolic, 3.65, 16, 20, 16, 4.8)
            .contains(&mixed_symbolic.to_string())
    );
    assert!(scan_isolated_with_policy(mixed_symbolic, 3.65, 17, 20, 16, 4.8).is_empty());
    assert!(
        scan_isolated_with_symbol_policy(mixed_symbolic, 3.65, 16, 4, true, 20, 16, 4.8)
            .contains(&mixed_symbolic.to_string())
    );
    assert!(
        scan_isolated_with_symbol_policy(mixed_symbolic, 3.65, 16, 5, true, 20, 16, 4.8).is_empty()
    );

    let underscore_symbolic = "Ab1_Cd2_Ef3_Gh45";
    assert!(
        scan_isolated_with_symbol_policy(underscore_symbolic, 8.0, 16, 2, true, 20, 16, 4.8)
            .is_empty()
    );
    assert!(
        scan_isolated_with_symbol_policy(underscore_symbolic, 8.0, 16, 2, false, 20, 16, 4.8)
            .contains(&underscore_symbolic.to_string())
    );

    let colon = "abcdefghij0123456789:klmnopqr01234567";
    assert!(scan_isolated_with_policy(colon, 3.65, 18, 20, 16, 4.8).contains(&colon.to_string()));
    assert!(scan_isolated_with_policy(colon, 3.65, 18, 21, 17, 4.8).is_empty());

    let slash_base64 = "/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGh==";
    assert!(
        scan_isolated_with_policy(slash_base64, 3.65, 18, 20, 16, 5.2)
            .contains(&slash_base64.to_string())
    );
    assert!(scan_isolated_with_policy(slash_base64, 3.65, 18, 20, 16, 5.3).is_empty());
}

#[test]
fn isolated_length_boundaries_are_owned_by_the_active_detector() {
    let dotted = "MTIzNDU2Nzg5MDEyMzQ1Njc4.Oabc12.xYz0123456789abcDEFghijk_lmnop";
    let dotted_len = dotted.len();
    assert!(scan_isolated_with_policy_mutation(dotted, |policy| {
        policy.structured_dotted_min_len = dotted_len;
    })
    .contains(&dotted.to_string()));
    assert!(scan_isolated_with_policy_mutation(dotted, |policy| {
        policy.structured_dotted_min_len = dotted_len + 1;
    })
    .is_empty());

    let slash_base64 = "/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCdEfGh==";
    let slash_len = slash_base64.len();
    assert!(scan_isolated_with_policy_mutation(slash_base64, |policy| {
        policy.leading_slash_base64_entropy_floor = 5.2;
        policy.leading_slash_base64_min_len = slash_len;
    })
    .contains(&slash_base64.to_string()));
    assert!(scan_isolated_with_policy_mutation(slash_base64, |policy| {
        policy.leading_slash_base64_entropy_floor = 5.2;
        policy.leading_slash_base64_min_len = slash_len + 1;
    })
    .is_empty());

    let unanchored_hex = "a3f8b2c9d1e07546ABCD";
    assert!(
        scan_isolated_with_policy_mutation_and_threshold(unanchored_hex, 3.0, |policy| policy
            .unanchored_hex_max_len =
            unanchored_hex.len(),)
        .contains(&unanchored_hex.to_string())
    );
    assert!(
        scan_isolated_with_policy_mutation_and_threshold(unanchored_hex, 3.0, |policy| policy
            .unanchored_hex_max_len =
            unanchored_hex.len() - 1,)
        .is_empty()
    );
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
    owner.patterns = vec![PatternSpec {
        regex: "custom_owner_pattern_that_cannot_match_([0-9]{99})".to_string(),
        group: Some(1),
        required_literals: Vec::new(),
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

#[test]
fn regex_entropy_owner_without_max_len_fails_scanner_construction() {
    let mut owner = entropy_only_owner(false);
    owner.id = "incomplete-regex-owner".into();
    owner.max_len = None;
    let error = match CompiledScanner::compile(vec![owner]) {
        Ok(_) => panic!("an incomplete regex entropy owner must not compile"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("max_len") && error.contains("incomplete-regex-owner"),
        "construction error must name the detector and missing field: {error}"
    );
}

#[test]
fn regex_entropy_owner_compiles_its_generic_assignment_generator() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.entropy_enabled = false;
    let scanner = CompiledScanner::compile(vec![entropy_only_owner(false)])
        .expect("compile regex-only generic assignment corpus")
        .with_config(config);
    let chunk = Chunk {
        data: format!(r#"{ENTROPY_ONLY_KEYWORD} = "{VALUE}""#).into(),
        metadata: ChunkMetadata::default(),
    };
    let findings = scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .filter(|finding| finding.credential.as_ref() == VALUE)
        .map(|finding| finding.detector_id.to_string())
        .collect::<Vec<_>>();
    assert_eq!(findings, vec!["custom-secret-owner"]);
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
    keyword_free_operator_margin: f64,
    path: &str,
    backend: ScanBackend,
) -> Vec<String> {
    let mut keyword_free_owner = detector("custom-keyword-free-owner", &["secret"], 8);
    keyword_free_owner.entropy_roles = vec![EntropyDetectionRole::KeywordFree];
    keyword_free_owner
        .plausibility
        .as_mut()
        .expect("keyword-free owner declares plausibility")
        .keyword_free_operator_margin = Some(keyword_free_operator_margin);
    keyword_free_owner.entropy_very_high = Some(entropy_very_high);
    keyword_free_owner.entropy_high = Some(entropy_very_high.min(4.5));
    let embedded_policy = keyhog_core::detector_spec_by_id("generic-secret")
        .expect("embedded generic-secret policy must load");
    let embedded_discount = embedded_policy
        .entropy_very_high
        .expect("generic-secret must declare entropy_very_high")
        - embedded_policy
            .sensitive_path_entropy_very_high
            .expect("generic-secret must declare sensitive path entropy policy");
    keyword_free_owner.sensitive_path_entropy_very_high =
        Some(entropy_very_high - embedded_discount);
    keyword_free_owner.keyword_free_min_len = Some(20);
    keyword_free_owner.bpe_enabled = Some(false);
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    // Keep one nonmatching phase-1 detector so explicit Hyperscan and GPU
    // routes execute their real production paths before the shared entropy
    // fallback evaluates the keyword-free candidate.
    let scanner = CompiledScanner::compile(vec![keyword_free_owner, entropy_only_owner(false)])
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
fn keyword_free_margin_contract_rejects_incomplete_custom_corpora() {
    let mut missing = detector("missing-keyword-free-margin", &["secret"], 8);
    missing.entropy_roles = vec![EntropyDetectionRole::KeywordFree];
    let missing_error = CompiledScanner::compile(vec![missing])
        .err()
        .expect("a keyword-free owner without its margin must fail compilation")
        .to_string();
    assert!(
        missing_error.contains("claims entropy role `keyword-free`")
            && missing_error.contains("omits plausibility.keyword_free_operator_margin"),
        "unexpected missing-margin error: {missing_error}"
    );

    let mut misplaced = detector("misplaced-keyword-free-margin", &["secret"], 8);
    misplaced
        .plausibility
        .as_mut()
        .expect("entropy owner declares plausibility")
        .keyword_free_operator_margin = Some(1.0);
    let misplaced_error = CompiledScanner::compile(vec![misplaced])
        .err()
        .expect("a non-role owner with the margin must fail compilation")
        .to_string();
    assert!(
        misplaced_error.contains("declares plausibility.keyword_free_operator_margin")
            && misplaced_error.contains("without claiming entropy role `keyword-free`"),
        "unexpected misplaced-margin error: {misplaced_error}"
    );

    let mut invalid = detector("invalid-keyword-free-margin", &["secret"], 8);
    invalid.entropy_roles = vec![EntropyDetectionRole::KeywordFree];
    invalid
        .plausibility
        .as_mut()
        .expect("keyword-free owner declares plausibility")
        .keyword_free_operator_margin = Some(8.001);
    let invalid_error = CompiledScanner::compile(vec![invalid])
        .err()
        .expect("an out-of-domain keyword-free margin must fail compilation")
        .to_string();
    assert!(
        invalid_error.contains("must be finite and in [0.0, 8.0]"),
        "unexpected invalid-margin error: {invalid_error}"
    );
}

#[test]
fn keyword_free_full_scan_uses_detector_owned_very_high_boundary() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    assert!(
        (entropy - 48_f64.log2()).abs() < 1e-12,
        "the boundary fixture must contain 48 equiprobable bytes"
    );
    let admitted =
        full_scan_keyword_free_values(entropy, 1.0, "payload.yaml", ScanBackend::CpuFallback);
    assert!(
        admitted.iter().any(|value| value == KEYWORD_FREE_VALUE),
        "a candidate exactly at the detector TOML threshold must be admitted: {admitted:?}"
    );
    assert!(
        !full_scan_keyword_free_values(
            entropy + 0.001,
            1.0,
            "payload.yaml",
            ScanBackend::CpuFallback,
        )
        .iter()
        .any(|value| value == KEYWORD_FREE_VALUE),
        "raising only the detector TOML threshold above the candidate must suppress it"
    );
}

#[test]
fn keyword_free_full_scan_composes_the_detector_owned_operator_margin_exactly() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    let operator_floor = ScannerConfig::default().entropy_threshold;
    let exact_margin = entropy - operator_floor;

    assert!(
        full_scan_keyword_free_values(4.0, exact_margin, "payload.yaml", ScanBackend::CpuFallback,)
            .iter()
            .any(|value| value == KEYWORD_FREE_VALUE),
        "the exact detector-owned operator-margin boundary must admit the candidate"
    );
    assert!(
        !full_scan_keyword_free_values(
            4.0,
            exact_margin + 0.001,
            "payload.yaml",
            ScanBackend::CpuFallback,
        )
        .iter()
        .any(|value| value == KEYWORD_FREE_VALUE),
        "raising only the detector-owned margin above the candidate must suppress it"
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
            1.0,
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
            1.0,
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
    let mut keyword_free_owner = detector("custom-keyword-free-owner", &["secret"], 8);
    keyword_free_owner.entropy_roles = vec![EntropyDetectionRole::KeywordFree];
    keyword_free_owner
        .plausibility
        .as_mut()
        .expect("keyword-free owner declares plausibility")
        .keyword_free_operator_margin = Some(1.0);
    keyword_free_owner.entropy_fallback = Some(EntropyFallbackMetadata {
        class: EntropyFallbackClass::Generic,
        id: "entropy-custom-policy".into(),
        name: "Custom Policy Entropy".into(),
        service: "custom-service".into(),
    });
    keyword_free_owner.keyword_free_min_len = Some(20);
    keyword_free_owner.bpe_enabled = Some(false);
    keyword_free_owner.sensitive_path_entropy_very_high = Some(5.5);
    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.entropy_in_source_files = true;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![keyword_free_owner, entropy_only_owner(false)])
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
    generic_keyword_secret.entropy_shapes = vec![keyhog_core::EntropyShapeSpec {
        charset: keyhog_core::ShapeCharset::LowerAlnum,
        entropy_floor: 8.0,
        special_min_length: 16,
        grouping: Some(keyhog_core::ShapeGrouping {
            group_count: 4,
            group_length: 4,
            separator: '-',
        }),
        require_mixed_case: false,
        require_digit: false,
        min_symbols: 0,
        require_non_hex_alpha: true,
        require_group_alpha_digit: true,
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
    generic_keyword_secret.entropy_shapes = vec![keyhog_core::EntropyShapeSpec {
        charset: keyhog_core::ShapeCharset::LowerAlnum,
        entropy_floor: 3.9,
        special_min_length: 16,
        grouping: Some(keyhog_core::ShapeGrouping {
            group_count: 4,
            group_length: 4,
            separator: '-',
        }),
        require_mixed_case: false,
        require_digit: false,
        min_symbols: 0,
        require_non_hex_alpha: true,
        require_group_alpha_digit: true,
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

#[test]
fn declarative_base64_shape_enforces_alphabet_padding_and_diversity() {
    const VALID: &str = "Ab3+/Cd4Ef5+Gh6/Ij7=";
    const INVALID_PADDING: &str = "Ab3+/Cd4Ef5+Gh6/I=7";
    let shape = keyhog_core::EntropyShapeSpec {
        charset: keyhog_core::ShapeCharset::Base64Standard,
        entropy_floor: 0.0,
        special_min_length: 16,
        grouping: None,
        require_mixed_case: true,
        require_digit: true,
        min_symbols: 2,
        require_non_hex_alpha: false,
        require_group_alpha_digit: false,
    };
    let mut detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detector corpus must load");
    for detector_id in ["generic-keyword-secret", "generic-secret"] {
        let detector = detectors
            .iter_mut()
            .find(|detector| detector.id == detector_id)
            .expect("generic entropy owner must be present");
        detector.entropy_shapes = vec![shape];
        detector.keyword_free_min_len = Some(64);
        detector
            .plausibility
            .as_mut()
            .expect("generic entropy owner declares plausibility")
            .symbolic_entropy_floor = 8.0;
    }

    let mut config = ScannerConfig::default();
    config.entropy_enabled = true;
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = CompiledScanner::compile(detectors)
        .expect("declarative base64 shape corpus must compile")
        .with_config(config);
    let chunk = |candidate: &str| Chunk {
        data: format!("{candidate}\n").into(),
        metadata: ChunkMetadata {
            path: Some("notes/shape-contract.txt".into()),
            ..Default::default()
        },
    };

    assert!(scanner
        .scan_with_backend(&chunk(VALID), ScanBackend::CpuFallback)
        .iter()
        .any(|finding| finding.credential.as_ref() == VALID));
    assert!(scanner
        .scan_with_backend(&chunk(INVALID_PADDING), ScanBackend::CpuFallback)
        .iter()
        .all(|finding| finding.credential.as_ref() != INVALID_PADDING));
}

#[cfg(feature = "gpu")]
#[test]
fn detector_owned_very_high_boundary_is_exact_on_every_accelerated_backend() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    let exact_margin = entropy - ScannerConfig::default().entropy_threshold;
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
        let normal = full_scan_keyword_free_values(entropy, 1.0, "payload.yaml", backend);
        assert!(
            normal.iter().any(|value| value == KEYWORD_FREE_VALUE),
            "{} must admit the exact detector-owned boundary: {normal:?}",
            backend.label()
        );
        assert!(
            !full_scan_keyword_free_values(entropy + 0.001, 1.0, "payload.yaml", backend)
                .iter()
                .any(|value| value == KEYWORD_FREE_VALUE),
            "{} must reject above the detector-owned boundary",
            backend.label()
        );
        assert!(
            full_scan_keyword_free_values(
                entropy + sensitive_discount,
                1.0,
                "secrets.yaml",
                backend,
            )
            .iter()
            .any(|value| value == KEYWORD_FREE_VALUE),
            "{} must preserve the detector-relative sensitive-path discount",
            backend.label()
        );
        assert!(
            full_scan_keyword_free_values(4.0, exact_margin, "payload.yaml", backend)
                .iter()
                .any(|value| value == KEYWORD_FREE_VALUE),
            "{} must admit the exact detector-owned margin boundary",
            backend.label()
        );
        assert!(
            !full_scan_keyword_free_values(4.0, exact_margin + 0.001, "payload.yaml", backend)
                .iter()
                .any(|value| value == KEYWORD_FREE_VALUE),
            "{} must reject above the detector-owned margin boundary",
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
    for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
        assert!(
            probe.warm_backend(backend),
            "{} must be usable on a GPU parity host",
            backend.label()
        );
        assert_eq!(
            disabled,
            full_scan_findings(false, backend),
            "CPU and {} must preserve the exact detector, credential, and offset",
            backend.label()
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
