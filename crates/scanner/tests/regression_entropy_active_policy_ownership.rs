use keyhog_core::{Chunk, ChunkMetadata, DetectorKind, DetectorSpec, PatternSpec};
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
        entropy_low: Some(0.0),
        entropy_high: Some(4.5),
        entropy_very_high: Some(5.8),
        mixed_alnum_floor: Some(0.0),
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
        ..Default::default()
    }];
    owner.entropy_policy_priority = Some(100);
    owner.bpe_enabled = Some(bpe_enabled);
    owner
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
    let sensitive_discount = keyhog_scanner::entropy::VERY_HIGH_ENTROPY_THRESHOLD
        - keyhog_scanner::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD;
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

#[cfg(feature = "gpu")]
#[test]
fn detector_owned_very_high_boundary_is_exact_on_every_accelerated_backend() {
    let entropy = keyhog_scanner::entropy::shannon_entropy(KEYWORD_FREE_VALUE.as_bytes());
    let sensitive_discount = keyhog_scanner::entropy::VERY_HIGH_ENTROPY_THRESHOLD
        - keyhog_scanner::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD;
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
