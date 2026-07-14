use keyhog_core::{Chunk, ChunkMetadata, DetectorKind, DetectorSpec, PatternSpec};
use keyhog_scanner::testing::entropy_scanner::{
    active_policy_match_values, active_policy_owner_id,
};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const KEYWORD: &str = "custom_credential";
const VALUE: &str = "a8Xk9mQ2pL5vR7tN3wE6yU1zAbCdEf0G";

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
            probe.warm_backend(ScanBackend::Gpu),
            "GPU-enabled parity runs require a usable accelerator"
        );
        assert_eq!(
            disabled,
            full_scan_findings(false, ScanBackend::Gpu),
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
