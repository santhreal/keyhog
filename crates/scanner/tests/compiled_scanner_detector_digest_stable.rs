use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn expected_digest(patterns: &[&str]) -> u64 {
    fn update(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
        hasher.update(&(tag.len() as u64).to_le_bytes());
        hasher.update(tag);
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value);
    }

    let mut hasher = blake3::Hasher::new();
    update(&mut hasher, b"domain", b"keyhog-scanner-detector-digest-v1");
    update(
        &mut hasher,
        b"pattern_count",
        &(patterns.len() as u64).to_le_bytes(),
    );
    for pattern in patterns {
        update(&mut hasher, b"regex", pattern.as_bytes());
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_le_bytes(bytes)
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
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec![keyword.into()],
        min_confidence: None,
        ..Default::default()
    }
}

#[test]
fn compiled_scanner_detector_digest_is_stable_and_boundary_aware() {
    let first_scanner = CompiledScanner::compile(vec![
        detector("alpha", "AKIA[0-9A-Z]{16}", "AKIA"),
        detector("beta", "ghp_[0-9A-Za-z]{36}", "ghp_"),
    ])
    .expect("compile first scanner");
    let first_patterns = keyhog_scanner::testing::pattern_regex_strs(&first_scanner);
    let first = first_scanner.runtime_status().detector_digest;
    let second = CompiledScanner::compile(vec![
        detector("alpha", "AKIA[0-9A-Z]{16}", "AKIA"),
        detector("beta", "ghp_[0-9A-Za-z]{36}", "ghp_"),
    ])
    .expect("compile second scanner")
    .runtime_status()
    .detector_digest;
    let changed = CompiledScanner::compile(vec![
        detector("alpha", "AKIA[0-9A-Z]{16}", "AKIA"),
        detector("beta", "ghp_[0-9A-Za-z]{37}", "ghp_"),
    ])
    .expect("compile changed scanner")
    .runtime_status()
    .detector_digest;

    assert_ne!(first, 0, "runtime detector digest must carry real identity");
    assert_eq!(
        first, second,
        "same compiled detector runtime must produce the same autoroute cache identity"
    );
    assert_ne!(
        first, changed,
        "regex source changes must invalidate autoroute detector identity"
    );
    assert_eq!(
        first,
        expected_digest(&first_patterns),
        "autoroute identity must use the stable domain-separated, length-delimited BLAKE3 contract"
    );
}
