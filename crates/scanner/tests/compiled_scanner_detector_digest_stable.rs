use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

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
    let first = CompiledScanner::compile(vec![
        detector("alpha", "AKIA[0-9A-Z]{16}", "AKIA"),
        detector("beta", "ghp_[0-9A-Za-z]{36}", "ghp_"),
    ])
    .expect("compile first scanner")
    .runtime_status()
    .detector_digest;
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
}
