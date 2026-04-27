use keyhog::baseline::Baseline;
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;

fn make_finding(
    detector_id: &str,
    credential_hash: &str,
    file_path: Option<&str>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential_redacted: "***".into(),
        credential_hash: credential_hash.to_string(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: file_path.map(Arc::from),
            line: Some(42),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: None,
    }
}

#[test]
fn baseline_creation_produces_expected_entries() {
    let findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("aws-key", "def456", Some("src/aws.py")),
    ];

    let baseline = Baseline::from_findings(&findings);
    assert_eq!(baseline.version, 1);
    assert_eq!(baseline.entries.len(), 2);
    assert_eq!(baseline.entries[0].detector_id, "aws-key");
    assert_eq!(baseline.entries[0].credential_hash, "sha256:def456");
    assert_eq!(
        baseline.entries[0].file_path,
        Some("src/aws.py".to_string())
    );
    assert_eq!(baseline.entries[0].line, Some(42));
    assert_eq!(baseline.entries[0].status, "acknowledged");
}

#[test]
fn baseline_creation_dedupes_duplicate_credentials() {
    let findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("github-pat", "abc123", Some("src/other.py")),
    ];

    let baseline = Baseline::from_findings(&findings);
    assert_eq!(baseline.entries.len(), 1);
    assert_eq!(baseline.entries[0].detector_id, "github-pat");
}

#[test]
fn baseline_suppresses_known_findings() {
    let findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("aws-key", "def456", Some("src/aws.py")),
    ];

    let baseline = Baseline::from_findings(&findings);
    let suppressed = baseline.filter_new(&findings);
    assert!(suppressed.is_empty());
}

#[test]
fn baseline_does_not_suppress_new_findings() {
    let baseline =
        Baseline::from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);
    let new_findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("github-pat", "newhash", Some("src/new.py")),
    ];

    let filtered = baseline.filter_new(&new_findings);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].credential_hash, "newhash");
}

#[test]
fn baseline_update_adds_new_findings() {
    let mut baseline =
        Baseline::from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);
    let new_findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("aws-key", "def456", Some("src/aws.py")),
    ];

    baseline.merge(&new_findings);
    assert_eq!(baseline.entries.len(), 2);
    let ids: Vec<_> = baseline
        .entries
        .iter()
        .map(|e| e.detector_id.as_str())
        .collect();
    assert!(ids.contains(&"github-pat"));
    assert!(ids.contains(&"aws-key"));
}

#[test]
fn baseline_save_and_load_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("baseline.json");
    let findings = vec![make_finding("github-pat", "abc123", Some("src/config.py"))];
    let baseline = Baseline::from_findings(&findings);

    baseline.save(&path).unwrap();
    let loaded = Baseline::load(&path).unwrap();

    assert_eq!(loaded, baseline);
}

#[test]
fn baseline_matching_ignores_file_path_and_line() {
    let findings = vec![make_finding("github-pat", "abc123", Some("src/config.py"))];
    let baseline = Baseline::from_findings(&findings);
    let moved_finding = make_finding("github-pat", "abc123", Some("src/moved.py"));

    assert!(baseline.contains(&moved_finding));
}
