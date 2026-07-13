use keyhog::testing::{CliTestApi as _, API};
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
        credential_hash: test_hash(credential_hash).into(),
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

fn test_hash(seed: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in seed.as_bytes().iter().copied().take(32).enumerate() {
        out[idx] = byte;
    }
    out
}

fn baseline_hash(seed: &str) -> String {
    format!("sha256:{}", keyhog_core::hex_encode(&test_hash(seed)))
}

#[test]
fn baseline_creation_produces_expected_entries() {
    let findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("aws-key", "def456", Some("src/aws.py")),
    ];

    let baseline = API.baseline_from_findings(&findings);
    assert_eq!(baseline.version, 1);
    assert_eq!(baseline.entries.len(), 2);
    assert_eq!(baseline.entries[0].detector_id, "aws-key");
    assert_eq!(baseline.entries[0].credential_hash, baseline_hash("def456"));
    assert_eq!(
        baseline.entries[0].file_path,
        Some("src/aws.py".to_string())
    );
    assert_eq!(baseline.entries[0].line, Some(42));
}

#[test]
fn baseline_creation_dedupes_duplicate_credentials() {
    let findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("github-pat", "abc123", Some("src/other.py")),
    ];

    let baseline = API.baseline_from_findings(&findings);
    assert_eq!(baseline.entries.len(), 1);
    assert_eq!(baseline.entries[0].detector_id, "github-pat");
}

#[test]
fn baseline_suppresses_known_findings() {
    let findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("aws-key", "def456", Some("src/aws.py")),
    ];

    let baseline = API.baseline_from_findings(&findings);
    let suppressed = API.baseline_filter_new(&baseline, &findings);
    assert!(suppressed.is_empty());
}

#[test]
fn baseline_does_not_suppress_new_findings() {
    let baseline =
        API.baseline_from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);
    let new_findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("github-pat", "newhash", Some("src/new.py")),
    ];

    let filtered = API.baseline_filter_new(&baseline, &new_findings);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].credential_hash, test_hash("newhash").into());
}

#[test]
fn baseline_update_adds_new_findings() {
    let mut baseline =
        API.baseline_from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);
    let new_findings = vec![
        make_finding("github-pat", "abc123", Some("src/config.py")),
        make_finding("aws-key", "def456", Some("src/aws.py")),
    ];

    API.baseline_merge(&mut baseline, &new_findings);
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
    let baseline = API.baseline_from_findings(&findings);

    API.baseline_save(&baseline, &path).unwrap();
    let loaded = API.baseline_load(&path).unwrap();

    assert_eq!(loaded, baseline);
}

#[test]
fn baseline_status_is_not_serialized_but_legacy_status_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("baseline.json");
    let baseline =
        API.baseline_from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);

    API.baseline_save(&baseline, &path).unwrap();
    let serialized = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert!(
        parsed["entries"][0].get("status").is_none(),
        "baseline status is not a real suppression state and must not be serialized: {serialized}"
    );

    let legacy = format!(
        r#"{{
            "version": 1,
            "created": "legacy",
            "entries": [{{
                "detector_id": "github-pat",
                "credential_hash": "{}",
                "file_path": "src/config.py",
                "line": 42,
                "status": "rejected"
            }}]
        }}"#,
        baseline_hash("abc123")
    );
    std::fs::write(&path, legacy).unwrap();
    let loaded = API.baseline_load(&path).unwrap();
    assert!(API.baseline_contains(
        &loaded,
        &make_finding("github-pat", "abc123", Some("src/moved.py"))
    ));
}

#[test]
fn baseline_matching_ignores_file_path_and_line() {
    let findings = vec![make_finding("github-pat", "abc123", Some("src/config.py"))];
    let baseline = API.baseline_from_findings(&findings);
    let moved_finding = make_finding("github-pat", "abc123", Some("src/moved.py"));

    assert!(API.baseline_contains(&baseline, &moved_finding));
}

// ── Moved from src/baseline.rs (#[cfg(test)]) per the no_inline_tests_in_src
//    gate. findings-report-vs-baseline detection + actionable load error.
use std::io::Write;

#[test]
fn findings_report_array_is_recognized() {
    // `scan --format json` emits a top-level ARRAY of findings.
    assert!(API
        .baseline_looks_like_findings_report(r#"[{"detector_id":"github-classic-pat","line":1}]"#));
}

#[test]
fn findings_report_object_without_baseline_keys_is_recognized() {
    // An object lacking version+entries is not a baseline.
    assert!(API.baseline_looks_like_findings_report(r#"{"results":[],"summary":{}}"#));
}

#[test]
fn real_baseline_is_not_flagged_as_findings_report() {
    assert!(
        !API.baseline_looks_like_findings_report(r#"{"version":1,"created":"now","entries":[]}"#)
    );
}

#[test]
fn load_of_scan_report_gives_actionable_error_not_serde_noise() {
    // Regression: feeding a `scan --format json` report to `diff` used to
    // surface "invalid type: map, expected u32", which reads like file
    // corruption. It must instead name the right command.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, r#"[{{"detector_id":"github-classic-pat","line":1}}]"#).unwrap();
    let err = API
        .baseline_load(tmp.path())
        .expect_err("a findings array is not a baseline");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("--create-baseline"),
        "error must point at `--create-baseline`, got: {msg}"
    );
    assert!(
        !msg.contains("expected u32"),
        "raw serde noise must be suppressed, got: {msg}"
    );
}

#[test]
fn load_of_valid_baseline_roundtrips() {
    let b = API.baseline_empty();
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", serde_json::to_string(&b).unwrap()).unwrap();
    let loaded = API.baseline_load(tmp.path()).expect("valid baseline loads");
    assert_eq!(loaded.version, API.baseline_version());
}
