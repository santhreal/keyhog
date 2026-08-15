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
        companions_redacted: std::collections::HashMap::new(),
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
        entropy: None,
        evidence_score: None,
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
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
    assert_eq!(baseline.version, 2);
    assert_eq!(baseline.entries.len(), 2);
    assert_eq!(baseline.entries[0].detector_id, "aws-key");
    assert_eq!(baseline.entries[0].credential_hash, baseline_hash("def456"));
    assert_eq!(
        baseline.entries[0].file_path,
        Some("src/aws.py".to_string())
    );
    assert_eq!(baseline.entries[0].line, Some(42));
    assert_eq!(
        baseline.entries[0].evidence,
        keyhog_core::EvidenceVerdict::review_unattributed()
    );
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

/// Baseline suppression must compact the existing finding vector so a large
/// report never retains old and replacement finding graphs at once.
#[test]
fn baseline_suppression_reuses_the_finding_allocation() {
    let baseline =
        API.baseline_from_findings(&[make_finding("github-pat", "known", Some("known.txt"))]);
    let mut findings = Vec::with_capacity(16);
    findings.push(make_finding("github-pat", "known", Some("known.txt")));
    findings.push(make_finding("aws-key", "new", Some("new.txt")));
    let allocation = findings.as_ptr();
    let capacity = findings.capacity();

    API.baseline_retain_new(&baseline, &mut findings);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector_id.as_ref(), "aws-key");
    assert_eq!(findings[0].credential_hash, test_hash("new").into());
    assert_eq!(findings[0].location.file_path.as_deref(), Some("new.txt"));
    assert_eq!(findings.as_ptr(), allocation);
    assert_eq!(findings.capacity(), capacity);
}

/// Suppressing every finding must clear entries without replacing or shrinking
/// the reusable vector allocation.
#[test]
fn baseline_full_suppression_keeps_the_reusable_allocation() {
    let baseline =
        API.baseline_from_findings(&[make_finding("github-pat", "known", Some("known.txt"))]);
    let mut findings = Vec::with_capacity(16);
    findings.push(make_finding("github-pat", "known", Some("known.txt")));
    let allocation = findings.as_ptr();
    let capacity = findings.capacity();

    API.baseline_retain_new(&baseline, &mut findings);

    assert!(findings.is_empty());
    assert_eq!(findings.as_ptr(), allocation);
    assert_eq!(findings.capacity(), capacity);
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
fn baseline_v2_serializes_evidence_and_rejects_stale_v1() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("baseline.json");
    let baseline =
        API.baseline_from_findings(&[make_finding("github-pat", "abc123", Some("src/config.py"))]);

    API.baseline_save(&baseline, &path).unwrap();
    let serialized = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(parsed["version"], 2);
    assert_eq!(parsed["entries"][0]["evidence"]["tier"], "review");
    assert_eq!(
        parsed["entries"][0]["evidence"]["reason_code"],
        "unattributed"
    );
    assert!(parsed["entries"][0].get("status").is_none());

    let stale_v1 = format!(
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
    std::fs::write(&path, stale_v1).unwrap();
    let error = API
        .baseline_load(&path)
        .expect_err("version-1 baseline must fail closed");
    assert!(
        format!("{error:#}").contains("unsupported baseline version 1 (expected 2)"),
        "stale baseline diagnostic must name the explicit version boundary: {error:#}"
    );
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
        !API.baseline_looks_like_findings_report(r#"{"version":2,"created":"now","entries":[]}"#)
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

#[test]
fn unknown_baseline_fields_and_removed_status_alias_fail_closed() {
    let mut root = tempfile::NamedTempFile::new().unwrap();
    write!(
        root,
        r#"{{"version":2,"created":"now","entries":[],"reviewd":true}}"#
    )
    .unwrap();
    let root_error = API
        .baseline_load(root.path())
        .expect_err("unknown root fields must not silently change baseline policy");
    assert!(
        format!("{root_error:#}").contains("reviewd"),
        "root typo should be named in the parse error: {root_error:#}"
    );

    let mut entry = tempfile::NamedTempFile::new().unwrap();
    write!(
        entry,
        r#"{{"version":2,"created":"now","entries":[{{"detector_id":"aws-key","credential_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","file_path":"x","line":1,"evidence":{{"tier":"review","reason_code":"unattributed"}},"reviewd":true}}]}}"#
    )
    .unwrap();
    let entry_error = API
        .baseline_load(entry.path())
        .expect_err("unknown entry fields must not silently change suppression policy");
    assert!(
        format!("{entry_error:#}").contains("reviewd"),
        "entry typo should be named in the parse error: {entry_error:#}"
    );

    let mut legacy = tempfile::NamedTempFile::new().unwrap();
    write!(
        legacy,
        r#"{{"version":2,"created":"current","entries":[{{"detector_id":"aws-key","credential_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","file_path":"x","line":1,"evidence":{{"tier":"review","reason_code":"unattributed"}},"status":"rejected"}}]}}"#
    )
    .unwrap();
    let status_error = API
        .baseline_load(legacy.path())
        .expect_err("removed status alias must fail closed");
    assert!(format!("{status_error:#}").contains("status"));
}
