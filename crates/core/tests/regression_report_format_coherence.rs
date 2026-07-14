//! Regression: cross-format COUNT and SEVERITY coherence for the three primary
//! report formats a CI pipeline consumes (text, JSON array, and SARIF).
//!
//! The contract under test: the SAME `&[VerifiedFinding]` slice, rendered
//! through [`keyhog_core::write_report`] into each format, must agree on
//! observable facts:
//!   * the finding COUNT is identical (text summary "N secrets found" ==
//!     JSON array length == SARIF `runs[0].results[]` length == JSONL line
//!     count),
//!   * the severity -> SARIF `level` mapping is EXACT and matches the
//!     JSON `severity` kebab string (critical/high -> `error`,
//!     medium -> `warning`, low/client-safe/info -> `note`),
//!   * the live/dead/unverified partition in the text roll-up sums to the
//!     total count, with `Revoked` folded into `dead`,
//!   * the set of detector ids in the JSON output equals the set of SARIF
//!     `ruleId`s.
//!
//! Every assertion is a concrete value: an exact integer count, an exact
//! level/severity string, or an exact summary substring. No bare
//! `is_empty()` / `len() > 0` gate is used as the sole assertion.

use keyhog_core::{
    write_report, CredentialHash, MatchLocation, ReportFormat, Severity, VerificationResult,
    VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// Build a fully-specified finding. `hash_byte` seeds all 32 hash bytes so the
/// value is deterministic; `line` gives a concrete filesystem location.
fn finding(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    redacted: &'static str,
    verification: VerificationResult,
    hash_byte: u8,
    line: usize,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        credential_hash: CredentialHash::from_bytes([hash_byte; 32]),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config/app.env".into()),
            line: Some(line),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: Some(0.9),
    }
}

fn render(format: ReportFormat, findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, format, findings).expect("write_report must succeed");
    String::from_utf8(buf).expect("report output must be valid UTF-8")
}

fn text(findings: &[VerifiedFinding]) -> String {
    render(
        ReportFormat::Text {
            color: false,
            example_suppressions: 0,
            dogfood_active: false,
        },
        findings,
    )
}

fn json_value(findings: &[VerifiedFinding]) -> serde_json::Value {
    serde_json::from_str(&render(ReportFormat::Json, findings)).expect("JSON output must parse")
}

fn json_array_len(findings: &[VerifiedFinding]) -> usize {
    json_value(findings)
        .as_array()
        .expect("JSON report is a top-level array")
        .len()
}

fn sarif_value(findings: &[VerifiedFinding]) -> serde_json::Value {
    serde_json::from_str(&render(
        ReportFormat::Sarif {
            skip_summary: vec![],
        },
        findings,
    ))
    .expect("SARIF output must parse")
}

/// Length of `runs[0].results[]`.
fn sarif_results_len(findings: &[VerifiedFinding]) -> usize {
    sarif_value(findings)["runs"][0]["results"]
        .as_array()
        .expect("SARIF runs[0].results is an array")
        .len()
}

/// A representative mixed slice: 4 findings, distinct detector ids, spanning
/// live / dead / revoked / unverifiable verification and several severities.
fn mixed_four() -> Vec<VerifiedFinding> {
    vec![
        finding(
            "aws-access-key",
            "AWS Access Key",
            "aws",
            Severity::Critical,
            "AKIA****WXYZ",
            VerificationResult::Live,
            0x11,
            3,
        ),
        finding(
            "github-pat",
            "GitHub PAT",
            "github",
            Severity::High,
            "ghp_****abcd",
            VerificationResult::Dead,
            0x22,
            5,
        ),
        finding(
            "stripe-secret",
            "Stripe Secret Key",
            "stripe",
            Severity::Medium,
            "sk_****9999",
            VerificationResult::Revoked,
            0x33,
            7,
        ),
        finding(
            "slack-webhook",
            "Slack Webhook",
            "slack",
            Severity::Low,
            "https://hooks****",
            VerificationResult::Unverifiable,
            0x44,
            9,
        ),
    ]
}

// ---------------------------------------------------------------------------
// COUNT coherence
// ---------------------------------------------------------------------------

#[test]
fn finding_count_is_four_in_json_and_sarif_for_mixed_set() {
    let f = mixed_four();
    assert_eq!(
        json_array_len(&f),
        4,
        "JSON array must hold exactly 4 findings"
    );
    assert_eq!(
        sarif_results_len(&f),
        4,
        "SARIF results must hold exactly 4 findings"
    );
}

#[test]
fn text_summary_count_equals_json_array_length() {
    let f = mixed_four();
    let n = json_array_len(&f);
    assert_eq!(n, 4);
    // The text roll-up header states the exact count.
    let expected = format!("{n} secrets found");
    let out = text(&f);
    assert!(
        out.contains(&expected),
        "text summary must state '{expected}'; got:\n{out}"
    );
}

#[test]
fn jsonl_line_count_equals_finding_count() {
    let f = mixed_four();
    let out = render(ReportFormat::Jsonl, &f);
    let lines = out.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(lines, 4, "JSONL must emit exactly one line per finding");
    // Each line is itself a valid JSON object with the detector id.
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("each JSONL line parses");
        assert!(
            v.get("detector_id").and_then(|d| d.as_str()).is_some(),
            "each JSONL object carries a detector_id"
        );
    }
}

#[test]
fn large_set_of_fifty_agrees_across_formats() {
    // Fifty copies of the same detector id => 50 results but ONE SARIF rule.
    let f: Vec<VerifiedFinding> = (0..50)
        .map(|i| {
            finding(
                "aws-access-key",
                "AWS Access Key",
                "aws",
                Severity::High,
                "AKIA****",
                VerificationResult::Dead,
                (i % 251) as u8,
                (i + 1) as usize,
            )
        })
        .collect();
    assert_eq!(json_array_len(&f), 50);
    assert_eq!(sarif_results_len(&f), 50);
    assert!(
        text(&f).contains("50 secrets found"),
        "text summary must state '50 secrets found'"
    );
    // Streaming SARIF collapses identical detector ids to a single rule.
    let rules = sarif_value(&f)["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("driver.rules is an array")
        .len();
    assert_eq!(
        rules, 1,
        "50 identical detector ids collapse to 1 SARIF rule"
    );
}

#[test]
fn empty_finding_set_is_zero_across_formats() {
    let f: Vec<VerifiedFinding> = vec![];
    assert_eq!(json_array_len(&f), 0, "empty JSON array");
    assert_eq!(sarif_results_len(&f), 0, "empty SARIF results");
    let out = text(&f);
    assert!(
        out.contains("No secrets detected in the scanned files."),
        "empty text report states the honest no-detection line; got:\n{out}"
    );
    // The honest empty line must NOT claim the code is clean.
    assert!(
        !out.to_lowercase().contains("clean"),
        "empty report must never claim the code is 'clean'"
    );
}

// ---------------------------------------------------------------------------
// SINGULAR / PLURAL wording
// ---------------------------------------------------------------------------

#[test]
fn single_finding_uses_singular_secret_wording() {
    let f = vec![finding(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Dead,
        0x01,
        1,
    )];
    assert_eq!(json_array_len(&f), 1);
    assert_eq!(sarif_results_len(&f), 1);
    let out = text(&f);
    assert!(
        out.contains("1 secret found"),
        "singular wording '1 secret found'; got:\n{out}"
    );
    assert!(
        !out.contains("1 secrets found"),
        "must not pluralize a single finding"
    );
}

// ---------------------------------------------------------------------------
// SEVERITY -> LEVEL mapping (exact)
// ---------------------------------------------------------------------------

/// Render a one-finding slice at `severity` and return
/// `(json_severity_string, sarif_level_string)`.
fn severity_pair(severity: Severity) -> (String, String) {
    let f = vec![finding(
        "detector-x",
        "Detector X",
        "svc",
        severity,
        "****",
        VerificationResult::Unverifiable,
        0x7F,
        4,
    )];
    let json_sev = json_value(&f)[0]["severity"]
        .as_str()
        .expect("json severity string")
        .to_string();
    let sarif_level = sarif_value(&f)["runs"][0]["results"][0]["level"]
        .as_str()
        .expect("sarif level string")
        .to_string();
    (json_sev, sarif_level)
}

#[test]
fn critical_maps_to_error_and_critical() {
    let (json_sev, level) = severity_pair(Severity::Critical);
    assert_eq!(json_sev, "critical");
    assert_eq!(level, "error", "critical -> SARIF error");
}

#[test]
fn high_maps_to_error() {
    let (json_sev, level) = severity_pair(Severity::High);
    assert_eq!(json_sev, "high");
    assert_eq!(level, "error", "high -> SARIF error");
}

#[test]
fn medium_maps_to_warning() {
    let (json_sev, level) = severity_pair(Severity::Medium);
    assert_eq!(json_sev, "medium");
    assert_eq!(level, "warning", "medium -> SARIF warning");
}

#[test]
fn low_maps_to_note() {
    let (json_sev, level) = severity_pair(Severity::Low);
    assert_eq!(json_sev, "low");
    assert_eq!(level, "note", "low -> SARIF note");
}

#[test]
fn client_safe_and_info_map_to_note_with_kebab_json() {
    let (cs_sev, cs_level) = severity_pair(Severity::ClientSafe);
    assert_eq!(cs_sev, "client-safe", "ClientSafe serializes kebab-case");
    assert_eq!(cs_level, "note", "client-safe -> SARIF note");

    let (info_sev, info_level) = severity_pair(Severity::Info);
    assert_eq!(info_sev, "info");
    assert_eq!(info_level, "note", "info -> SARIF note");
}

#[test]
fn all_six_severities_map_exactly_in_one_run() {
    // One finding per severity, each with a distinct detector id, so we can
    // read back the level by ruleId and assert the full mapping table at once.
    let specs: [(&'static str, Severity, &'static str); 6] = [
        ("d-critical", Severity::Critical, "error"),
        ("d-high", Severity::High, "error"),
        ("d-medium", Severity::Medium, "warning"),
        ("d-low", Severity::Low, "note"),
        ("d-client-safe", Severity::ClientSafe, "note"),
        ("d-info", Severity::Info, "note"),
    ];
    let f: Vec<VerifiedFinding> = specs
        .iter()
        .enumerate()
        .map(|(i, (id, sev, _))| {
            finding(
                id,
                "Detector",
                "svc",
                *sev,
                "****",
                VerificationResult::Unverifiable,
                (i as u8) + 1,
                i + 1,
            )
        })
        .collect();

    assert_eq!(sarif_results_len(&f), 6);
    let results = sarif_value(&f);
    let arr = results["runs"][0]["results"].as_array().unwrap();
    let mut by_rule: HashMap<String, String> = HashMap::new();
    for r in arr {
        by_rule.insert(
            r["ruleId"].as_str().unwrap().to_string(),
            r["level"].as_str().unwrap().to_string(),
        );
    }
    for (id, _sev, expected_level) in specs {
        assert_eq!(
            by_rule.get(id).map(String::as_str),
            Some(expected_level),
            "detector {id} must map to SARIF level {expected_level}"
        );
    }
}

// ---------------------------------------------------------------------------
// VERIFICATION partition coherence
// ---------------------------------------------------------------------------

#[test]
fn text_partition_sums_to_count_with_revoked_folded_into_dead() {
    // 1 live, 1 dead, 1 revoked (folds into dead), 1 unverifiable (unverified).
    // Expected roll-up: 4 secrets found · 1 live · 2 dead · 1 unverified.
    let f = mixed_four();
    let out = text(&f);
    assert!(
        out.contains("4 secrets found · 1 live · 2 dead · 1 unverified"),
        "exact partition roll-up expected; got:\n{out}"
    );
    // Cross-format: same count everywhere.
    assert_eq!(json_array_len(&f), 4);
    assert_eq!(sarif_results_len(&f), 4);
}

#[test]
fn revoked_finding_is_dead_in_text_but_revoked_token_in_structured_formats() {
    let f = vec![finding(
        "stripe-secret",
        "Stripe Secret Key",
        "stripe",
        Severity::Medium,
        "sk_****9999",
        VerificationResult::Revoked,
        0x55,
        7,
    )];
    let out = text(&f);
    // Coarse roll-up folds Revoked into the dead tally.
    assert!(
        out.contains("1 secret found · 1 dead"),
        "revoked counts toward the dead tally; got:\n{out}"
    );
    // JSON keeps the precise snake_case token.
    assert_eq!(json_value(&f)[0]["verification"].as_str(), Some("revoked"));
    // SARIF result properties carry the same precise token.
    assert_eq!(
        sarif_value(&f)["runs"][0]["results"][0]["properties"]["verification"].as_str(),
        Some("revoked"),
    );
}

// ---------------------------------------------------------------------------
// IDENTITY coherence: same detector-id set in JSON and SARIF
// ---------------------------------------------------------------------------

#[test]
fn json_detector_ids_equal_sarif_rule_ids_set() {
    let f = mixed_four();
    let json_ids: HashSet<String> = json_value(&f)
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["detector_id"].as_str().unwrap().to_string())
        .collect();
    let sarif_ids: HashSet<String> = sarif_value(&f)["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ruleId"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        json_ids, sarif_ids,
        "JSON detector_id set must equal SARIF ruleId set"
    );
    assert_eq!(
        json_ids.len(),
        4,
        "four distinct detector ids in the mixed set"
    );
    // Spot-check a specific member is present in both.
    assert!(json_ids.contains("aws-access-key"));
    assert!(sarif_ids.contains("aws-access-key"));
}

#[test]
fn json_severity_matches_sarif_level_per_finding() {
    // For every finding, the JSON `severity` and the SARIF `level` at the same
    // detector id must obey the exact mapping table (verified pairwise).
    let f = mixed_four();
    let json = json_value(&f);
    let sarif = sarif_value(&f);
    let level_by_rule: HashMap<String, String> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["ruleId"].as_str().unwrap().to_string(),
                r["level"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    let expected_level = |sev: &str| -> &'static str {
        match sev {
            "critical" | "high" => "error",
            "medium" => "warning",
            "low" | "client-safe" | "info" => "note",
            other => panic!("unexpected severity {other}"),
        }
    };

    for obj in json.as_array().unwrap() {
        let id = obj["detector_id"].as_str().unwrap();
        let sev = obj["severity"].as_str().unwrap();
        assert_eq!(
            level_by_rule.get(id).map(String::as_str),
            Some(expected_level(sev)),
            "detector {id} severity {sev} must match SARIF level"
        );
    }
}
