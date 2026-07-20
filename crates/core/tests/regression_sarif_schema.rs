//! Regression: SARIF v2.1.0 **schema envelope** conformance.
//!
//! Distinct from `regression_sarif_partial_fingerprints.rs` (which pins the
//! per-credential fingerprint identity), this file pins the OUTER document
//! shape a code-scanning platform (GitHub, Azure DevOps, SonarQube) validates
//! against the SARIF 2.1.0 JSON schema:
//!
//!   1. The top-level object has EXACTLY the three keys `$schema`, `version`,
//!      `runs`, with `version == "2.1.0"` (a literal, NOT the crate version)
//!      and the canonical OASIS schema URL.
//!   2. `runs` is a one-element array; `runs[0]` carries `results`, `tool`, and
//!      `taxonomies` (and `invocations` ONLY when there are coverage gaps).
//!   3. A finding maps to `runs[0].results[i]` with the exact `ruleId`,
//!      severity->`level` mapping, and
//!      `locations[0].physicalLocation.region.startLine`.
//!   4. `partialFingerprints` carries the sha256 credential hash at the finding.
//!   5. Empty findings still produce a schema-valid SARIF with `results == []`.
//!
//! Every assertion pins a concrete value: exact key sets, the exact schema URL,
//! the exact `"2.1.0"` version string, exact ruleId/level strings, exact
//! startLine integer, and the exact sha256 hex fingerprint.

use keyhog_core::{
    hex_encode, sha256_hash, write_report, MatchLocation, ReportFormat, Severity,
    VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Canonical SARIF 2.1.0 schema URL keyhog emits (owned in
/// `report/sarif.rs::ensure_prefix`). Pinned so a URL edit is a reviewed break.
const SARIF_SCHEMA_URL: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json";

/// The SARIF spec version. keyhog is a 2.1.0 producer; this MUST NOT track the
/// crate's own semver (a prior shape emitted CARGO_PKG_VERSION here).
const SARIF_VERSION: &str = "2.1.0";

/// The versioned partialFingerprints key (owned in `report/sarif_uri.rs`).
const FP_KEY: &str = "keyhog/credentialHash/v1";

/// sha256 hex of `"AKIAIOSFODNN7EXAMPLE"` (out-of-band `printf '%s' .. | sha256sum`).
const AWS_VALUE: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_VALUE_SHA256_HEX: &str =
    "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3";

/// Build a finding at a caller-chosen file/line/severity.
fn finding_for(
    value: &str,
    file: &str,
    line: usize,
    severity: Severity,
    redacted: &'static str,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        credential_hash: sha256_hash(value),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some(file.into()),
            line: Some(line),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: Some(0.9),
    }
}

/// A finding with NO file path and NO line/offset (e.g. a stdin scan): the
/// reporter labels the artifact `"stdin"` and omits the region entirely.
fn finding_stdin_no_region(value: &str) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA****"),
        credential_hash: sha256_hash(value),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "stdin".into(),
            file_path: None,
            line: None,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: None,
    }
}

/// A finding with a char offset but NO line: region carries `charOffset`, no
/// `startLine`.
fn finding_offset_no_line(value: &str, offset: usize) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA****"),
        credential_hash: sha256_hash(value),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("blob.bin".into()),
            line: None,
            offset,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: None,
    }
}

fn render_sarif(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        findings,
    )
    .expect("finish SARIF document");
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

fn render_sarif_with_skips(
    findings: &[VerifiedFinding],
    skips: Vec<(String, usize)>,
) -> serde_json::Value {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Sarif {
            skip_summary: skips,
        },
        findings,
    )
    .expect("finish SARIF document");
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

// ---------------------------------------------------------------------------
// Top-level envelope
// ---------------------------------------------------------------------------

/// The top-level object has EXACTLY `$schema`, `version`, `runs`: no more.
#[test]
fn top_level_has_exactly_schema_version_runs() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    let obj = json.as_object().expect("SARIF root must be a JSON object");
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["$schema", "runs", "version"],
        "top-level keys must be exactly $schema/version/runs"
    );
}

/// `version` is the literal producer version `"2.1.0"`, NOT the crate semver.
#[test]
fn version_is_literal_2_1_0_not_crate_version() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    assert_eq!(
        json["version"].as_str(),
        Some(SARIF_VERSION),
        "SARIF version must be the 2.1.0 producer literal"
    );
    // Guard the exact regression: the crate's own version must not leak here.
    let crate_version = env!("CARGO_PKG_VERSION");
    if crate_version != SARIF_VERSION {
        assert_ne!(
            json["version"].as_str(),
            Some(crate_version),
            "version must be the SARIF spec version, never the crate version"
        );
    }
}

/// `$schema` is the canonical OASIS SARIF 2.1.0 URL, byte for byte.
#[test]
fn schema_url_is_canonical_oasis_2_1_0() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    assert_eq!(
        json["$schema"].as_str(),
        Some(SARIF_SCHEMA_URL),
        "$schema must be the canonical OASIS 2.1.0 schema URL"
    );
}

/// `runs` is a one-element array (keyhog emits exactly one run per document).
#[test]
fn runs_is_single_element_array() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    let runs = json["runs"].as_array().expect("runs must be a JSON array");
    assert_eq!(runs.len(), 1, "keyhog emits exactly one run");
}

/// `runs[0]` (no coverage gaps) carries its terminal status plus the exact
/// results/tool/taxonomies surfaces, and specifically NO `invocations` when
/// there is nothing to report.
#[test]
fn run0_keys_are_results_tool_taxonomies_when_no_skips() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    let run0 = json["runs"][0]
        .as_object()
        .expect("runs[0] must be a JSON object");
    let mut keys: Vec<&str> = run0.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["properties", "results", "taxonomies", "tool"],
        "runs[0] must carry the terminal status with results/tool/taxonomies"
    );
    assert_eq!(
        json["runs"][0]["properties"]["keyhog.scan.status"],
        "success"
    );
    assert!(
        json["runs"][0]["invocations"].is_null(),
        "invocations must be absent when there are no coverage gaps"
    );
}

/// With a non-empty skip summary, `runs[0].invocations` appears with the exact
/// coverage-gap count and `executionSuccessful == false` (Partial is not green).
#[test]
fn run0_gains_invocations_with_skip_summary() {
    let json = render_sarif_with_skips(
        &[finding_for(
            AWS_VALUE,
            "a.env",
            1,
            Severity::High,
            "AKIA****",
        )],
        vec![("oversize".to_string(), 3)],
    );
    let inv = &json["runs"][0]["invocations"];
    assert_eq!(
        json["runs"][0]["properties"]["keyhog.scan.status"],
        "partial"
    );
    let arr = inv.as_array().expect("invocations must be an array");
    assert_eq!(arr.len(), 1, "one invocation entry");
    assert_eq!(
        arr[0]["executionSuccessful"].as_bool(),
        Some(false),
        "Partial coverage gaps must flip executionSuccessful (KH-1437)"
    );
    let notif = &arr[0]["toolExecutionNotifications"][0];
    assert_eq!(
        notif["properties"]["count"].as_u64(),
        Some(3),
        "notification must carry the exact skip count"
    );
    assert_eq!(
        notif["properties"]["reason"].as_str(),
        Some("oversize"),
        "notification must carry the exact skip reason"
    );
}

// ---------------------------------------------------------------------------
// tool.driver
// ---------------------------------------------------------------------------

/// `runs[0].tool.driver.name == "keyhog"` and the accumulated rule for the
/// finding's detector is present with the exact id and name.
#[test]
fn tool_driver_name_and_rule_present() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    assert_eq!(
        json["runs"][0]["tool"]["driver"]["name"].as_str(),
        Some("keyhog"),
        "tool.driver.name must be keyhog"
    );
    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("tool.driver.rules must be an array");
    assert_eq!(rules.len(), 1, "one unique detector -> one rule");
    assert_eq!(
        rules[0]["id"].as_str(),
        Some("aws-access-key"),
        "rule id must equal the detector id"
    );
    assert_eq!(
        rules[0]["name"].as_str(),
        Some("AWS Access Key"),
        "rule name must equal the detector name"
    );
}

/// `taxonomies` carries the CWE-798 and OWASP A07:2021 taxa keyhog cross-refs.
#[test]
fn taxonomies_carry_cwe798_and_owasp_a07() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "a.env",
        1,
        Severity::High,
        "AKIA****",
    )]);
    let taxa = json["runs"][0]["taxonomies"]
        .as_array()
        .expect("taxonomies must be an array");
    assert_eq!(taxa.len(), 2, "exactly CWE + OWASP taxonomy blocks");
    assert_eq!(taxa[0]["name"].as_str(), Some("CWE"));
    assert_eq!(
        taxa[0]["taxa"][0]["id"].as_str(),
        Some("CWE-798"),
        "CWE taxon id must be CWE-798"
    );
    assert_eq!(taxa[1]["name"].as_str(), Some("OWASP"));
    assert_eq!(
        taxa[1]["taxa"][0]["id"].as_str(),
        Some("A07:2021"),
        "OWASP taxon id must be A07:2021"
    );
}

// ---------------------------------------------------------------------------
// results[i] shape
// ---------------------------------------------------------------------------

/// A single finding maps to one result with the exact ruleId, level, message
/// text, physicalLocation URI, and region.startLine.
#[test]
fn single_finding_maps_to_result_with_exact_fields() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "config/prod.env",
        137,
        Severity::High,
        "AKIA****",
    )]);
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results must be an array");
    assert_eq!(results.len(), 1, "one finding -> one result");
    let r = &results[0];
    assert_eq!(
        r["ruleId"].as_str(),
        Some("aws-access-key"),
        "ruleId must equal the detector id"
    );
    assert_eq!(
        r["level"].as_str(),
        Some("error"),
        "High severity maps to error"
    );
    assert_eq!(
        r["message"]["text"].as_str(),
        Some("aws secret detected: AKIA****"),
        "message text is '<service> secret detected: <redacted>'"
    );
    let phys = &r["locations"][0]["physicalLocation"];
    assert_eq!(
        phys["artifactLocation"]["uri"].as_str(),
        Some("config/prod.env"),
        "artifactLocation.uri must be the file path"
    );
    assert_eq!(
        phys["region"]["startLine"].as_u64(),
        Some(137),
        "region.startLine must be the finding's exact line"
    );
    // charOffset must be absent when offset is zero.
    assert!(
        phys["region"]["charOffset"].is_null(),
        "charOffset must be absent for a zero offset"
    );
}

/// `partialFingerprints` on the result carries the exact sha256 credential hash.
#[test]
fn result_partial_fingerprints_carry_sha256() {
    let json = render_sarif(&[finding_for(
        AWS_VALUE,
        "config.env",
        12,
        Severity::High,
        "AKIA****",
    )]);
    let fp = &json["runs"][0]["results"][0]["partialFingerprints"][FP_KEY];
    assert_eq!(
        fp.as_str(),
        Some(AWS_VALUE_SHA256_HEX),
        "partialFingerprints must carry hex(sha256(value))"
    );
    // Cross-check against the public hashing API to guard a silent hash swap.
    assert_eq!(
        fp.as_str().map(str::to_string),
        Some(hex_encode(sha256_hash(AWS_VALUE))),
        "reporter fingerprint must match hex_encode(sha256_hash(value))"
    );
}

/// Severity -> level mapping across ALL six severities (exact SARIF level).
#[test]
fn severity_to_level_mapping_is_exact() {
    let cases = [
        (Severity::Critical, "error"),
        (Severity::High, "error"),
        (Severity::Medium, "warning"),
        (Severity::Low, "note"),
        (Severity::ClientSafe, "note"),
        (Severity::Info, "note"),
    ];
    for (sev, expected_level) in cases {
        let json = render_sarif(&[finding_for(AWS_VALUE, "a.env", 1, sev, "AKIA****")]);
        assert_eq!(
            json["runs"][0]["results"][0]["level"].as_str(),
            Some(expected_level),
            "severity {sev:?} must map to level {expected_level:?}"
        );
    }
}

/// Multiple findings -> a results array of the same length, in emission order,
/// each with the right ruleId and startLine.
#[test]
fn multiple_findings_produce_ordered_results() {
    let json = render_sarif(&[
        finding_for(AWS_VALUE, "one.env", 5, Severity::Critical, "AKIA****"),
        finding_for(AWS_VALUE, "two.env", 50, Severity::Low, "AKIA****"),
    ]);
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert_eq!(results.len(), 2, "two findings -> two results");
    assert_eq!(
        results[0]["level"].as_str(),
        Some("error"),
        "result 0 is the Critical finding"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64(),
        Some(5),
    );
    assert_eq!(
        results[1]["level"].as_str(),
        Some("note"),
        "result 1 is the Low finding"
    );
    assert_eq!(
        results[1]["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64(),
        Some(50),
    );
}

// ---------------------------------------------------------------------------
// Boundary / adversarial
// ---------------------------------------------------------------------------

/// Empty findings still produce a schema-valid SARIF: the three top-level keys,
/// `version == 2.1.0`, and `runs[0].results == []` (zero results, tool present).
#[test]
fn empty_findings_yield_valid_sarif_with_zero_results() {
    let json = render_sarif(&[]);
    assert_eq!(json["version"].as_str(), Some(SARIF_VERSION));
    assert_eq!(json["$schema"].as_str(), Some(SARIF_SCHEMA_URL));
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results must be present even with no findings");
    assert_eq!(results.len(), 0, "no findings -> zero results");
    // The tool block is still emitted so the document validates.
    assert_eq!(
        json["runs"][0]["tool"]["driver"]["name"].as_str(),
        Some("keyhog"),
        "tool.driver must be present in an empty run"
    );
    // No rules accumulated when there were no findings.
    let rules = json["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array present");
    assert_eq!(rules.len(), 0, "no findings -> no rules");
}

/// A path-less (stdin) finding labels its artifact `"stdin"` and, with no line
/// and a zero offset, emits NO region object at all.
#[test]
fn stdin_finding_labels_artifact_and_omits_region() {
    let json = render_sarif(&[finding_stdin_no_region(AWS_VALUE)]);
    let phys = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(
        phys["artifactLocation"]["uri"].as_str(),
        Some("stdin"),
        "path-less finding labels its artifact 'stdin'"
    );
    assert!(
        phys["region"].is_null(),
        "no line and zero offset must emit no region"
    );
}

/// A finding with a non-zero char offset and no line carries `region.charOffset`
/// with the exact value and NO `startLine`.
#[test]
fn offset_without_line_emits_char_offset_only() {
    let json = render_sarif(&[finding_offset_no_line(AWS_VALUE, 4096)]);
    let region = &json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
    assert!(!region.is_null(), "a non-zero offset must produce a region");
    assert_eq!(
        region["charOffset"].as_u64(),
        Some(4096),
        "region.charOffset must be the exact byte offset"
    );
    assert!(region["startLine"].is_null(), "no line means no startLine");
}
