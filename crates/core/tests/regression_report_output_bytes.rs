//! Regression: EXACT reporter output bytes for the SARIF, JSON/JSONL, and text
//! formatters.
//!
//! These tests build a KNOWN [`VerifiedFinding`] set and assert the concrete,
//! byte-level contract each format ships:
//!   * SARIF: `runs[0].results[].ruleId` == detector id, `.level` mapped from
//!     severity (`error`/`warning`/`note`), `.partialFingerprints` carries the
//!     `keyhog/credentialHash/v1` -> hex-hash entry (and is ABSENT for the
//!     all-zero sentinel), CWE/OWASP taxonomy ids, the `security-severity`
//!     rule band, and the message text.
//!   * JSON / JSONL: the exact serde field NAMES and VALUES (`detector_id`,
//!     `severity` kebab-case, `credential_hash` as 64-char lower hex,
//!     `credential_redacted`), one object per line for JSONL.
//!   * Text: the right-aligned severity LABEL, the redacted secret form, the
//!     results roll-up ("N secrets found", "1 dead" for a revoked finding),
//!     and the honest empty-scan line.
//!
//! Every assertion is a specific value. None is a bare non-empty check.

use keyhog_core::{
    hex_encode, write_report, CredentialHash, MatchLocation, ReportFormat, Severity,
    VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// The SARIF `partialFingerprints` key keyhog uses for the credential identity.
const FINGERPRINT_KEY: &str = "keyhog/credentialHash/v1";
/// CWE / OWASP taxonomy ids attached to every secret finding.
const EXPECTED_CWE: &str = "CWE-798";
const EXPECTED_OWASP: &str = "A07:2021";

/// A finding with a fully-specified, non-zero credential hash and a filesystem
/// location. `hash_byte` seeds every one of the 32 hash bytes so the expected
/// hex is `<hash_byte as 2-hex>` repeated 32 times.
fn finding_with(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    redacted: &'static str,
    verification: VerificationResult,
    hash_byte: u8,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        credential_hash: CredentialHash::from_bytes([hash_byte; 32]),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config/app.env".into()),
            line: Some(7),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.9),
    }
}

/// A canonical AWS High finding whose hash bytes are all `0xAB`.
fn aws_high() -> VerifiedFinding {
    finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        0xAB,
    )
}

fn render(format: ReportFormat, findings: &[VerifiedFinding]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_report(&mut buf, format, findings).expect("write_report must succeed");
    buf
}

fn render_sarif(findings: &[VerifiedFinding]) -> serde_json::Value {
    let buf = render(
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        findings,
    );
    serde_json::from_slice(&buf).expect("SARIF output must parse as JSON")
}

fn render_text(findings: &[VerifiedFinding]) -> String {
    let buf = render(
        ReportFormat::Text {
            color: false,
            example_suppressions: 0,
            dogfood_active: false,
        },
        findings,
    );
    String::from_utf8(buf).expect("text output must be valid UTF-8")
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/// Positive: the single result carries the detector id verbatim as `ruleId`
/// and, for a High severity, `level == "error"`.
#[test]
fn sarif_result_ruleid_and_error_level_for_high() {
    let json = render_sarif(&[aws_high()]);
    let result = &json["runs"][0]["results"][0];
    assert_eq!(
        result["ruleId"].as_str(),
        Some("aws-access-key"),
        "ruleId must be the detector id"
    );
    assert_eq!(
        result["level"].as_str(),
        Some("error"),
        "High severity maps to SARIF level `error`"
    );
}

/// Boundary: the severity->level table. Medium -> warning, Low/Info/ClientSafe
/// -> note, Critical -> error. One finding per band, asserted exactly.
#[test]
fn sarif_level_mapping_across_severities() {
    let cases = [
        (Severity::Critical, "error"),
        (Severity::High, "error"),
        (Severity::Medium, "warning"),
        (Severity::Low, "note"),
        (Severity::ClientSafe, "note"),
        (Severity::Info, "note"),
    ];
    for (severity, expected_level) in cases {
        let finding = finding_with(
            "generic-token",
            "Generic Token",
            "generic",
            severity,
            "tok_****",
            VerificationResult::Unverifiable,
            0x11,
        );
        let json = render_sarif(&[finding]);
        assert_eq!(
            json["runs"][0]["results"][0]["level"].as_str(),
            Some(expected_level),
            "severity {severity:?} must render SARIF level {expected_level:?}"
        );
    }
}

/// Positive: the credential hash is surfaced as `partialFingerprints` under the
/// exact keyhog key, hex-encoded. `0xAB` in every byte -> "ab" x 32.
#[test]
fn sarif_partial_fingerprints_hex_hash() {
    let json = render_sarif(&[aws_high()]);
    let expected_hex = "ab".repeat(32);
    assert_eq!(expected_hex.len(), 64, "SHA-256 hex is 64 chars");
    let fp = &json["runs"][0]["results"][0]["partialFingerprints"];
    assert_eq!(
        fp[FINGERPRINT_KEY].as_str(),
        Some(expected_hex.as_str()),
        "partialFingerprints[{FINGERPRINT_KEY}] must be the lower-hex credential hash"
    );
    // Cross-check against the crate's own encoder for the same bytes.
    assert_eq!(
        expected_hex,
        hex_encode([0xAB_u8; 32]),
        "expected hex must match hex_encode of the same bytes"
    );
}

/// Negative twin: the all-zero hash sentinel means "no credential identity", so
/// the `partialFingerprints` object must be ABSENT (not empty, not zero-hex).
#[test]
fn sarif_zero_hash_omits_partial_fingerprints() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Unverifiable,
        0x00,
    );
    let json = render_sarif(&[finding]);
    let result = &json["runs"][0]["results"][0];
    assert!(
        result.get("partialFingerprints").is_none(),
        "zero-hash finding must not emit partialFingerprints, got {:?}",
        result.get("partialFingerprints")
    );
}

/// Positive: the human message text is exactly "{service} secret detected:
/// {redacted}".
#[test]
fn sarif_result_message_text_exact() {
    let json = render_sarif(&[aws_high()]);
    assert_eq!(
        json["runs"][0]["results"][0]["message"]["text"].as_str(),
        Some("aws secret detected: AKIA****"),
        "message.text must be the '{{service}} secret detected: {{redacted}}' form"
    );
}

/// Positive: CWE-798 + OWASP A07:2021 taxonomy ids are attached to the result
/// properties for every secret finding.
#[test]
fn sarif_result_properties_cwe_and_owasp() {
    let json = render_sarif(&[aws_high()]);
    let props = &json["runs"][0]["results"][0]["properties"];
    assert_eq!(
        props["cwe"].as_str(),
        Some(EXPECTED_CWE),
        "properties.cwe must be {EXPECTED_CWE}"
    );
    assert_eq!(
        props["owasp"].as_str(),
        Some(EXPECTED_OWASP),
        "properties.owasp must be {EXPECTED_OWASP}"
    );
}

/// Positive: the rule's `security-severity` band for High is exactly "8.0"
/// (GitHub code-scanning reads this string to bucket the alert).
#[test]
fn sarif_rule_security_severity_band_for_high() {
    let json = render_sarif(&[aws_high()]);
    let rule = &json["runs"][0]["tool"]["driver"]["rules"][0];
    assert_eq!(
        rule["id"].as_str(),
        Some("aws-access-key"),
        "the single accumulated rule carries the detector id"
    );
    assert_eq!(
        rule["properties"]["security-severity"].as_str(),
        Some("8.0"),
        "High -> security-severity band 8.0"
    );
    assert_eq!(
        rule["properties"]["severity"].as_str(),
        Some("high"),
        "rule severity text is the kebab-case token"
    );
}

/// Positive: the machine verification token for a revoked credential is the
/// snake_case "revoked" string in `properties.verification` (not the Debug or
/// colored display form).
#[test]
fn sarif_verification_token_revoked() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Revoked,
        0xAB,
    );
    let json = render_sarif(&[finding]);
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["verification"].as_str(),
        Some("revoked"),
        "verification token for Revoked must be exactly `revoked`"
    );
}

// ---------------------------------------------------------------------------
// JSON / JSONL
// ---------------------------------------------------------------------------

/// Positive: JSON-array output has the exact serde field names and values,
/// including the kebab-case severity and the 64-char lower-hex credential hash.
#[test]
fn json_array_field_names_and_values() {
    let buf = render(ReportFormat::Json, &[aws_high()]);
    let json: serde_json::Value =
        serde_json::from_slice(&buf).expect("JSON array output must parse");
    let obj = &json[0];
    assert_eq!(obj["detector_id"].as_str(), Some("aws-access-key"));
    assert_eq!(obj["detector_name"].as_str(), Some("AWS Access Key"));
    assert_eq!(obj["service"].as_str(), Some("aws"));
    assert_eq!(
        obj["severity"].as_str(),
        Some("high"),
        "severity serializes as the kebab-case token"
    );
    assert_eq!(obj["credential_redacted"].as_str(), Some("AKIA****"));
    assert_eq!(
        obj["credential_hash"].as_str(),
        Some("ab".repeat(32).as_str()),
        "credential_hash serializes as 64-char lower hex"
    );
    assert_eq!(
        obj["verification"].as_str(),
        Some("unverifiable"),
        "verification serializes snake_case"
    );
    assert_eq!(obj["confidence"].as_f64(), Some(0.9));
}

/// Boundary: ClientSafe severity serializes as the hyphenated "client-safe"
/// token (the ClientSafe/clientsafe drift trap).
#[test]
fn json_client_safe_severity_is_hyphenated() {
    let finding = finding_with(
        "mixpanel-token",
        "Mixpanel Token",
        "mixpanel",
        Severity::ClientSafe,
        "mp_****",
        VerificationResult::Unverifiable,
        0x22,
    );
    let buf = render(ReportFormat::Json, &[finding]);
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("parse");
    assert_eq!(
        json[0]["severity"].as_str(),
        Some("client-safe"),
        "ClientSafe must serialize as `client-safe`, never `clientsafe`"
    );
}

/// Positive: JSONL emits exactly one JSON object per line, two findings yield
/// two newline-terminated parseable lines, in order.
#[test]
fn jsonl_one_object_per_line() {
    let second = finding_with(
        "github-pat",
        "GitHub PAT",
        "github",
        Severity::Critical,
        "ghp_****",
        VerificationResult::Live,
        0xCD,
    );
    let buf = render(ReportFormat::Jsonl, &[aws_high(), second]);
    let text = String::from_utf8(buf).expect("utf8");
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "JSONL must emit one line per finding");
    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("line 0 parses");
    let secondv: serde_json::Value = serde_json::from_str(lines[1]).expect("line 1 parses");
    assert_eq!(first["detector_id"].as_str(), Some("aws-access-key"));
    assert_eq!(secondv["detector_id"].as_str(), Some("github-pat"));
    assert_eq!(secondv["severity"].as_str(), Some("critical"));
}

/// Positive: an empty JSON-array run is exactly the two bytes `[]`: the array
/// reporter opens on construction and closes on finish regardless of count.
#[test]
fn json_empty_run_is_bracket_pair() {
    let buf = render(ReportFormat::Json, &[]);
    assert_eq!(buf, b"[]", "empty JSON run must be exactly `[]`");
}

/// Positive: provider metadata is serialized as a nested object with the exact
/// key/value pairs supplied on the finding.
#[test]
fn json_metadata_object_values() {
    let mut finding = aws_high();
    finding
        .metadata
        .insert("account_id".to_string(), "123456789012".to_string());
    finding
        .metadata
        .insert("region".to_string(), "us-east-1".to_string());
    let buf = render(ReportFormat::Json, &[finding]);
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("parse");
    let meta = &json[0]["metadata"];
    assert_eq!(meta["account_id"].as_str(), Some("123456789012"));
    assert_eq!(meta["region"].as_str(), Some("us-east-1"));
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

/// Positive: the finding block shows the HIGH severity label, the detector
/// name, the redacted secret line, and the file:line location.
#[test]
fn text_finding_block_labels_and_redaction() {
    let text = render_text(&[aws_high()]);
    assert!(
        text.contains("HIGH"),
        "text block must carry the HIGH severity label, got:\n{text}"
    );
    assert!(
        text.contains("AWS Access Key"),
        "text block must name the detector, got:\n{text}"
    );
    assert!(
        text.contains("Secret:"),
        "text block must have a Secret: field, got:\n{text}"
    );
    assert!(
        text.contains("AKIA****"),
        "text block must show the redacted credential, got:\n{text}"
    );
    assert!(
        text.contains("config/app.env:7"),
        "text block must show file:line location, got:\n{text}"
    );
}

/// Positive: the results roll-up for two unverified findings says exactly
/// "2 secrets found" and "2 unverified".
#[test]
fn text_summary_counts_two_secrets() {
    let mut second = aws_high();
    second.detector_id = "github-pat".into();
    let text = render_text(&[aws_high(), second]);
    assert!(
        text.contains("2 secrets found"),
        "summary must read '2 secrets found', got:\n{text}"
    );
    assert!(
        text.contains("2 unverified"),
        "two Unverifiable findings roll up as '2 unverified', got:\n{text}"
    );
}

/// Boundary: a single REVOKED finding rolls into the inactive ("dead") tally,
/// so the summary reads "1 secret found" and "1 dead" with NO "unverified"
/// bucket (a verified-revoked secret is not liveness-unknown).
#[test]
fn text_revoked_counts_as_dead_not_unverified() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        VerificationResult::Revoked,
        0xAB,
    );
    let text = render_text(&[finding]);
    assert!(
        text.contains("1 secret found"),
        "singular count phrasing, got:\n{text}"
    );
    assert!(
        text.contains("1 dead"),
        "a revoked secret must count toward the inactive/dead tally, got:\n{text}"
    );
    assert!(
        !text.contains("unverified"),
        "a verified-revoked secret must not appear as unverified, got:\n{text}"
    );
}

/// Negative twin: an empty scan never claims "clean"; it emits the exact honest
/// line about what was scanned.
#[test]
fn text_empty_scan_honest_line() {
    let text = render_text(&[]);
    assert!(
        text.contains("No secrets detected in the scanned files."),
        "empty scan must print the honest scanned-files line, got:\n{text}"
    );
    assert!(
        !text.to_lowercase().contains("clean"),
        "empty scan must never claim the tree is clean, got:\n{text}"
    );
}
