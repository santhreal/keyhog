//! Regression: GitLab SAST security-report (`ReportFormat::GitlabSast`) angles
//! NOT already pinned by `regression_report_gitlab_codequality.rs`.
//!
//! That sibling file already pins the envelope, description/name/message,
//! severity table, identifier mapping, credential/service/hash details, the
//! fingerprint composition, and the missing-file/missing-line fail-closed paths.
//! To avoid duplicating those (ONE PLACE), this file pins the surfaces that file
//! does NOT touch:
//!   * the streaming multi-finding writer: order, count, comma separation;
//!   * the RAW byte contract emitted by the hand-written JSON prefix/suffix;
//!   * the `line > 0` boundary (line == Some(0) is rejected like absent);
//!   * the exact `solution` sentence;
//!   * the PER-vulnerability `scanner` tool identity (distinct from `scan.scanner`);
//!   * every `details.*.type == "text"` and `.name` label;
//!   * adversarial JSON-injection escaping through file path / redacted value;
//!   * an EXACT literal 64-char lower-hex for a varied (non-uniform) hash.
//!
//! Every assertion is a specific value. None is a bare non-empty check.

use keyhog_core::{
    hex_encode, write_report, CredentialHash, MatchLocation, ReportFormat, Severity,
    VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

const SCAN_START: &str = "2026-07-02T09:00:00";
const SCAN_END: &str = "2026-07-02T09:00:30";

#[allow(clippy::too_many_arguments)]
fn finding_with(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    redacted: &'static str,
    file_path: Option<&'static str>,
    line: Option<usize>,
    hash_bytes: [u8; 32],
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: detector_name.into(),
        service: service.into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        credential_hash: CredentialHash::from_bytes(hash_bytes),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: file_path.map(Into::into),
            line,
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.9),
    }
}

fn aws_high() -> VerifiedFinding {
    finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("config/app.env"),
        Some(7),
        [0xAB; 32],
    )
}

fn format() -> ReportFormat {
    ReportFormat::GitlabSast {
        scan_started_at: SCAN_START.to_string(),
        scan_finished_at: SCAN_END.to_string(),
    }
}

/// Render to raw bytes (for byte-level contract assertions).
fn render_bytes(findings: &[VerifiedFinding]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_report(&mut buf, format(), findings).expect("GitLab SAST write_report must succeed");
    buf
}

/// Render and parse as JSON.
fn render(findings: &[VerifiedFinding]) -> serde_json::Value {
    serde_json::from_slice(&render_bytes(findings)).expect("GitLab SAST output must parse as JSON")
}

// ---------------------------------------------------------------------------
// Streaming writer: multiple findings preserve order, count, and separators
// ---------------------------------------------------------------------------

/// Positive: three findings produce a length-3 `vulnerabilities` array whose
/// order matches the input slice order exactly (streamed, not sorted).
#[test]
fn three_findings_preserve_input_order_and_count() {
    let a = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        [0x01; 32],
    );
    let b = finding_with(
        "generic-password",
        "Generic Password",
        "generic",
        Severity::Medium,
        "pw_****",
        Some("b.env"),
        Some(2),
        [0x02; 32],
    );
    let c = finding_with(
        "stripe-secret-key",
        "Stripe Secret Key",
        "stripe",
        Severity::Critical,
        "sk_****",
        Some("c.env"),
        Some(3),
        [0x03; 32],
    );
    let json = render(&[a, b, c]);
    let vulns = json["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert_eq!(vulns.len(), 3, "all three findings must be emitted");
    assert_eq!(
        vulns[0]["identifiers"][0]["value"].as_str(),
        Some("aws-access-key")
    );
    assert_eq!(
        vulns[1]["identifiers"][0]["value"].as_str(),
        Some("generic-password")
    );
    assert_eq!(
        vulns[2]["identifiers"][0]["value"].as_str(),
        Some("stripe-secret-key")
    );
    assert_eq!(vulns[0]["location"]["file"].as_str(), Some("a.env"));
    assert_eq!(vulns[1]["location"]["start_line"].as_u64(), Some(2));
    assert_eq!(vulns[2]["severity"].as_str(), Some("Critical"));
}

/// Adversarial: the streamed comma separators are well-formed even with exactly
/// two findings (the `first_vulnerability` toggle) — the raw bytes contain the
/// separator `},{` between the two objects, not `}{`.
#[test]
fn two_findings_are_comma_separated_in_raw_bytes() {
    let a = aws_high();
    let b = finding_with(
        "generic-password",
        "Generic Password",
        "generic",
        Severity::Low,
        "pw_****",
        Some("b.env"),
        Some(2),
        [0x02; 32],
    );
    let text = String::from_utf8(render_bytes(&[a, b])).expect("utf8");
    assert!(
        text.contains("},{"),
        "two streamed vulnerabilities must be joined by '}},{{', got: {text}"
    );
    assert!(
        !text.contains("}{"),
        "there must be no missing comma between objects"
    );
}

// ---------------------------------------------------------------------------
// Raw-byte contract of the hand-written JSON prefix / suffix
// ---------------------------------------------------------------------------

/// Boundary: an EMPTY scan still emits the exact prefix/suffix envelope bytes,
/// with empty `vulnerabilities` and `remediations` arrays.
#[test]
fn empty_report_raw_byte_envelope() {
    let text = String::from_utf8(render_bytes(&[])).expect("utf8");
    assert!(
        text.starts_with("{\"version\":\"15.2.4\","),
        "must start with the pinned version prefix, got: {text}"
    );
    assert!(
        text.contains(",\"vulnerabilities\":[]"),
        "empty scan emits an empty vulnerabilities array inline"
    );
    assert!(
        text.ends_with("],\"remediations\":[]}"),
        "must end with the empty-remediations suffix, got: {text}"
    );
}

/// Positive: with one finding, the raw bytes open the vulnerabilities array
/// immediately after the scan envelope and close with the remediations suffix.
#[test]
fn one_finding_raw_byte_suffix() {
    let text = String::from_utf8(render_bytes(&[aws_high()])).expect("utf8");
    assert!(
        text.starts_with("{\"version\":\"15.2.4\","),
        "version prefix"
    );
    assert!(
        text.contains(",\"vulnerabilities\":[{"),
        "the array must open directly onto the first vulnerability object"
    );
    assert!(
        text.ends_with("}],\"remediations\":[]}"),
        "suffix closes the object, the array, and appends empty remediations"
    );
}

// ---------------------------------------------------------------------------
// line > 0 boundary
// ---------------------------------------------------------------------------

/// Boundary: line == Some(0) is rejected exactly like an absent line (the guard
/// is `line > 0`, not `line.is_some()`), failing the report closed.
#[test]
fn line_zero_fails_closed_like_absent() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("config/app.env"),
        Some(0),
        [0xAB; 32],
    );
    let mut buf = Vec::new();
    let err = write_report(&mut buf, format(), &[finding])
        .expect_err("line 0 must fail the GitLab SAST report closed");
    assert!(
        err.to_string().contains("one-based line number"),
        "line 0 must be rejected with the one-based-line message, got: {err}"
    );
}

/// Boundary twin: line == Some(1) is the minimum valid line and renders
/// `start_line == 1`.
#[test]
fn line_one_is_the_minimum_valid_line() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("config/app.env"),
        Some(1),
        [0xAB; 32],
    );
    let json = render(&[finding]);
    assert_eq!(
        json["vulnerabilities"][0]["location"]["start_line"].as_u64(),
        Some(1),
        "line 1 is valid and rendered verbatim"
    );
}

/// Positive: a large line number survives round-trip as an exact integer.
#[test]
fn large_line_number_round_trips_exactly() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("big.env"),
        Some(1_000_000),
        [0xAB; 32],
    );
    let json = render(&[finding]);
    assert_eq!(
        json["vulnerabilities"][0]["location"]["start_line"].as_u64(),
        Some(1_000_000),
    );
    assert_eq!(
        json["vulnerabilities"][0]["id"].as_str(),
        Some(
            format!(
                "keyhog:aws-access-key:{}:big.env:1000000",
                hex_encode([0xAB_u8; 32])
            )
            .as_str()
        ),
        "the fingerprint carries the large line verbatim"
    );
}

// ---------------------------------------------------------------------------
// Fixed strings not pinned elsewhere: solution, per-vuln scanner, detail types
// ---------------------------------------------------------------------------

/// Positive: the `solution` field is the exact fixed remediation sentence.
#[test]
fn solution_field_is_exact_fixed_sentence() {
    let json = render(&[aws_high()]);
    assert_eq!(
        json["vulnerabilities"][0]["solution"].as_str(),
        Some(
            "Rotate this credential, revoke the exposed value, and load the \
             replacement from a secret manager or CI secret variable."
        ),
        "solution must be the exact fixed remediation sentence"
    );
}

/// Positive: each vulnerability carries its OWN `scanner` tool object (distinct
/// JSON node from `scan.scanner`) with the full keyhog identity.
#[test]
fn per_vulnerability_scanner_identity() {
    let json = render(&[aws_high()]);
    let scanner = &json["vulnerabilities"][0]["scanner"];
    assert_eq!(scanner["id"].as_str(), Some("keyhog"));
    assert_eq!(scanner["name"].as_str(), Some("KeyHog"));
    assert_eq!(scanner["vendor"]["name"].as_str(), Some("Santh Security"));
    assert_eq!(
        scanner["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "per-vuln scanner.version must be the compiled crate version"
    );
    assert_eq!(
        scanner["url"].as_str(),
        Some(env!("CARGO_PKG_REPOSITORY")),
        "per-vuln scanner.url must track the crate manifest repository"
    );
}

/// Positive: every `details.*` entry is typed `"text"` and carries its fixed
/// display-name label.
#[test]
fn detail_entries_are_typed_text_with_fixed_names() {
    let json = render(&[aws_high()]);
    let details = &json["vulnerabilities"][0]["details"];
    assert_eq!(details["credential"]["type"].as_str(), Some("text"));
    assert_eq!(
        details["credential"]["name"].as_str(),
        Some("Redacted credential")
    );
    assert_eq!(details["service"]["type"].as_str(), Some("text"));
    assert_eq!(details["service"]["name"].as_str(), Some("Service"));
    assert_eq!(details["credential_hash"]["type"].as_str(), Some("text"));
    assert_eq!(
        details["credential_hash"]["name"].as_str(),
        Some("Credential hash")
    );
}

// ---------------------------------------------------------------------------
// Exact literal hex for a varied (non-uniform) credential hash
// ---------------------------------------------------------------------------

/// Positive: a hash whose 32 bytes are 0x00..=0x1F renders as the exact
/// canonical lower-hex string (no uppercase, no truncation), and the same
/// string appears in both `details.credential_hash.value` and the `id`.
#[test]
fn varied_hash_renders_exact_lowercase_hex() {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = i as u8;
    }
    const EXPECTED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("h.env"),
        Some(5),
        bytes,
    );
    let json = render(&[finding]);
    assert_eq!(EXPECTED_HEX.len(), 64, "SHA-256 hex is 64 chars");
    assert_eq!(
        json["vulnerabilities"][0]["details"]["credential_hash"]["value"].as_str(),
        Some(EXPECTED_HEX),
        "credential_hash must be the exact lower-hex of the 0x00..0x1F digest"
    );
    assert_eq!(
        json["vulnerabilities"][0]["id"].as_str(),
        Some(format!("keyhog:aws-access-key:{EXPECTED_HEX}:h.env:5").as_str()),
        "the id embeds the same exact hex"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: JSON-injection escaping through untrusted string fields
// ---------------------------------------------------------------------------

/// Adversarial: a file path containing JSON metacharacters (`"`, `\`, `{`) is
/// escaped so the whole document still parses, and `location.file` decodes back
/// to the exact original bytes — no injection, no truncation.
#[test]
fn file_path_with_json_metacharacters_is_escaped_not_injected() {
    let nasty = "a\"b\\c{\"x\":1}.env";
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some(nasty),
        Some(9),
        [0xCD; 32],
    );
    // Must still parse as a single well-formed document.
    let json = render(&[finding]);
    assert_eq!(
        json["vulnerabilities"][0]["location"]["file"].as_str(),
        Some(nasty),
        "location.file must decode back to the exact untrusted path"
    );
    // And it must remain a length-1 array (no injected sibling object).
    assert_eq!(
        json["vulnerabilities"].as_array().map(Vec::len),
        Some(1),
        "a crafted path must not inject extra array entries"
    );
}

/// Adversarial twin: a redacted-credential value containing a control byte and a
/// quote is escaped; the parsed `details.credential.value` equals the original.
#[test]
fn redacted_value_with_quote_and_control_is_escaped() {
    let nasty = "AKIA\"\n\tEVIL";
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        nasty,
        Some("r.env"),
        Some(4),
        [0xEF; 32],
    );
    let json = render(&[finding]);
    assert_eq!(
        json["vulnerabilities"][0]["details"]["credential"]["value"].as_str(),
        Some(nasty),
        "the redacted value must round-trip through JSON escaping unchanged"
    );
}
