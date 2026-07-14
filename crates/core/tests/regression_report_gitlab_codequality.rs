//! Regression: EXACT byte/JSON contract of the GitLab code-quality/security
//! report format keyhog ships (`ReportFormat::GitlabSast`).
//!
//! NOTE ON NAMING: the *only* GitLab reporter in the crate is the GitLab SAST
//! security-report reporter (`crates/core/src/report/gitlab_sast.rs`); there is
//! no separate "Code Quality" reporter. GitLab's SAST security report is the
//! surface CI consumes for secret findings, and it carries exactly the fields a
//! code-quality integration cares about: a stable per-finding fingerprint
//! (`vulnerability.id`), a human `description`, a `severity`, and a
//! `location.file` + `location.start_line`. These tests pin those.
//!
//! Every assertion is a specific value. None is a bare non-empty check.

use keyhog_core::{
    hex_encode, write_report, CredentialHash, MatchLocation, ReportFormat, Severity,
    VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

const SCHEMA_VERSION: &str = "15.2.4";
const SCHEMA_URL: &str =
    "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json";
const SCAN_START: &str = "2026-07-01T00:00:00";
const SCAN_END: &str = "2026-07-01T00:05:00";

/// Build a fully-specified finding. `hash_byte` seeds all 32 credential-hash
/// bytes, so the expected hex is `<hash_byte as 2-hex>` repeated 32 times.
fn finding_with(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    redacted: &'static str,
    file_path: Option<&'static str>,
    line: Option<usize>,
    hash_byte: u8,
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
        entropy: None,
        confidence: Some(0.9),
    }
}

/// Canonical AWS High finding: hash bytes all `0xAB`, at `config/app.env:7`.
fn aws_high() -> VerifiedFinding {
    finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("config/app.env"),
        Some(7),
        0xAB,
    )
}

fn render(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::GitlabSast {
            scan_started_at: SCAN_START.to_string(),
            scan_finished_at: SCAN_END.to_string(),
        },
        findings,
    )
    .expect("GitLab SAST write_report must succeed");
    serde_json::from_slice(&buf).expect("GitLab SAST output must parse as JSON")
}

// ---------------------------------------------------------------------------
// Empty report
// ---------------------------------------------------------------------------

/// Boundary: an empty findings slice still produces a schema-valid report with
/// an EMPTY (not null, not missing) `vulnerabilities` array and empty
/// `remediations`, plus the version/schema envelope.
#[test]
fn empty_findings_emit_valid_empty_arrays() {
    let json = render(&[]);
    assert_eq!(
        json["vulnerabilities"].as_array().map(Vec::len),
        Some(0),
        "empty scan must emit an empty vulnerabilities array"
    );
    assert_eq!(
        json["remediations"].as_array().map(Vec::len),
        Some(0),
        "empty scan must emit an empty remediations array"
    );
    assert_eq!(
        json["version"].as_str(),
        Some(SCHEMA_VERSION),
        "version envelope must be present even for an empty report"
    );
}

// ---------------------------------------------------------------------------
// Envelope: version / schema / scan metadata / tool identity
// ---------------------------------------------------------------------------

/// Positive: the top-level `version` and `schema` URL are the pinned constants.
#[test]
fn envelope_version_and_schema_url_exact() {
    let json = render(&[aws_high()]);
    assert_eq!(json["version"].as_str(), Some(SCHEMA_VERSION));
    assert_eq!(json["schema"].as_str(), Some(SCHEMA_URL));
}

/// Positive: the `scan` object echoes the caller-supplied timestamps and pins
/// `type == "sast"` and `status == "success"`.
#[test]
fn scan_object_type_status_and_timestamps() {
    let json = render(&[aws_high()]);
    let scan = &json["scan"];
    assert_eq!(scan["type"].as_str(), Some("sast"));
    assert_eq!(scan["status"].as_str(), Some("success"));
    assert_eq!(
        scan["start_time"].as_str(),
        Some(SCAN_START),
        "scan.start_time must echo the caller's start timestamp"
    );
    assert_eq!(
        scan["end_time"].as_str(),
        Some(SCAN_END),
        "scan.end_time must echo the caller's end timestamp"
    );
}

/// Positive: both `analyzer` and `scanner` tool objects carry the fixed keyhog
/// identity, the compiled crate version, and the Santh vendor name.
#[test]
fn tool_identity_analyzer_and_scanner() {
    let json = render(&[aws_high()]);
    for role in ["analyzer", "scanner"] {
        let tool = &json["scan"][role];
        assert_eq!(tool["id"].as_str(), Some("keyhog"), "{role}.id");
        assert_eq!(tool["name"].as_str(), Some("KeyHog"), "{role}.name");
        assert_eq!(
            tool["vendor"]["name"].as_str(),
            Some("Santh Security"),
            "{role}.vendor.name"
        );
        assert_eq!(
            tool["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION")),
            "{role}.version must be the compiled crate version"
        );
    }
}

// ---------------------------------------------------------------------------
// Vulnerability body: description / severity / location / identifiers
// ---------------------------------------------------------------------------

/// Positive: the human `description` is the exact rotate-and-remove sentence,
/// service-interpolated.
#[test]
fn vulnerability_description_exact() {
    let json = render(&[aws_high()]);
    assert_eq!(
        json["vulnerabilities"][0]["description"].as_str(),
        Some(
            "KeyHog detected a redacted aws credential. \
             Rotate the credential and remove it from source control."
        ),
        "description must be the service-interpolated rotate sentence"
    );
}

/// Positive: `name` and `message` are the exact service/detector-interpolated
/// strings.
#[test]
fn vulnerability_name_and_message_exact() {
    let json = render(&[aws_high()]);
    let vuln = &json["vulnerabilities"][0];
    assert_eq!(
        vuln["name"].as_str(),
        Some("aws credential detected"),
        "name is '{{service}} credential detected'"
    );
    assert_eq!(
        vuln["message"].as_str(),
        Some("AWS Access Key found by aws-access-key at config/app.env:7"),
        "message is '{{detector_name}} found by {{detector_id}} at {{file}}:{{line}}'"
    );
}

/// Boundary: the severity->GitLab-label table. Both `ClientSafe` and `Info`
/// collapse to "Info"; everything else is Title-cased 1:1.
#[test]
fn severity_label_mapping_table() {
    let cases = [
        (Severity::Critical, "Critical"),
        (Severity::High, "High"),
        (Severity::Medium, "Medium"),
        (Severity::Low, "Low"),
        (Severity::ClientSafe, "Info"),
        (Severity::Info, "Info"),
    ];
    for (severity, expected) in cases {
        let finding = finding_with(
            "generic-password",
            "Generic Password",
            "generic",
            severity,
            "pw_****",
            Some("config/app.env"),
            Some(7),
            0x11,
        );
        let json = render(&[finding]);
        assert_eq!(
            json["vulnerabilities"][0]["severity"].as_str(),
            Some(expected),
            "severity {severity:?} must render GitLab label {expected:?}"
        );
    }
}

/// Positive: `location.file` and `location.start_line` carry the finding's
/// filesystem path and one-based line verbatim, and `category` is "sast".
#[test]
fn location_file_start_line_and_category() {
    let json = render(&[aws_high()]);
    let vuln = &json["vulnerabilities"][0];
    assert_eq!(vuln["category"].as_str(), Some("sast"));
    assert_eq!(
        vuln["location"]["file"].as_str(),
        Some("config/app.env"),
        "location.file must be the finding path"
    );
    assert_eq!(
        vuln["location"]["start_line"].as_u64(),
        Some(7),
        "location.start_line must be the one-based line"
    );
}

/// Positive: the single `identifiers` entry maps the keyhog rule name/value to
/// the detector name/id under `type == "keyhog_rule"`.
#[test]
fn identifier_maps_detector_name_and_id() {
    let json = render(&[aws_high()]);
    let ident = &json["vulnerabilities"][0]["identifiers"][0];
    assert_eq!(ident["type"].as_str(), Some("keyhog_rule"));
    assert_eq!(
        ident["name"].as_str(),
        Some("AWS Access Key"),
        "identifier.name is the detector display name"
    );
    assert_eq!(
        ident["value"].as_str(),
        Some("aws-access-key"),
        "identifier.value is the detector id"
    );
}

/// Positive: the `details` block surfaces the redacted credential, the service,
/// and the 64-char lower-hex credential hash under stable text-detail labels.
#[test]
fn details_credential_service_and_hash() {
    let json = render(&[aws_high()]);
    let details = &json["vulnerabilities"][0]["details"];
    assert_eq!(
        details["credential"]["value"].as_str(),
        Some("AKIA****"),
        "details.credential.value is the redacted secret"
    );
    assert_eq!(
        details["credential"]["name"].as_str(),
        Some("Redacted credential")
    );
    assert_eq!(details["service"]["value"].as_str(), Some("aws"));
    let expected_hex = hex_encode([0xAB_u8; 32]);
    assert_eq!(expected_hex.len(), 64, "SHA-256 hex is 64 chars");
    assert_eq!(
        details["credential_hash"]["value"].as_str(),
        Some(expected_hex.as_str()),
        "details.credential_hash.value is the lower-hex credential hash"
    );
}

// ---------------------------------------------------------------------------
// Fingerprint stability
// ---------------------------------------------------------------------------

/// Positive: the `id` fingerprint is composed as
/// `keyhog:{detector_id}:{hex_hash}:{file}:{start_line}`.
#[test]
fn fingerprint_id_composition_exact() {
    let json = render(&[aws_high()]);
    let expected = format!(
        "keyhog:aws-access-key:{}:config/app.env:7",
        hex_encode([0xAB_u8; 32])
    );
    assert_eq!(
        json["vulnerabilities"][0]["id"].as_str(),
        Some(expected.as_str()),
        "id must be keyhog:{{detector}}:{{hash}}:{{file}}:{{line}}"
    );
}

/// Positive: the fingerprint is STABLE, two independent renders of the same
/// finding produce byte-identical `id`s.
#[test]
fn fingerprint_stable_across_renders() {
    let a = render(&[aws_high()]);
    let b = render(&[aws_high()]);
    let id_a = a["vulnerabilities"][0]["id"].as_str().unwrap();
    let id_b = b["vulnerabilities"][0]["id"].as_str().unwrap();
    assert_eq!(
        id_a, id_b,
        "identical findings must yield identical fingerprints"
    );
}

/// Negative twin: moving the credential to a different file/line changes the
/// fingerprint (location is part of identity), so it is NOT accidentally
/// location-independent.
#[test]
fn fingerprint_changes_with_location() {
    let base = render(&[aws_high()]);
    let moved = render(&[finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("src/other.txt"),
        Some(42),
        0xAB,
    )]);
    let id_base = base["vulnerabilities"][0]["id"].as_str().unwrap();
    let id_moved = moved["vulnerabilities"][0]["id"].as_str().unwrap();
    assert_ne!(
        id_base, id_moved,
        "distinct location must yield a distinct fingerprint"
    );
    assert_eq!(
        id_moved,
        format!(
            "keyhog:aws-access-key:{}:src/other.txt:42",
            hex_encode([0xAB_u8; 32])
        ),
        "moved fingerprint reflects the new file/line"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed: SAST requires a file path and a line
// ---------------------------------------------------------------------------

/// Adversarial: a finding with NO file path must fail the whole report closed
/// (not silently drop the finding or emit an empty path). The error names the
/// requirement and points the operator at json/sarif.
#[test]
fn missing_file_path_fails_closed() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        None,
        Some(7),
        0xAB,
    );
    let mut buf = Vec::new();
    let err = write_report(
        &mut buf,
        ReportFormat::GitlabSast {
            scan_started_at: SCAN_START.to_string(),
            scan_finished_at: SCAN_END.to_string(),
        },
        &[finding],
    )
    .expect_err("missing file path must fail the GitLab SAST report closed");
    let msg = err.to_string();
    assert!(
        msg.contains("requires a non-empty file path"),
        "error must name the file-path requirement, got: {msg}"
    );
}

/// Adversarial twin: an empty-string file path is treated the same as absent
/// fail closed, not emit `location.file == ""`.
#[test]
fn empty_file_path_fails_closed() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some(""),
        Some(7),
        0xAB,
    );
    let mut buf = Vec::new();
    let err = write_report(
        &mut buf,
        ReportFormat::GitlabSast {
            scan_started_at: SCAN_START.to_string(),
            scan_finished_at: SCAN_END.to_string(),
        },
        &[finding],
    )
    .expect_err("empty file path must fail the GitLab SAST report closed");
    assert!(
        err.to_string().contains("requires a non-empty file path"),
        "empty path must be rejected like an absent one"
    );
}

/// Adversarial: a finding with no line number fails closed with the one-based
/// line requirement in the message.
#[test]
fn missing_line_fails_closed() {
    let finding = finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("config/app.env"),
        None,
        0xAB,
    );
    let mut buf = Vec::new();
    let err = write_report(
        &mut buf,
        ReportFormat::GitlabSast {
            scan_started_at: SCAN_START.to_string(),
            scan_finished_at: SCAN_END.to_string(),
        },
        &[finding],
    )
    .expect_err("missing line must fail the GitLab SAST report closed");
    let msg = err.to_string();
    assert!(
        msg.contains("one-based line number"),
        "error must name the line requirement, got: {msg}"
    );
}
