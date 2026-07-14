//! Regression: `VerifiedFinding` -> SARIF `runs[0].results[]` FIELD mapping.
//!
//! This pins the per-result object built by
//! `report/sarif.rs::build_sarif_result` / `result_properties` /
//! `location_to_sarif` / `severity_to_level`, distinct from the
//! partialFingerprints test (identity hash) already covered elsewhere. The
//! headline contract is the EXACT `Severity -> SarifLevel` map:
//!
//!   Critical -> "error"     High     -> "error"
//!   Medium   -> "warning"   Low      -> "note"
//!   ClientSafe -> "note"    Info     -> "note"
//!
//! (from `SarifReporter::severity_to_level`, serialized lower-case via
//! `SarifLevel`'s `rename_all = "lowercase"`.)
//!
//! Every assertion pins a concrete value: the exact level string, the exact
//! `message.text` (`"{service} secret detected: {redacted}"`), the exact
//! `ruleId` (= detector_id), the physical-location uri + region fields, and the
//! `properties` bag (verification token, confidence pass-through, the fixed
//! `cwe`/`owasp` taxonomy ids, and `metadata.*`-prefixed flattening).

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// Taxonomy ids the reporter attaches to EVERY result. Owned in
/// `report/sarif.rs` as `CWE_HARDCODED_CREDENTIALS_ID` / `OWASP_AUTH_FAILURES_ID`;
/// pinned here so a value change is a visible, reviewed break.
const CWE_ID: &str = "CWE-798";
const OWASP_ID: &str = "A07:2021";

/// Build a finding with a caller-chosen detector/service/severity/redaction and
/// a simple RELATIVE file path so the emitted uri is host/CWD-independent
/// (`file_path_to_sarif_uri` keeps an already-relative path verbatim, only
/// percent-encoding it).
fn finding(
    detector_id: &str,
    service: &str,
    severity: Severity,
    redacted: &'static str,
    file: Option<&str>,
    line: Option<usize>,
    offset: usize,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: detector_id.into(),
        detector_name: "Test Detector".into(),
        service: service.into(),
        severity,
        credential_redacted: Cow::Borrowed(redacted),
        // Non-zero hash so the result is fully populated; identity value is
        // exercised by the partialFingerprints test, not here.
        credential_hash: keyhog_core::sha256_hash("value-for-this-finding"),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: file.map(Into::into),
            line,
            offset,
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

/// `runs[0].results[idx]`.
fn result(json: &serde_json::Value, idx: usize) -> serde_json::Value {
    json["runs"][0]["results"][idx].clone()
}

/// Render one finding of the given severity and return its `level` string.
fn level_for(severity: Severity) -> String {
    let json = render_sarif(&[finding(
        "aws-access-key",
        "aws",
        severity,
        "AKIA****",
        Some("config.env"),
        Some(1),
        0,
    )]);
    result(&json, 0)["level"]
        .as_str()
        .expect("result.level must be a JSON string")
        .to_string()
}

// ---------------------------------------------------------------------------
// Severity -> level map (the headline contract), one test per severity.
// ---------------------------------------------------------------------------

#[test]
fn critical_severity_maps_to_error_level() {
    assert_eq!(level_for(Severity::Critical), "error");
}

#[test]
fn high_severity_maps_to_error_level() {
    // Negative twin to Medium: High is still "error", not "warning".
    assert_eq!(level_for(Severity::High), "error");
}

#[test]
fn medium_severity_maps_to_warning_level() {
    assert_eq!(level_for(Severity::Medium), "warning");
}

#[test]
fn low_severity_maps_to_note_level() {
    assert_eq!(level_for(Severity::Low), "note");
}

#[test]
fn client_safe_severity_maps_to_note_level() {
    assert_eq!(level_for(Severity::ClientSafe), "note");
}

#[test]
fn info_severity_maps_to_note_level() {
    assert_eq!(level_for(Severity::Info), "note");
}

/// One document with all six severities: the level column must be exactly the
/// mapped strings, in order, and the ONLY level values that ever appear are the
/// three SARIF levels (never a raw "critical"/"high"/"low" leaking through).
#[test]
fn all_six_severities_level_column_and_only_three_levels() {
    let json = render_sarif(&[
        finding("d", "svc", Severity::Critical, "*", Some("a"), Some(1), 0),
        finding("d", "svc", Severity::High, "*", Some("b"), Some(1), 0),
        finding("d", "svc", Severity::Medium, "*", Some("c"), Some(1), 0),
        finding("d", "svc", Severity::Low, "*", Some("e"), Some(1), 0),
        finding("d", "svc", Severity::ClientSafe, "*", Some("f"), Some(1), 0),
        finding("d", "svc", Severity::Info, "*", Some("g"), Some(1), 0),
    ]);
    let levels: Vec<String> = (0..6)
        .map(|i| {
            result(&json, i)["level"]
                .as_str()
                .expect("level string")
                .to_string()
        })
        .collect();
    assert_eq!(
        levels,
        vec!["error", "error", "warning", "note", "note", "note"],
        "severity->level column must map exactly per severity_to_level"
    );
    // Adversarial: no severity name ("critical"/"high"/"medium"/"low"/...) may
    // leak into the level slot; only the three SARIF levels are legal.
    for lvl in &levels {
        assert!(
            matches!(lvl.as_str(), "error" | "warning" | "note"),
            "illegal SARIF level {lvl:?}: only error/warning/note allowed"
        );
    }
}

// ---------------------------------------------------------------------------
// message.text, ruleId
// ---------------------------------------------------------------------------

/// `message.text` is exactly `"{service} secret detected: {credential_redacted}"`.
#[test]
fn message_text_is_service_and_redacted_credential() {
    let json = render_sarif(&[finding(
        "stripe-secret-key",
        "stripe",
        Severity::High,
        "sk_live_****",
        Some("config.env"),
        Some(3),
        0,
    )]);
    assert_eq!(
        result(&json, 0)["message"]["text"].as_str(),
        Some("stripe secret detected: sk_live_****"),
        "message.text must be '<service> secret detected: <redacted>'"
    );
}

/// `ruleId` is the finding's detector_id verbatim (this is what ties a result to
/// its `tool.driver.rules[]` entry).
#[test]
fn rule_id_equals_detector_id() {
    let json = render_sarif(&[finding(
        "github-pat",
        "github",
        Severity::Critical,
        "ghp_****",
        Some("a.env"),
        Some(1),
        0,
    )]);
    assert_eq!(
        result(&json, 0)["ruleId"].as_str(),
        Some("github-pat"),
        "ruleId must equal detector_id"
    );
}

// ---------------------------------------------------------------------------
// locations / region
// ---------------------------------------------------------------------------

/// A relative file path renders as that path in the artifact uri, and a known
/// line with a non-zero offset produces a region with `startLine` and
/// `charOffset` set to the exact values.
#[test]
fn location_uri_relative_path_with_line_and_offset() {
    let json = render_sarif(&[finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("src/creds.env"),
        Some(42),
        128,
    )]);
    let phys = &result(&json, 0)["locations"][0]["physicalLocation"];
    assert_eq!(
        phys["artifactLocation"]["uri"].as_str(),
        Some("src/creds.env"),
        "relative path must pass through verbatim as the uri"
    );
    assert_eq!(
        phys["region"]["startLine"].as_u64(),
        Some(42),
        "region.startLine must equal the finding line"
    );
    assert_eq!(
        phys["region"]["charOffset"].as_u64(),
        Some(128),
        "region.charOffset must equal the finding byte offset"
    );
}

/// Boundary: offset 0 with a known line => region present with `startLine` but
/// NO `charOffset` key at all (the builder omits a zero offset).
#[test]
fn zero_offset_omits_char_offset_but_keeps_line() {
    let json = render_sarif(&[finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("x.env"),
        Some(7),
        0,
    )]);
    let region = &result(&json, 0)["locations"][0]["physicalLocation"]["region"];
    assert_eq!(
        region["startLine"].as_u64(),
        Some(7),
        "startLine must still be present"
    );
    assert!(
        region.get("charOffset").is_none(),
        "charOffset must be omitted when offset == 0, got {region}"
    );
}

/// A path-less finding (stdin / git-history-only) labels the uri as the literal
/// string "stdin", and with no line and zero offset there is NO region object.
#[test]
fn no_file_path_uses_stdin_uri_and_no_region() {
    let json = render_sarif(&[finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        None,
        None,
        0,
    )]);
    let phys = &result(&json, 0)["locations"][0]["physicalLocation"];
    assert_eq!(
        phys["artifactLocation"]["uri"].as_str(),
        Some("stdin"),
        "path-less finding must label uri as 'stdin'"
    );
    assert!(
        phys.get("region").is_none(),
        "no line and zero offset must produce no region, got {phys}"
    );
}

// ---------------------------------------------------------------------------
// properties bag
// ---------------------------------------------------------------------------

/// The CWE/OWASP taxonomy ids are the fixed constants on every result.
#[test]
fn properties_carry_fixed_cwe_and_owasp() {
    let json = render_sarif(&[finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        0,
    )]);
    let props = &result(&json, 0)["properties"];
    assert_eq!(
        props["cwe"].as_str(),
        Some(CWE_ID),
        "properties.cwe must be the hard-coded-credentials CWE"
    );
    assert_eq!(
        props["owasp"].as_str(),
        Some(OWASP_ID),
        "properties.owasp must be the auth-failures OWASP category"
    );
}

/// The verification token in properties is the exact style-token string for the
/// finding's `VerificationResult` (positive: Live; twin: Unverifiable).
#[test]
fn properties_verification_token_matches_result() {
    let mut live = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        0,
    );
    live.verification = VerificationResult::Live;
    let unverifiable = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("b.env"),
        Some(1),
        0,
    );
    let json = render_sarif(&[live, unverifiable]);
    assert_eq!(
        result(&json, 0)["properties"]["verification"].as_str(),
        Some("live"),
        "Live must serialize as the 'live' token"
    );
    assert_eq!(
        result(&json, 1)["properties"]["verification"].as_str(),
        Some("unverifiable"),
        "Unverifiable must serialize as the 'unverifiable' token"
    );
}

/// A finite confidence passes through as the same f64; `None` omits the key.
#[test]
fn properties_confidence_passthrough_and_omitted() {
    let with = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        0,
    );
    let mut without = with.clone();
    without.confidence = None;
    without.location.file_path = Some("b.env".into());
    let json = render_sarif(&[with, without]);
    let c = result(&json, 0)["properties"]["confidence"]
        .as_f64()
        .expect("confidence must be a JSON number when present");
    assert!(
        (c - 0.9).abs() < 1e-9,
        "confidence must pass through as 0.9, got {c}"
    );
    assert!(
        result(&json, 1)["properties"].get("confidence").is_none(),
        "a None confidence must omit the properties.confidence key"
    );
}

#[test]
fn properties_entropy_passthrough_and_omitted() {
    let mut measured = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        0,
    );
    measured.entropy = Some(4.5);
    let mut absent = measured.clone();
    absent.entropy = None;
    absent.location.file_path = Some("b.env".into());
    let json = render_sarif(&[measured, absent]);
    assert_eq!(result(&json, 0)["properties"]["entropy"], 4.5);
    assert!(
        result(&json, 1)["properties"].get("entropy").is_none(),
        "an absent entropy measurement must omit the SARIF property"
    );
}

/// Adversarial: a non-finite confidence (NaN) is coerced to 0.0, never emitted
/// as `null`/`NaN` (which would make the SARIF invalid JSON).
#[test]
fn properties_non_finite_confidence_coerced_to_zero() {
    let mut f = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        0,
    );
    f.confidence = Some(f64::NAN);
    let json = render_sarif(&[f]);
    let c = result(&json, 0)["properties"]["confidence"]
        .as_f64()
        .expect("non-finite confidence must serialize as a finite number, not null");
    assert_eq!(c, 0.0, "NaN confidence must be coerced to exactly 0.0");
}

/// Metadata entries are flattened into properties under a `metadata.` prefix,
/// with the value verbatim.
#[test]
fn properties_metadata_flattened_with_prefix() {
    let mut f = finding(
        "aws-access-key",
        "aws",
        Severity::High,
        "AKIA****",
        Some("a.env"),
        Some(1),
        0,
    );
    f.metadata
        .insert("account_id".to_string(), "123456789012".to_string());
    let json = render_sarif(&[f]);
    let props = &result(&json, 0)["properties"];
    assert_eq!(
        props["metadata.account_id"].as_str(),
        Some("123456789012"),
        "metadata.<key> must flatten into properties with the value verbatim"
    );
    // The bare (un-prefixed) key must NOT exist, the prefix is load-bearing so
    // metadata can never collide with a first-class property like `cwe`.
    assert!(
        props.get("account_id").is_none(),
        "metadata must be prefixed, not emitted under its bare key"
    );
}
