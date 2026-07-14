//! Regression: EXACT output contract of the GitHub Actions workflow-command
//! annotation reporter (`ReportFormat::GithubAnnotations`).
//!
//! NOTE ON NAMING: the requested area was a "SonarQube" report format. There is
//! NO SonarQube reporter in this crate. `ReportFormat` has no `SonarQube`
//! variant and `crates/core/src/report/` ships no `sonar*.rs`. The closest
//! CI-consumed structured reporters are already pinned elsewhere
//! (`regression_report_gitlab_codequality.rs` -> GitLab SAST,
//! `regression_report_junit_xml.rs` -> JUnit, `regression_sarif_*` -> SARIF).
//! This file therefore pins the concrete, byte-level contract of the reporter
//! with the thinnest coverage: `GithubAnnotationsReporter`
//! (`crates/core/src/report/github_annotations.rs`). The existing unit test
//! only exercises the `error` level, a single escaping case, and the empty
//! report. Below we lock the two OTHER severity levels (`warning`/`notice`),
//! the optional-field branches (missing file / missing line / no confidence),
//! the full first-line byte contract, and the data-vs-property escaping split.
//!
//! Every assertion is a specific value: an exact string, an exact substring,
//! an exact level token, or an exact line count. No bare non-empty checks.

use std::borrow::Cow;
use std::collections::HashMap;

use keyhog_core::{
    write_report, CredentialHash, MatchLocation, ReportFormat, Severity, VerificationResult,
    VerifiedFinding,
};

/// Build a fully-specified finding. `hash_byte` seeds all 32 credential-hash
/// bytes. Location fields are caller-controlled so the optional-field branches
/// (`file_path == None`, `line == None`) can be exercised directly.
#[allow(clippy::too_many_arguments)]
fn finding_with(
    detector_id: &'static str,
    detector_name: &'static str,
    service: &'static str,
    severity: Severity,
    redacted: &'static str,
    file_path: Option<&'static str>,
    line: Option<usize>,
    verification: VerificationResult,
    confidence: Option<f64>,
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
        verification,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence,
    }
}

/// Canonical High finding at `config/app.env:12`, live-verified, confidence
/// 0.875. Matches the fixture the existing unit test uses so the exact-byte
/// contract here is directly comparable.
fn canonical_high() -> VerifiedFinding {
    finding_with(
        "aws-access-key",
        "AWS Access Key",
        "aws",
        Severity::High,
        "AKIA...7XYA",
        Some("config/app.env"),
        Some(12),
        VerificationResult::Live,
        Some(0.875),
        0xAB,
    )
}

fn render(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, ReportFormat::GithubAnnotations, findings)
        .expect("GithubAnnotations write_report must succeed");
    String::from_utf8(buf).expect("GithubAnnotations output must be UTF-8")
}

// ---------------------------------------------------------------------------
// Exact byte contract (positive)
// ---------------------------------------------------------------------------

/// The single canonical finding renders to EXACTLY one workflow-command line,
/// byte for byte, terminated by a newline. This pins property order
/// (file,line,title), the `::` data delimiter, message field order, and the
/// `{:.3}` confidence format all at once.
#[test]
fn canonical_finding_exact_annotation_bytes() {
    let out = render(std::slice::from_ref(&canonical_high()));
    assert_eq!(
        out,
        "::error file=config/app.env,line=12,title=keyhog high aws-access-key::\
AWS Access Key detector=aws-access-key service=aws redacted=AKIA...7XYA \
verification=live confidence=0.875\n"
    );
}

// ---------------------------------------------------------------------------
// Severity -> annotation level mapping (positive / boundary)
// ---------------------------------------------------------------------------

/// Critical and High both map to the GitHub `error` annotation level.
#[test]
fn critical_and_high_map_to_error_level() {
    for severity in [Severity::Critical, Severity::High] {
        let f = finding_with(
            "id",
            "Name",
            "svc",
            severity,
            "RED",
            Some("f.env"),
            Some(1),
            VerificationResult::Unverifiable,
            Some(0.5),
            0x01,
        );
        let out = render(std::slice::from_ref(&f));
        assert!(
            out.starts_with("::error "),
            "{severity} must produce an ::error annotation: {out:?}"
        );
    }
}

/// Medium and Low both map to the GitHub `warning` annotation level (the
/// existing unit test never exercises this branch).
#[test]
fn medium_and_low_map_to_warning_level() {
    for severity in [Severity::Medium, Severity::Low] {
        let f = finding_with(
            "id",
            "Name",
            "svc",
            severity,
            "RED",
            Some("f.env"),
            Some(1),
            VerificationResult::Unverifiable,
            Some(0.5),
            0x02,
        );
        let out = render(std::slice::from_ref(&f));
        assert!(
            out.starts_with("::warning "),
            "{severity} must produce a ::warning annotation: {out:?}"
        );
    }
}

/// ClientSafe and Info both map to the GitHub `notice` annotation level.
#[test]
fn clientsafe_and_info_map_to_notice_level() {
    for severity in [Severity::ClientSafe, Severity::Info] {
        let f = finding_with(
            "id",
            "Name",
            "svc",
            severity,
            "RED",
            Some("f.env"),
            Some(1),
            VerificationResult::Unverifiable,
            Some(0.5),
            0x03,
        );
        let out = render(std::slice::from_ref(&f));
        assert!(
            out.starts_with("::notice "),
            "{severity} must produce a ::notice annotation: {out:?}"
        );
    }
}

/// The `title` property embeds the Display form of the severity, which is the
/// kebab-case token (`client-safe`, not `clientsafe`).
#[test]
fn title_uses_kebab_case_client_safe_token() {
    let f = finding_with(
        "id",
        "Name",
        "svc",
        Severity::ClientSafe,
        "RED",
        Some("f.env"),
        Some(1),
        VerificationResult::Unverifiable,
        Some(0.5),
        0x04,
    );
    let out = render(std::slice::from_ref(&f));
    assert!(
        out.contains("title=keyhog client-safe id::"),
        "title must use the kebab-case severity Display token: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// Optional-field branches (boundary)
// ---------------------------------------------------------------------------

/// A finding with no file path omits the `file=` property entirely, and `line`
/// becomes the FIRST property (no leading comma before it).
#[test]
fn missing_file_path_omits_file_property_and_line_is_first() {
    let f = finding_with(
        "id",
        "Name",
        "svc",
        Severity::Medium,
        "RED",
        None,
        Some(7),
        VerificationResult::Unverifiable,
        Some(0.5),
        0x05,
    );
    let out = render(std::slice::from_ref(&f));
    assert!(
        !out.contains("file="),
        "a fileless finding must not emit a file= property: {out:?}"
    );
    assert!(
        out.starts_with("::warning line=7,title=keyhog medium id::"),
        "line must be the first property when file is absent: {out:?}"
    );
}

/// A finding with no line omits the `line=` property; `file` then `title`
/// remain, in that order.
#[test]
fn missing_line_omits_line_property() {
    let f = finding_with(
        "id",
        "Name",
        "svc",
        Severity::Low,
        "RED",
        Some("only/file.env"),
        None,
        VerificationResult::Unverifiable,
        Some(0.5),
        0x06,
    );
    let out = render(std::slice::from_ref(&f));
    assert!(
        !out.contains("line="),
        "a lineless finding must not emit a line= property: {out:?}"
    );
    assert!(
        out.starts_with("::warning file=only/file.env,title=keyhog low id::"),
        "file then title must remain when line is absent: {out:?}"
    );
}

/// With neither file nor line, `title` is the ONLY property (first property,
/// no leading comma).
#[test]
fn missing_file_and_line_leaves_only_title_property() {
    let f = finding_with(
        "id",
        "Name",
        "svc",
        Severity::Info,
        "RED",
        None,
        None,
        VerificationResult::Unverifiable,
        Some(0.5),
        0x07,
    );
    let out = render(std::slice::from_ref(&f));
    assert!(
        out.starts_with("::notice title=keyhog info id::"),
        "title must be the sole property when file and line are both absent: {out:?}"
    );
    assert!(
        !out.contains("file=") && !out.contains("line="),
        "no file/line properties when both are absent: {out:?}"
    );
}

/// When confidence is `None`, the message carries NO ` confidence=` suffix and
/// ends right after the verification token.
#[test]
fn absent_confidence_omits_confidence_suffix() {
    let f = finding_with(
        "id",
        "Name",
        "svc",
        Severity::High,
        "RED",
        Some("f.env"),
        Some(1),
        VerificationResult::Dead,
        None,
        0x08,
    );
    let out = render(std::slice::from_ref(&f));
    assert!(
        !out.contains("confidence="),
        "no confidence field for a finding without a confidence score: {out:?}"
    );
    assert!(
        out.ends_with("verification=dead\n"),
        "message must end at the verification token when confidence is absent: {out:?}"
    );
}

/// Confidence is formatted with exactly three decimals, rounding half-to-even
/// per Rust's float formatting (`0.12345 -> 0.123`, `0.87650 -> 0.876`).
#[test]
fn confidence_formats_to_three_decimals() {
    let low = finding_with(
        "id",
        "Name",
        "svc",
        Severity::High,
        "RED",
        Some("f.env"),
        Some(1),
        VerificationResult::Unverifiable,
        Some(0.123_45),
        0x09,
    );
    assert!(
        render(std::slice::from_ref(&low)).contains("confidence=0.123\n"),
        "0.12345 must render as confidence=0.123"
    );

    let round_up = finding_with(
        "id",
        "Name",
        "svc",
        Severity::High,
        "RED",
        Some("f.env"),
        Some(1),
        VerificationResult::Unverifiable,
        Some(0.456_7),
        0x0A,
    );
    assert!(
        render(std::slice::from_ref(&round_up)).contains("confidence=0.457\n"),
        "0.4567 must render as confidence=0.457"
    );
}

// ---------------------------------------------------------------------------
// Escaping split: property escaping vs command-data escaping (adversarial)
// ---------------------------------------------------------------------------

/// Property values (`file`, `title`) escape colon and comma (they delimit the
/// workflow command), so a detector id with `:`/`,` is percent-encoded inside
/// the title.
#[test]
fn property_values_escape_colon_and_comma() {
    let f = finding_with(
        "x:y,z",
        "Name",
        "svc",
        Severity::High,
        "RED",
        Some("a:b,c.env"),
        Some(1),
        VerificationResult::Unverifiable,
        Some(0.5),
        0x0B,
    );
    let out = render(std::slice::from_ref(&f));
    assert!(
        out.contains("file=a%3Ab%2Cc.env"),
        "file property must percent-escape colon and comma: {out:?}"
    );
    assert!(
        out.contains("title=keyhog high x%3Ay%2Cz::"),
        "title property must percent-escape colon and comma: {out:?}"
    );
}

/// Command DATA (the message after `::`) escapes only `%`, CR, and LF, colon
/// and comma are preserved literally (the reverse of property escaping). This
/// is the exact asymmetry that makes property-vs-data a real distinction.
#[test]
fn command_data_escapes_percent_cr_lf_but_keeps_colon_and_comma() {
    let f = finding_with(
        "id",
        "svc:name,x%y",
        "aws",
        Severity::High,
        "RED",
        Some("f.env"),
        Some(1),
        VerificationResult::Error("a\r\nb".to_string()),
        None,
        0x0C,
    );
    let out = render(std::slice::from_ref(&f));
    // Detector name is the leading token of the message data: colon/comma kept,
    // percent escaped.
    assert!(
        out.contains("::svc:name,x%25y detector=id "),
        "message data keeps colon/comma but escapes percent: {out:?}"
    );
    // Error verification text has its CR/LF percent-escaped, keeping one line.
    assert!(
        out.contains("verification=error: a%0D%0Ab\n"),
        "verification error text must escape CR and LF in data: {out:?}"
    );
    assert_eq!(
        out.lines().count(),
        1,
        "injected CR/LF must not create extra workflow-command lines: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// Cardinality (boundary)
// ---------------------------------------------------------------------------

/// One workflow-command line is emitted PER finding, three findings produce
/// exactly three lines.
#[test]
fn one_line_per_finding() {
    let a = canonical_high();
    let b = finding_with(
        "b-id",
        "B",
        "svc",
        Severity::Low,
        "RED",
        Some("b.env"),
        Some(2),
        VerificationResult::Unverifiable,
        None,
        0x11,
    );
    let c = finding_with(
        "c-id",
        "C",
        "svc",
        Severity::Info,
        "RED",
        None,
        None,
        VerificationResult::Skipped,
        None,
        0x22,
    );
    let findings = vec![a, b, c];
    let out = render(&findings);
    assert_eq!(
        out.lines().count(),
        3,
        "three findings must emit three annotation lines: {out:?}"
    );
    assert_eq!(
        out.matches("::error ").count(),
        1,
        "exactly one ::error line (the High finding): {out:?}"
    );
    assert_eq!(
        out.matches("::notice ").count(),
        1,
        "exactly one ::notice line (the Info finding): {out:?}"
    );
}

/// An empty findings slice produces NO output at all, the annotation reporter
/// has no report skeleton, unlike the JSON/SARIF envelopes.
#[test]
fn empty_findings_produce_no_output() {
    let out = render(&[]);
    assert_eq!(
        out, "",
        "GitHub annotations emit one command per finding and no empty-report skeleton"
    );
}
