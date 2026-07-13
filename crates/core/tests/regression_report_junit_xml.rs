//! JUnit XML report regression tests.
//!
//! Pins the exact wire form of the JUnit reporter reached through the public
//! `write_report(_, ReportFormat::Junit, _)` entrypoint: a finding maps to a
//! `<testcase>`/`<failure>` pair with exact `name`/`classname`/`message`/`type`
//! attributes, the enclosing `<testsuite>` carries exact `tests`/`failures`
//! tallies, XML-special and XML-illegal-control characters are escaped, the
//! CDATA terminator is neutralized, and an empty finding set still emits a
//! structurally valid (but empty) suite.
//!
//! Every assertion is a concrete expected value read from the reporter source
//! (`crates/core/src/report/junit.rs`) and the shared escaper
//! (`crates/core/src/report/escape.rs`), not an assumption. Distinct from
//! `regression_report_alt_formats.rs`: this file drives only JUnit and asserts
//! full-line XML fragments rather than cross-format shape.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};

/// The canonical finding used across these tests. Mirrors the shape the shared
/// test support fixture uses so the pinned attribute values stay stable:
/// detector name deliberately carries `"`, `<`, `>`, `&` to exercise escaping.
fn sample_finding() -> VerifiedFinding {
    let mut metadata = HashMap::new();
    metadata.insert("account_id".to_string(), "123456789012".to_string());

    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key, \"prod\" <a&b>"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [
            0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]
        .into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config/app.env")),
            line: Some(12),
            offset: 5,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata,
        additional_locations: vec![],
        confidence: Some(0.875),
    }
}

/// Render findings through the public JUnit report path.
fn render(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, ReportFormat::Junit, findings).expect("junit write_report");
    String::from_utf8(buf).expect("utf8 junit output")
}

/// The 64-char hex encoding of the sample credential hash: `deadbeef` followed
/// by 28 zero bytes.
fn sample_hash_hex() -> String {
    format!("deadbeef{}", "0".repeat(56))
}

#[test]
fn header_and_wrapper_are_exact() {
    let out = render(&[sample_finding()]);
    assert!(
        out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n"),
        "prolog/wrapper prefix wrong: {out:?}"
    );
    assert!(
        out.ends_with("  </testsuite>\n</testsuites>\n"),
        "suite/wrapper suffix wrong: {out:?}"
    );
}

#[test]
fn testsuite_line_tallies_single_finding_exactly() {
    let out = render(&[sample_finding()]);
    assert!(
        out.contains(
            "  <testsuite name=\"keyhog\" tests=\"1\" failures=\"1\" errors=\"0\" time=\"0.0\">"
        ),
        "single-finding testsuite line wrong: {out:?}"
    );
}

#[test]
fn testcase_open_line_is_exact() {
    let out = render(&[sample_finding()]);
    assert!(
        out.contains(
            "    <testcase name=\"config/app.env:12:aws-access-key\" classname=\"keyhog.findings\" time=\"0.0\">"
        ),
        "testcase open line wrong: {out:?}"
    );
}

#[test]
fn failure_line_escapes_message_and_carries_severity_type() {
    let out = render(&[sample_finding()]);
    // `"` -> &quot;, `<` -> &lt;, `&` -> &amp;, `>` -> &gt;; type is the
    // severity `as_str()` ("high"), itself run through the attribute escaper.
    assert!(
        out.contains(
            "      <failure message=\"Secret detected: AWS Key, &quot;prod&quot; &lt;a&amp;b&gt; (id: aws-access-key)\" type=\"high\">"
        ),
        "failure line escaping/type wrong: {out:?}"
    );
}

#[test]
fn cdata_body_lines_are_exact() {
    let out = render(&[sample_finding()]);
    // Inside CDATA, XML metacharacters are NOT entity-escaped: the detector
    // name appears verbatim.
    for line in [
        "Detector Name: AWS Key, \"prod\" <a&b>",
        "Detector ID:   aws-access-key",
        "Service:       aws",
        "Severity:      high",
        "Source:        filesystem",
        "File Path:     config/app.env",
        "Line:          12",
        "Offset:        5",
        "Redacted:      AKIA...7XYA",
        "Verification:  live",
        "Confidence:    0.875",
    ] {
        assert!(
            out.contains(line),
            "missing exact CDATA line {line:?}: {out:?}"
        );
    }
    assert!(
        out.contains(&format!("Hash:          {}", sample_hash_hex())),
        "hash hex line wrong: {out:?}"
    );
    // CDATA open marker present exactly once for a single finding.
    assert_eq!(
        out.matches("<![CDATA[").count(),
        1,
        "one CDATA block: {out:?}"
    );
}

#[test]
fn tallies_and_element_counts_scale_with_findings() {
    let findings = vec![sample_finding(), sample_finding(), sample_finding()];
    let out = render(&findings);
    assert!(
        out.contains(
            "  <testsuite name=\"keyhog\" tests=\"3\" failures=\"3\" errors=\"0\" time=\"0.0\">"
        ),
        "3-finding tallies wrong: {out:?}"
    );
    assert_eq!(
        out.matches("<testcase name=").count(),
        3,
        "expected 3 testcases: {out:?}"
    );
    assert_eq!(
        out.matches("<failure message=").count(),
        3,
        "expected 3 failures: {out:?}"
    );
    // Every JUnit report has exactly one enclosing suite regardless of count.
    assert_eq!(
        out.matches("<testsuite ").count(),
        1,
        "exactly one testsuite: {out:?}"
    );
}

#[test]
fn empty_findings_emit_exact_empty_suite() {
    let out = render(&[]);
    // NB: no `\`-line-continuation, that strips the leading whitespace of the
    // next source line, which would drop the real 2-space indentation below.
    let expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n  <testsuite name=\"keyhog\" tests=\"0\" failures=\"0\" errors=\"0\" time=\"0.0\">\n  </testsuite>\n</testsuites>\n";
    assert_eq!(out, expected, "empty-suite bytes wrong");
    // No testcase/failure elements at all.
    assert_eq!(out.matches("<testcase").count(), 0);
    assert_eq!(out.matches("<failure").count(), 0);
}

#[test]
fn case_name_without_file_path_uses_detector_and_line() {
    let mut finding = sample_finding();
    finding.location.file_path = None;
    let out = render(&[finding]);
    // file empty branch: "{detector_id}:{line}".
    assert!(
        out.contains("<testcase name=\"aws-access-key:12\" classname=\"keyhog.findings\""),
        "no-file case name wrong: {out:?}"
    );
    // The `File Path:` CDATA line is omitted when there is no path.
    assert!(
        !out.contains("File Path:"),
        "File Path line must be absent when no path: {out:?}"
    );
}

#[test]
fn case_name_with_file_but_no_line_omits_line() {
    let mut finding = sample_finding();
    finding.location.line = None;
    let out = render(&[finding]);
    // line empty branch: "{file_path}:{detector_id}".
    assert!(
        out.contains(
            "<testcase name=\"config/app.env:aws-access-key\" classname=\"keyhog.findings\""
        ),
        "no-line case name wrong: {out:?}"
    );
    assert!(
        !out.contains("Line:"),
        "Line CDATA line must be absent when line is None: {out:?}"
    );
}

#[test]
fn failure_type_reflects_each_severity_label() {
    for (severity, expected) in [
        (Severity::Info, "info"),
        (Severity::ClientSafe, "client-safe"),
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ] {
        let mut finding = sample_finding();
        finding.severity = severity;
        let out = render(&[finding]);
        assert!(
            out.contains(&format!("type=\"{expected}\">")),
            "severity {expected:?} must render as failure type: {out:?}"
        );
        assert!(
            out.contains(&format!("Severity:      {expected}")),
            "severity {expected:?} CDATA line wrong: {out:?}"
        );
    }
}

#[test]
fn cdata_terminator_in_credential_is_neutralized() {
    let mut finding = sample_finding();
    finding.credential_redacted = Cow::Owned("AK]]>IA".to_string());
    let out = render(&[finding]);
    // escape_cdata splits the terminator so it cannot close the CDATA early.
    assert!(
        out.contains("Redacted:      AK]]]]><![CDATA[>IA"),
        "CDATA terminator not neutralized: {out:?}"
    );
    // The raw redacted value must not appear as a lone terminator inside a
    // Redacted line (it would break the CDATA section).
    assert!(
        !out.contains("Redacted:      AK]]>IA"),
        "raw CDATA terminator leaked: {out:?}"
    );
}

#[test]
fn xml_illegal_control_chars_replaced_with_fffd() {
    let mut finding = sample_finding();
    // Control bytes across an attribute surface (file path drives case_name)
    // and a CDATA surface (git author).
    finding.location.file_path = Some(Arc::from("config/ev\u{1}il.env"));
    finding.location.author = Some(Arc::from("Bad\u{7}Actor"));
    let out = render(&[finding]);

    let illegal: Vec<u32> = out
        .chars()
        .map(|c| c as u32)
        .filter(|&u| u < 0x20 && !matches!(u, 0x09 | 0x0A | 0x0D))
        .collect();
    assert!(
        illegal.is_empty(),
        "output carries XML-1.0-illegal control codepoints {illegal:?}: {out:?}"
    );
    // The bytes are made visible (Law 10: no silent drop), not deleted.
    assert!(
        out.contains("Author:        Bad\u{FFFD}Actor"),
        "author control byte must become U+FFFD: {out:?}"
    );
    assert!(
        out.contains("config/ev\u{FFFD}il.env"),
        "file-path control byte must become U+FFFD: {out:?}"
    );
}

#[test]
fn confidence_none_omits_confidence_line() {
    let mut finding = sample_finding();
    finding.confidence = None;
    let out = render(&[finding]);
    assert!(
        !out.contains("Confidence:"),
        "Confidence line must be absent when confidence is None: {out:?}"
    );
    // Twin: a present confidence DOES render.
    let out_with = render(&[sample_finding()]);
    assert!(
        out_with.contains("Confidence:    0.875"),
        "confidence line missing when present: {out_with:?}"
    );
}

#[test]
fn verification_error_token_includes_message() {
    let mut finding = sample_finding();
    finding.verification = VerificationResult::Error("boom".to_string());
    let out = render(&[finding]);
    assert!(
        out.contains("Verification:  error: boom"),
        "error verification token wrong: {out:?}"
    );
}

#[test]
fn commit_author_date_lines_present_only_when_set() {
    // Negative twin first: the default sample has none of these history fields.
    let bare = render(&[sample_finding()]);
    for label in ["Commit:", "Author:", "Date:"] {
        assert!(
            !bare.contains(label),
            "history line {label:?} must be absent when unset: {bare:?}"
        );
    }

    let mut finding = sample_finding();
    finding.location.commit = Some(Arc::from("abc123"));
    finding.location.author = Some(Arc::from("Jane Doe"));
    finding.location.date = Some(Arc::from("2026-07-01"));
    let out = render(&[finding]);
    assert!(
        out.contains("Commit:        abc123"),
        "commit line: {out:?}"
    );
    assert!(
        out.contains("Author:        Jane Doe"),
        "author line: {out:?}"
    );
    assert!(
        out.contains("Date:          2026-07-01"),
        "date line: {out:?}"
    );
}
