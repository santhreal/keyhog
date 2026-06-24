use super::report_common::sample_finding;
use crate::support::reporters::JunitReporter;
use keyhog_core::VerificationResult;

fn render(finding: &keyhog_core::VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = JunitReporter::new(&mut buf);
        reporter.report(finding).expect("report finding");
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 junit output")
}

#[test]
fn junit_wraps_finding_in_testsuites_with_failure() {
    let out = render(&sample_finding());

    assert!(out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n"));
    assert!(out.trim_end().ends_with("</testsuites>"));
    assert!(
        out.contains(
            "<testsuite name=\"keyhog\" tests=\"1\" failures=\"1\" errors=\"0\" time=\"0.0\">"
        ),
        "testsuite counts wrong: {out:?}"
    );
    assert!(
        out.contains(
            "<testcase name=\"config/app.env:12:aws-access-key\" classname=\"keyhog.findings\" time=\"0.0\">"
        ),
        "testcase name wrong: {out:?}"
    );
    assert!(
        out.contains(
            "<failure message=\"Secret detected: AWS Key, &quot;prod&quot; &lt;a&amp;b&gt; (id: aws-access-key)\" type=\"high\">"
        ),
        "failure message/type not escaped as expected: {out:?}"
    );
    assert!(out.contains("<![CDATA["));
    assert!(out.contains("Verification:  live"));
    assert!(out.contains("Confidence:    0.875"));
}

#[test]
fn junit_escapes_apostrophe_in_failure_message() {
    let mut finding = sample_finding();
    finding.detector_name = "Owner's Key".into();
    let out = render(&finding);
    assert!(out.contains("Owner&apos;s Key"));
}

/// XML 1.0 §2.2 forbids the C0 control bytes (except tab/LF/CR) even as numeric
/// character references, so attacker-controlled fields carrying one — a scanned
/// file named with a raw 0x01, a git author name with a 0x07 bell, a redacted
/// credential byte — must never reach the JUnit output verbatim, or the report a
/// CI system ingests is unparseable and the operator's findings silently vanish
/// from their dashboard. The reporter replaces them with the XML-legal U+FFFD.
#[test]
fn junit_strips_xml_illegal_control_chars_from_untrusted_fields() {
    let mut finding = sample_finding();
    // Control bytes in every attacker-controlled surface: file path (attribute
    // case_name AND CDATA body), git author (CDATA), redacted credential (CDATA).
    finding.location.file_path = Some(std::sync::Arc::from("config/ev\u{1}il.env"));
    finding.location.author = Some(std::sync::Arc::from("Bad\u{7}Actor"));
    finding.credential_redacted = std::borrow::Cow::Owned("AK\u{1}A...7X\u{1b}A".to_string());

    let out = render(&finding);

    // The actual contract: the rendered document contains NO XML-1.0-illegal
    // control character (the C0 set minus the three XML-legal whitespace chars).
    let illegal: Vec<u32> = out
        .chars()
        .map(|c| c as u32)
        .filter(|&u| u < 0x20 && !matches!(u, 0x09 | 0x0A | 0x0D))
        .collect();
    assert!(
        illegal.is_empty(),
        "JUnit output must be XML-1.0-valid; found illegal control codepoints {illegal:?} in: {out:?}"
    );
    // The offending bytes are visibly flagged, not silently dropped (Law 10).
    assert!(
        out.contains('\u{FFFD}'),
        "illegal control bytes must be replaced with the visible U+FFFD marker: {out:?}"
    );
    // And the document is still structurally intact around the sanitized fields.
    assert!(
        out.contains("<testcase name=\""),
        "testcase survived: {out:?}"
    );
    assert!(
        out.trim_end().ends_with("</testsuites>"),
        "doc closed: {out:?}"
    );
}

#[test]
fn junit_uses_canonical_structured_verification_tokens() {
    for (verification, expected) in [
        (VerificationResult::Live, "live"),
        (VerificationResult::Revoked, "revoked"),
        (VerificationResult::Dead, "dead"),
        (VerificationResult::RateLimited, "rate_limited"),
        (VerificationResult::Error("boom".to_string()), "error: boom"),
        (VerificationResult::Unverifiable, "unverifiable"),
        (VerificationResult::Skipped, "skipped"),
    ] {
        let mut finding = sample_finding();
        finding.verification = verification;
        let out = render(&finding);
        assert!(
            out.contains(&format!("Verification:  {expected}")),
            "JUnit must use the canonical structured verification token {expected:?}: {out:?}"
        );
    }
}
