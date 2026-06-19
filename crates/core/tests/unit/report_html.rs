use super::report_common::sample_finding;
use crate::support::reporters::HtmlReporter;

fn render(finding: &keyhog_core::VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = HtmlReporter::new(&mut buf);
        reporter.report(finding).expect("report finding");
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 html output")
}

fn raw_findings_json(out: &str) -> &str {
    let line = out
        .lines()
        .find(|l| l.trim_start().starts_with("const rawFindings = "))
        .expect("rawFindings assignment present");
    let start = line.find('[').expect("array opens");
    let end = line.rfind(']').expect("array closes");
    &line[start..=end]
}

#[test]
fn html_emits_doctype_and_embeds_raw_findings() {
    let out = render(&sample_finding());

    assert!(out.starts_with("<!DOCTYPE html>\n"), "missing DOCTYPE");
    assert!(out.contains("<html lang=\"en\" data-theme=\"obsidian\">"));
    assert!(out.contains("<title>KeyHog Secret Scan Report</title>"));
    assert!(out.contains("const rawFindings = "));
    assert!(out.trim_end().ends_with("</html>"));

    let json = raw_findings_json(&out);
    let parsed: Vec<keyhog_core::VerifiedFinding> =
        serde_json::from_str(json).expect("embedded rawFindings is valid JSON array");
    assert_eq!(parsed.len(), 1);
    let finding = &parsed[0];
    assert_eq!(finding.detector_id.as_ref(), "aws-access-key");
    assert_eq!(finding.severity, keyhog_core::Severity::High);
    assert_eq!(finding.credential_redacted.as_ref(), "AKIA...7XYA");
    assert_eq!(finding.verification, keyhog_core::VerificationResult::Live);
    assert_eq!(finding.confidence, Some(0.875));
}

#[test]
fn html_json_escapes_quotes_in_detector_name() {
    let out = render(&sample_finding());
    let json = raw_findings_json(&out);
    // Quotes stay JSON-escaped, AND `<`/`>` are now `\uXXXX`-escaped before the
    // JSON is inlined into the <script> raw-text block so an attacker-controlled
    // field can never emit a literal `</script>` (stored-XSS fix, C3/C6/C7). The
    // value still JSON.parses back to the exact original string in the browser.
    assert!(json.contains("AWS Key, \\\"prod\\\" \\u003ca&b\\u003e"));
    // The raw, unescaped angle brackets must NOT appear in the inlined script.
    assert!(!json.contains("<a&b>"));
    assert!(json.contains("\"severity\":\"high\""));
}

#[test]
fn html_report_has_accessibility_affordances() {
    let out = render(&sample_finding());

    assert!(out.contains("aria-label=\"Report theme\""));
    assert!(out.contains("aria-label=\"Use Obsidian theme\""));
    assert!(out.contains("aria-pressed=\"true\""));
    assert!(out.contains("aria-live=\"polite\""));
    assert!(out.contains("aria-atomic=\"true\""));
    assert!(out.contains("role=\"tablist\""));
    assert!(out.contains("role=\"tab\" aria-selected=\"true\""));
    assert!(out.contains("<th scope=\"col\">Detector</th>"));
    assert!(out.contains("<th scope=\"col\">Verification</th>"));
    assert!(out.contains("button:focus-visible"));
    assert!(out.contains("tbody tr:focus-visible"));
    assert!(out.contains("btn.setAttribute('aria-pressed', 'true')"));
    assert!(out.contains("tab.setAttribute('aria-selected', 'true')"));
    assert!(out.contains("resultCount.innerText = `Showing ${count} of ${total} findings.`"));
    assert!(out.contains("tr.tabIndex = 0"));
    assert!(out.contains("tr.setAttribute('role', 'button')"));
    assert!(out.contains("toggleDetailsFromKeyboard"));
}

#[test]
fn html_report_does_not_embed_plaintext_unmask_controls() {
    let out = render(&sample_finding());

    assert!(
        !out.contains("toggleMask"),
        "HTML report must not ship a dead or plaintext-revealing credential toggle"
    );
    assert!(
        !out.contains("data-plaintext"),
        "HTML report must not embed a plaintext credential copy"
    );
    assert!(
        !out.contains("Show secret"),
        "HTML report must not promise a plaintext reveal path"
    );
    assert!(
        out.contains("<span id=\"cred-text-${idx}\">${credRedacted}</span>"),
        "report script should render the redacted credential as static text"
    );
}
