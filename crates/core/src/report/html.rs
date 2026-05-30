//! Dynamic themed HTML findings reporter.

use std::io::Write;

use crate::VerifiedFinding;

use super::{ReportError, Reporter, WriterBackedReporter};

/// Dynamic themed HTML findings reporter.
pub struct HtmlReporter<W: Write + Send> {
    writer: W,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write + Send> HtmlReporter<W> {
    /// Create a new HTML reporter.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            findings: Vec::new(),
        }
    }
}

impl<W: Write + Send> Reporter for HtmlReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        let serialized_findings = serde_json::to_string(&self.findings)?;

        writeln!(self.writer, "<!DOCTYPE html>")?;
        writeln!(self.writer, "<html lang=\"en\" data-theme=\"obsidian\">")?;
        writeln!(self.writer, "<head>")?;
        writeln!(self.writer, "  <meta charset=\"UTF-8\">")?;
        writeln!(self.writer, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">")?;
        writeln!(self.writer, "  <title>KeyHog Secret Scan Report</title>")?;
        writeln!(self.writer, "  <style>")?;
        writeln!(self.writer, "{}", include_str!("html_styles.css"))?;
        writeln!(self.writer, "  </style>")?;
        writeln!(self.writer, "</head>")?;
        writeln!(self.writer, "<body>")?;
        
        writeln!(self.writer, "{}", include_str!("html_body.html"))?;

        writeln!(self.writer, "  <script>")?;
        writeln!(self.writer, "    const rawFindings = {};", serialized_findings)?;
        writeln!(self.writer, "{}", include_str!("html_script.js"))?;
        writeln!(self.writer, "  </script>")?;
        writeln!(self.writer, "</body>")?;
        writeln!(self.writer, "</html>")?;

        self.flush_writer()
    }
}

impl<W: Write + Send> WriterBackedReporter for HtmlReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::sample_finding;
    use super::HtmlReporter;
    use crate::Reporter;

    fn render(finding: &crate::VerifiedFinding) -> String {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut reporter = HtmlReporter::new(&mut buf);
            reporter.report(finding).expect("report finding");
            reporter.finish().expect("finish");
        }
        String::from_utf8(buf).expect("utf8 html output")
    }

    /// Pull the JSON array literal out of the `const rawFindings = [...]`;
    /// assignment line so the test can assert against parsed structure, not
    /// fragile substrings inside the surrounding script.
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

        // A standalone HTML document: DOCTYPE first, themed root element,
        // and the embedded raw findings the in-page script renders from.
        assert!(out.starts_with("<!DOCTYPE html>\n"), "missing DOCTYPE: {}", &out[..out.len().min(64)]);
        assert!(out.contains("<html lang=\"en\" data-theme=\"obsidian\">"), "missing themed root");
        assert!(out.contains("<title>KeyHog Secret Scan Report</title>"), "missing report title");
        assert!(out.contains("const rawFindings = "), "no embedded rawFindings: {out:?}");
        assert!(out.trim_end().ends_with("</html>"), "document not closed");

        // The embedded JSON must round-trip back into the finding type so the
        // page receives real data, and it must carry this finding's identity,
        // severity, redacted credential, and live verdict.
        let json = raw_findings_json(&out);
        let parsed: Vec<crate::VerifiedFinding> =
            serde_json::from_str(json).expect("embedded rawFindings is valid JSON array of findings");
        assert_eq!(parsed.len(), 1, "exactly one embedded finding expected");
        let f = &parsed[0];
        assert_eq!(f.detector_id.as_ref(), "aws-access-key");
        assert_eq!(f.severity, crate::Severity::High);
        assert_eq!(f.credential_redacted.as_ref(), "AKIA...7XYA");
        assert_eq!(f.verification, crate::VerificationResult::Live);
        assert_eq!(f.confidence, Some(0.875));
    }

    #[test]
    fn html_json_escapes_quotes_in_detector_name() {
        // serde_json must escape the embedded double quotes in the detector
        // name so the resulting `<script>` payload stays syntactically valid
        // JavaScript (a raw `"` would terminate the JSON string early).
        let out = render(&sample_finding());
        let json = raw_findings_json(&out);
        assert!(
            json.contains("AWS Key, \\\"prod\\\" <a&b>"),
            "detector name quotes not JSON-escaped in embedded payload: {json}"
        );
        // The kebab-case severity wire form is what the page filters on.
        assert!(json.contains("\"severity\":\"high\""), "severity wire form wrong: {json}");
    }
}
