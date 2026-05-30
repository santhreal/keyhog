//! Structured JUnit XML findings reporter.

use std::io::Write;

use crate::VerifiedFinding;

use super::{ReportError, Reporter, WriterBackedReporter};

/// Structured JUnit XML findings reporter.
pub struct JunitReporter<W: Write + Send> {
    writer: W,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write + Send> JunitReporter<W> {
    /// Create a new JUnit reporter.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            findings: Vec::new(),
        }
    }
}

impl<W: Write + Send> Reporter for JunitReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        writeln!(self.writer, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(self.writer, "<testsuites>")?;

        let tests_count = self.findings.len();
        writeln!(
            self.writer,
            "  <testsuite name=\"keyhog\" tests=\"{}\" failures=\"{}\" errors=\"0\" time=\"0.0\">",
            tests_count, tests_count
        )?;

        for finding in &self.findings {
            let line_str = finding.location.line.map(|l| l.to_string()).unwrap_or_default();
            let file_path_str = finding.location.file_path.as_ref().map(|f| f.as_ref()).unwrap_or_default();
            let case_name = if file_path_str.is_empty() {
                format!("{}:{}", finding.detector_id, line_str)
            } else if line_str.is_empty() {
                format!("{}:{}", file_path_str, finding.detector_id)
            } else {
                format!("{}:{}:{}", file_path_str, line_str, finding.detector_id)
            };

            let confidence_str = finding.confidence.map(|c| c.to_string()).unwrap_or_default();
            let verification_str = match &finding.verification {
                crate::VerificationResult::Live => "live".to_string(),
                crate::VerificationResult::Revoked => "revoked".to_string(),
                crate::VerificationResult::Dead => "dead".to_string(),
                crate::VerificationResult::RateLimited => "rate_limited".to_string(),
                crate::VerificationResult::Error(err) => format!("error: {err}"),
                crate::VerificationResult::Unverifiable => "unverifiable".to_string(),
                crate::VerificationResult::Skipped => "skipped".to_string(),
            };

            writeln!(
                self.writer,
                "    <testcase name=\"{}\" classname=\"keyhog.findings\" time=\"0.0\">",
                escape_xml_attr(&case_name)
            )?;

            let failure_msg = format!(
                "Secret detected: {} (id: {})",
                finding.detector_name, finding.detector_id
            );
            writeln!(
                self.writer,
                "      <failure message=\"{}\" type=\"{}\">",
                escape_xml_attr(&failure_msg),
                escape_xml_attr(&finding.severity.to_string())
            )?;

            writeln!(self.writer, "        <![CDATA[")?;
            writeln!(self.writer, "Detector Name: {}", finding.detector_name)?;
            writeln!(self.writer, "Detector ID:   {}", finding.detector_id)?;
            writeln!(self.writer, "Service:       {}", finding.service)?;
            writeln!(self.writer, "Severity:      {}", finding.severity)?;
            writeln!(self.writer, "Source:        {}", finding.location.source)?;
            if !file_path_str.is_empty() {
                writeln!(self.writer, "File Path:     {}", file_path_str)?;
            }
            if !line_str.is_empty() {
                writeln!(self.writer, "Line:          {}", line_str)?;
            }
            writeln!(self.writer, "Offset:        {}", finding.location.offset)?;
            if let Some(c) = &finding.location.commit {
                writeln!(self.writer, "Commit:        {}", c)?;
            }
            if let Some(a) = &finding.location.author {
                writeln!(self.writer, "Author:        {}", a)?;
            }
            if let Some(d) = &finding.location.date {
                writeln!(self.writer, "Date:          {}", d)?;
            }
            writeln!(self.writer, "Redacted:      {}", finding.credential_redacted)?;
            writeln!(self.writer, "Hash:          {}", crate::hex_encode(&finding.credential_hash))?;
            writeln!(self.writer, "Verification:  {}", verification_str)?;
            if !confidence_str.is_empty() {
                writeln!(self.writer, "Confidence:    {}", confidence_str)?;
            }
            writeln!(self.writer, "        ]]>")?;
            writeln!(self.writer, "      </failure>")?;
            writeln!(self.writer, "    </testcase>")?;
        }

        writeln!(self.writer, "  </testsuite>")?;
        writeln!(self.writer, "</testsuites>")?;

        self.flush_writer()
    }
}

impl<W: Write + Send> WriterBackedReporter for JunitReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

fn escape_xml_attr(val: &str) -> String {
    val.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::super::test_support::sample_finding;
    use super::JunitReporter;
    use crate::Reporter;

    fn render(finding: &crate::VerifiedFinding) -> String {
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

        // XML prolog + envelope.
        assert!(
            out.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites>\n"),
            "missing XML prolog/testsuites open: {out:?}"
        );
        assert!(out.trim_end().ends_with("</testsuites>"), "no testsuites close: {out:?}");

        // One finding -> one test, one failure, zero errors.
        assert!(
            out.contains(
                "<testsuite name=\"keyhog\" tests=\"1\" failures=\"1\" errors=\"0\" time=\"0.0\">"
            ),
            "testsuite counts wrong: {out:?}"
        );

        // Testcase name is file:line:detector for a fully-located finding.
        assert!(
            out.contains(
                "<testcase name=\"config/app.env:12:aws-access-key\" classname=\"keyhog.findings\" time=\"0.0\">"
            ),
            "testcase name wrong: {out:?}"
        );

        // The <failure> message carries the detector name with XML special
        // characters escaped (& -> &amp; first, then < > "), and the severity
        // becomes the failure type attribute.
        assert!(
            out.contains(
                "<failure message=\"Secret detected: AWS Key, &quot;prod&quot; &lt;a&amp;b&gt; (id: aws-access-key)\" type=\"high\">"
            ),
            "failure message/type not escaped as expected: {out:?}"
        );

        // The CDATA detail block carries the live verification verdict.
        assert!(out.contains("<![CDATA["), "no CDATA block: {out:?}");
        assert!(out.contains("Verification:  live"), "verification verdict missing: {out:?}");
        assert!(out.contains("Confidence:    0.875"), "confidence missing: {out:?}");
    }

    #[test]
    fn junit_escapes_ampersand_before_angle_brackets() {
        // Ordering guard: `&` must be escaped first so a literal `<` in the
        // input does not get double-escaped into `&amp;lt;`.
        assert_eq!(super::escape_xml_attr("a&b<c>"), "a&amp;b&lt;c&gt;");
        assert_eq!(super::escape_xml_attr("\"q\""), "&quot;q&quot;");
        assert_eq!(super::escape_xml_attr("it's"), "it&apos;s");
    }
}
