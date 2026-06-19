//! Structured JUnit XML findings reporter.

use std::io::Write;

use crate::VerifiedFinding;

use super::{ReportError, Reporter, WriterBackedReporter};

/// Structured JUnit XML findings reporter.
pub(crate) struct JunitReporter<W: Write + Send> {
    writer: W,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write + Send> JunitReporter<W> {
    /// Create a new JUnit reporter.
    pub(crate) fn new(writer: W) -> Self {
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
            // LAW10 (both below): recall-safe — formatting OPTIONAL location
            // fields of an already-detected finding into JUnit XML. A `None`
            // becomes an empty string handled by the `case_name` branches below;
            // the finding is still emitted. No detection happens here.
            let line_str = finding
                .location
                .line
                .map(|l| l.to_string())
                .unwrap_or_default(); // LAW10: optional field -> empty, finding still emitted
            let file_path_str = finding
                .location
                .file_path
                .as_ref()
                .map(|f| f.as_ref())
                .unwrap_or_default(); // LAW10: optional field -> empty, finding still emitted
            let case_name = if file_path_str.is_empty() {
                format!("{}:{}", finding.detector_id, line_str)
            } else if line_str.is_empty() {
                format!("{}:{}", file_path_str, finding.detector_id)
            } else {
                format!("{}:{}:{}", file_path_str, line_str, finding.detector_id)
            };

            let confidence_str = finding
                .confidence
                .map(|c| c.to_string())
                .unwrap_or_default(); // LAW10: optional confidence -> empty cell; finding still emitted
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
            writeln!(
                self.writer,
                "Detector Name: {}",
                escape_cdata(&finding.detector_name)
            )?;
            writeln!(
                self.writer,
                "Detector ID:   {}",
                escape_cdata(&finding.detector_id)
            )?;
            writeln!(
                self.writer,
                "Service:       {}",
                escape_cdata(&finding.service)
            )?;
            writeln!(self.writer, "Severity:      {}", finding.severity)?;
            writeln!(
                self.writer,
                "Source:        {}",
                escape_cdata(&finding.location.source)
            )?;
            if !file_path_str.is_empty() {
                writeln!(
                    self.writer,
                    "File Path:     {}",
                    escape_cdata(file_path_str)
                )?;
            }
            if !line_str.is_empty() {
                writeln!(self.writer, "Line:          {}", line_str)?;
            }
            writeln!(self.writer, "Offset:        {}", finding.location.offset)?;
            if let Some(c) = &finding.location.commit {
                writeln!(self.writer, "Commit:        {}", escape_cdata(c))?;
            }
            if let Some(a) = &finding.location.author {
                writeln!(self.writer, "Author:        {}", escape_cdata(a))?;
            }
            if let Some(d) = &finding.location.date {
                writeln!(self.writer, "Date:          {}", escape_cdata(d))?;
            }
            writeln!(
                self.writer,
                "Redacted:      {}",
                escape_cdata(&finding.credential_redacted)
            )?;
            writeln!(
                self.writer,
                "Hash:          {}",
                crate::hex_encode(&finding.credential_hash)
            )?;
            writeln!(
                self.writer,
                "Verification:  {}",
                escape_cdata(&verification_str)
            )?;
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
    sanitize_xml(val)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Replace XML-1.0-illegal control characters with the visible replacement char
/// U+FFFD. XML 1.0 §2.2 forbids the C0 controls — EXCEPT tab (0x09), LF (0x0A),
/// and CR (0x0D) — in a conformant document, and (unlike `<`/`&`) entity-escaping
/// does NOT legalize them: even `&#x1;` is rejected. So a scanned file whose name
/// carries a raw 0x01, or a git author/committer name that does, would otherwise
/// make keyhog emit a JUnit report NO conformant CI parser can ingest — the
/// operator's findings then silently never surface in their CI dashboard. The
/// parallel `text` reporter already neutralizes these for the terminal
/// (`sanitize_terminal`); XML needs its own predicate because XML keeps
/// tab/LF/CR legal where a terminal does not. U+FFFD is itself a valid XML char,
/// so the report stays parseable and the offending byte is visibly flagged
/// rather than silently dropped (Law 10). Borrows on the common clean path.
fn sanitize_xml(val: &str) -> std::borrow::Cow<'_, str> {
    let illegal = |c: char| {
        let u = c as u32;
        u < 0x20 && !matches!(u, 0x09 | 0x0A | 0x0D)
    };
    if val.chars().any(illegal) {
        std::borrow::Cow::Owned(
            val.chars()
                .map(|c| if illegal(c) { '\u{FFFD}' } else { c })
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(val)
    }
}

/// Neutralize the CDATA terminator inside a value written into a `<![CDATA[…]]>`
/// body, and strip XML-illegal control bytes first (`sanitize_xml`). XML escaping
/// does NOT apply inside CDATA, so an attacker-controlled field (git
/// author/committer name, file path, or redacted credential bytes) containing the
/// literal `]]>` would otherwise close the section early and inject arbitrary
/// markup into the JUnit report a CI system ingests. The standard mitigation
/// splits the `]]>` token across two CDATA sections (`]]]]><![CDATA[>`); a
/// conformant XML parser rejoins the surrounding text, so the displayed value is
/// unchanged. Borrows on the common no-terminator path.
fn escape_cdata(val: &str) -> std::borrow::Cow<'_, str> {
    let sanitized = sanitize_xml(val);
    if sanitized.contains("]]>") {
        std::borrow::Cow::Owned(sanitized.replace("]]>", "]]]]><![CDATA[>"))
    } else {
        sanitized
    }
}
