//! GitHub Actions workflow command annotation reporter.

use std::io::Write;

use crate::{Severity, VerificationResult, VerifiedFinding};

use super::{ReportError, Reporter, WriterBackedReporter};

/// GitHub Actions workflow command annotations.
pub(crate) struct GithubAnnotationsReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> GithubAnnotationsReporter<W> {
    /// Create a GitHub Actions annotation reporter.
    pub(crate) fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write + Send> Reporter for GithubAnnotationsReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        write!(self.writer, "::{} ", annotation_level(finding.severity))?;

        let mut first_property = true;
        if let Some(file_path) = &finding.location.file_path {
            write_property(
                &mut self.writer,
                &mut first_property,
                "file",
                file_path.as_ref(),
            )?;
        }
        if let Some(line) = finding.location.line {
            let line_text = line.to_string();
            write_property(&mut self.writer, &mut first_property, "line", &line_text)?;
        }

        let title = format!("keyhog {} {}", finding.severity, finding.detector_id);
        write_property(&mut self.writer, &mut first_property, "title", &title)?;
        write!(self.writer, "::")?;
        writeln!(self.writer, "{}", escape_command_data(&message(finding)))?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.flush_writer()
    }
}

impl<W: Write + Send> WriterBackedReporter for GithubAnnotationsReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

fn annotation_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::ClientSafe | Severity::Info => "notice",
    }
}

fn write_property<W: Write>(
    writer: &mut W,
    first_property: &mut bool,
    name: &str,
    value: &str,
) -> Result<(), ReportError> {
    if *first_property {
        *first_property = false;
    } else {
        write!(writer, ",")?;
    }
    write!(writer, "{}={}", name, escape_property(value))?;
    Ok(())
}

fn message(finding: &VerifiedFinding) -> String {
    let verification = verification_label(&finding.verification);
    let mut text = format!(
        "{} detector={} service={} redacted={} verification={}",
        finding.detector_name,
        finding.detector_id,
        finding.service,
        finding.credential_redacted,
        verification
    );
    if let Some(confidence) = finding.confidence {
        text.push_str(&format!(" confidence={confidence:.3}"));
    }
    text
}

fn verification_label(verification: &VerificationResult) -> String {
    match verification {
        VerificationResult::Live => "live".to_string(),
        VerificationResult::Revoked => "revoked".to_string(),
        VerificationResult::Dead => "dead".to_string(),
        VerificationResult::RateLimited => "rate_limited".to_string(),
        VerificationResult::Error(err) => format!("error: {err}"),
        VerificationResult::Unverifiable => "unverifiable".to_string(),
        VerificationResult::Skipped => "skipped".to_string(),
    }
}

fn escape_property(value: &str) -> String {
    escape_with(value, true)
}

fn escape_command_data(value: &str) -> String {
    escape_with(value, false)
}

fn escape_with(value: &str, property: bool) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '%' => escaped.push_str("%25"),
            '\r' => escaped.push_str("%0D"),
            '\n' => escaped.push_str("%0A"),
            ':' if property => escaped.push_str("%3A"),
            ',' if property => escaped.push_str("%2C"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
