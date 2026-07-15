//! GitHub Actions workflow command annotation reporter.

use std::io::Write;

use crate::{Severity, VerifiedFinding};

use super::escape::sanitize_terminal;
use super::{impl_writer_backed, ReportError, Reporter, WriterBackedReporter};

/// GitHub Actions workflow command annotations.
pub(crate) struct GithubAnnotationsReporter<W: Write + Send> {
    writer: W,
    skip_summary: Vec<(String, usize)>,
    emit_scan_status: bool,
}

impl<W: Write + Send> GithubAnnotationsReporter<W> {
    /// Create a GitHub Actions annotation reporter.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            skip_summary: Vec::new(),
            emit_scan_status: false,
        }
    }

    /// Attach a terminal workflow notice for incomplete source coverage.
    pub(crate) fn with_skip_summary(mut self, summary: Vec<(String, usize)>) -> Self {
        self.emit_scan_status = true;
        self.skip_summary = summary
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .collect();
        self
    }
}

impl<W: Write + Send> Reporter for GithubAnnotationsReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        write!(self.writer, "::{} ", annotation_level(finding.severity))?;

        let mut first_property = true;
        if let Some(file_path) = &finding.location.file_path {
            let file_path = sanitize_terminal(file_path.as_ref());
            write_property(&mut self.writer, &mut first_property, "file", &file_path)?;
        }
        if let Some(line) = finding.location.line {
            let line_text = line.to_string();
            write_property(&mut self.writer, &mut first_property, "line", &line_text)?;
        }

        let title = format!(
            "keyhog {} {}",
            finding.severity,
            sanitize_terminal(&finding.detector_id)
        );
        write_property(&mut self.writer, &mut first_property, "title", &title)?;
        write!(self.writer, "::")?;
        writeln!(self.writer, "{}", escape_command_data(&message(finding)?))?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        if self.emit_scan_status {
            let status = if self.skip_summary.is_empty() {
                "success"
            } else {
                "partial"
            };
            writeln!(
                self.writer,
                "::notice title=keyhog scan::scan status: {status}"
            )?;
        }
        if !self.skip_summary.is_empty() {
            let details = self
                .skip_summary
                .iter()
                .map(|(reason, count)| format!("{}={count}", sanitize_terminal(reason)))
                .collect::<Vec<_>>()
                .join("; ");
            writeln!(
                self.writer,
                "::warning title=keyhog coverage::{}",
                escape_command_data(&format!("partial scan coverage: {details}"))
            )?;
        }
        self.flush_writer()
    }
}

impl_writer_backed!(GithubAnnotationsReporter);

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

fn message(finding: &VerifiedFinding) -> Result<String, ReportError> {
    let verification = super::style::verification_token(&finding.verification);
    let mut text = format!(
        "{} detector={} service={} redacted={} verification={}",
        sanitize_terminal(&finding.detector_name),
        sanitize_terminal(&finding.detector_id),
        sanitize_terminal(&finding.service),
        sanitize_terminal(&finding.credential_redacted),
        verification
    );
    if let Some(confidence) = finding.confidence {
        use std::fmt::Write;
        if write!(text, " confidence={confidence:.3}").is_err() {
            unreachable!("formatting into a String cannot fail");
        }
    }
    if let Some(entropy) = finding.entropy.filter(|entropy| entropy.is_finite()) {
        use std::fmt::Write;
        if write!(text, " entropy={entropy:.3}").is_err() {
            unreachable!("formatting into a String cannot fail");
        }
    }
    if !finding.companions_redacted.is_empty() {
        text.push_str(" companions=");
        text.push_str(&super::companions_json(finding)?);
    }
    Ok(text)
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
