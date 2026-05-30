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
