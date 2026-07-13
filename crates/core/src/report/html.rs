//! Dynamic themed HTML findings reporter.

use std::io::Write;

use crate::VerifiedFinding;

use super::{impl_writer_backed, HtmlScanMetadata, ReportError, Reporter, WriterBackedReporter};

/// Make a serialized JSON string safe to inline inside an HTML `<script>`
/// element's raw-text content.
///
/// `serde_json` escapes JSON string syntax but leaves `<`, `>`, and `/`
/// untouched, so an attacker-controlled field containing the byte sequence
/// `</script>` (file path, git author, redacted credential preview, metadata
/// value, ...) would terminate the script element in the browser's HTML parser
/// and execute injected markup (stored XSS). Escaping `<`, `>`, and `/` to
/// `\uXXXX` JSON escapes makes it impossible for `</script` (or any tag close)
/// to appear in the raw text while still producing a value that `JSON.parse`
/// and a JS object literal decode to exactly the original string.
fn escape_for_script(serialized: &str) -> String {
    let mut out = String::with_capacity(serialized.len());
    for ch in serialized.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '/' => out.push_str("\\u002f"),
            // U+2028 / U+2029 are valid in JSON but terminate JS statements.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

/// Dynamic themed HTML findings reporter.
pub(crate) struct HtmlReporter<W: Write + Send> {
    writer: W,
    findings: Vec<VerifiedFinding>,
    /// Non-empty `(reason, count)` coverage-gap entries, rendered as a panel so
    /// "N findings" is never mistaken for "fully scanned, all clean".
    skip_summary: Vec<(String, usize)>,
    metadata: Option<HtmlScanMetadata>,
}

impl<W: Write + Send> HtmlReporter<W> {
    /// Create a new HTML reporter.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            findings: Vec::new(),
            skip_summary: Vec::new(),
            metadata: None,
        }
    }

    /// Attach the scan coverage-gap summary. Zero-count entries are dropped so
    /// the panel only lists categories that actually reduced coverage.
    pub(crate) fn with_skip_summary(mut self, skip_summary: Vec<(String, usize)>) -> Self {
        self.skip_summary = skip_summary.into_iter().filter(|(_, n)| *n > 0).collect();
        self
    }

    /// Attach scan metadata rendered in the report header.
    pub(crate) fn with_metadata(mut self, metadata: Option<HtmlScanMetadata>) -> Self {
        self.metadata = metadata;
        self
    }
}

impl<W: Write + Send> Reporter for HtmlReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        // Unit verification variants serialize as strings, while Error(String)
        // serializes as an object. Keep a string discriminant for filtering but
        // never inline the raw error message. Transport errors may contain
        // credential-bearing response details.
        let mut findings_value = serde_json::to_value(&self.findings)?;
        if let Some(arr) = findings_value.as_array_mut() {
            for finding in arr {
                if let Some(verification) = finding.get_mut("verification") {
                    if verification
                        .as_object()
                        .is_some_and(|object| object.contains_key("error"))
                    {
                        *verification = serde_json::Value::String("error".to_string());
                    }
                }
            }
        }
        let serialized_findings = escape_for_script(&serde_json::to_string(&findings_value)?);

        // Coverage gaps as [{reason, count}], escaped on the same XSS-safe path.
        let coverage_value: Vec<serde_json::Value> = self
            .skip_summary
            .iter()
            .map(|(reason, count)| serde_json::json!({ "reason": reason, "count": count }))
            .collect();
        let serialized_coverage = escape_for_script(&serde_json::to_string(&coverage_value)?);
        let serialized_metadata = escape_for_script(&serde_json::to_string(&self.metadata)?);

        writeln!(self.writer, "<!DOCTYPE html>")?;
        writeln!(self.writer, "<html lang=\"en\" data-theme=\"keyhog\">")?;
        writeln!(self.writer, "<head>")?;
        writeln!(self.writer, "  <meta charset=\"UTF-8\">")?;
        writeln!(
            self.writer,
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        )?;
        writeln!(self.writer, "  <title>KeyHog Secret Scan Report</title>")?;
        writeln!(self.writer, "  <style>")?;
        writeln!(self.writer, "{}", include_str!("html_styles.css"))?;
        writeln!(self.writer, "  </style>")?;
        writeln!(self.writer, "</head>")?;
        writeln!(self.writer, "<body>")?;

        writeln!(self.writer, "{}", include_str!("html_body.html"))?;

        writeln!(self.writer, "  <script>")?;
        writeln!(
            self.writer,
            "    const rawFindings = {};",
            serialized_findings
        )?;
        writeln!(
            self.writer,
            "    const coverageGaps = {};",
            serialized_coverage
        )?;
        writeln!(
            self.writer,
            "    const scanMetadata = {};",
            serialized_metadata
        )?;
        writeln!(self.writer, "{}", include_str!("html_script.js"))?;
        writeln!(self.writer, "  </script>")?;
        writeln!(self.writer, "</body>")?;
        writeln!(self.writer, "</html>")?;

        self.flush_writer()
    }
}

impl_writer_backed!(HtmlReporter);
