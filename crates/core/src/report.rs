//! Reporting logic for scan results.

pub(crate) mod csv;
pub(crate) mod github_annotations;
pub(crate) mod gitlab_sast;
pub(crate) mod html;
pub(crate) mod json;
pub(crate) mod junit;
pub(crate) mod sarif;
mod style;
pub(crate) mod text;

#[path = "report/sarif_uri.rs"]
pub(crate) mod sarif_uri;

pub(crate) mod banner;

use std::io::Write;

use crate::VerifiedFinding;

/// Common error type used by all reporters.
pub use anyhow::Error as ReportError;

/// Output format and formatter options for [`write_report`].
pub enum ReportFormat {
    /// Human-oriented terminal output.
    Text {
        /// Emit ANSI color escapes.
        color: bool,
        /// Number of example suppression hints to include.
        example_suppressions: usize,
        /// Include dogfood telemetry hints in the text report.
        dogfood_active: bool,
    },
    /// JSON array output.
    Json,
    /// Newline-delimited JSON output.
    Jsonl,
    /// SARIF output.
    Sarif {
        /// Operator-visible scan skip summary entries.
        skip_summary: Vec<(String, usize)>,
    },
    /// CSV output.
    Csv,
    /// GitHub Actions workflow command annotations.
    GithubAnnotations,
    /// GitLab SAST security report JSON.
    GitlabSast {
        /// UTC scan start time formatted as `YYYY-MM-DDTHH:MM:SS`.
        scan_started_at: String,
        /// UTC scan end time formatted as `YYYY-MM-DDTHH:MM:SS`.
        scan_finished_at: String,
    },
    /// Self-contained HTML output.
    Html,
    /// JUnit XML output.
    Junit,
}

/// Write a complete findings report in the requested format.
pub fn write_report<W: Write + Send>(
    writer: W,
    format: ReportFormat,
    findings: &[VerifiedFinding],
) -> Result<(), ReportError> {
    match format {
        ReportFormat::Text {
            color,
            example_suppressions,
            dogfood_active,
        } => {
            let mut reporter = text::TextReporter::with_color(writer, color);
            reporter.set_example_suppressions(example_suppressions);
            reporter.set_dogfood_active(dogfood_active);
            finish_reporter(reporter, findings)
        }
        ReportFormat::Json => finish_reporter(json::JsonArrayReporter::new(writer)?, findings),
        ReportFormat::Jsonl => finish_reporter(json::JsonlReporter::new(writer), findings),
        ReportFormat::Sarif { skip_summary } => finish_reporter(
            sarif::SarifReporter::new(writer).with_skip_summary(skip_summary),
            findings,
        ),
        ReportFormat::Csv => finish_reporter(csv::CsvReporter::new(writer)?, findings),
        ReportFormat::GithubAnnotations => finish_reporter(
            github_annotations::GithubAnnotationsReporter::new(writer),
            findings,
        ),
        ReportFormat::GitlabSast {
            scan_started_at,
            scan_finished_at,
        } => finish_reporter(
            gitlab_sast::GitlabSastReporter::new(writer, scan_started_at, scan_finished_at),
            findings,
        ),
        ReportFormat::Html => finish_reporter(html::HtmlReporter::new(writer), findings),
        ReportFormat::Junit => finish_reporter(junit::JunitReporter::new(writer), findings),
    }
}

fn finish_reporter<R: Reporter>(
    mut reporter: R,
    findings: &[VerifiedFinding],
) -> Result<(), ReportError> {
    for finding in findings {
        reporter.report(finding)?;
    }
    reporter.finish()?;
    Ok(())
}

/// Common trait for all finding reporters.
pub(crate) trait Reporter: Send {
    /// Report a single finding.
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError>;

    /// Finalize the report and flush buffered bytes.
    fn finish(&mut self) -> Result<(), ReportError>;
}

trait WriterBackedReporter {
    type Writer: Write;

    fn writer_mut(&mut self) -> &mut Self::Writer;

    fn flush_writer(&mut self) -> Result<(), ReportError> {
        self.writer_mut().flush()?;
        Ok(())
    }
}

// `BufferedFindingReporter` was the legacy buffer-everything trait. The
// SARIF reporter now streams results directly to its writer (audit
// legendary-2026-04-26), so the trait has no callers and is removed. Other
// reporters that still buffer (text, JSON-array) keep their state inline.
