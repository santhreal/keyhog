//! Reporting logic for scan results.

pub(crate) mod csv;
pub(crate) mod escape;
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

use std::io::Write;

use crate::VerifiedFinding;

/// Common error type used by all reporters.
pub use anyhow::Error as ReportError;

/// Operator-visible scan metadata for the self-contained HTML report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HtmlScanMetadata {
    /// KeyHog crate/binary version that produced the report.
    pub keyhog_version: String,
    /// UTC generation timestamp formatted as `YYYY-MM-DDTHH:MM:SS`.
    pub generated_at: String,
    /// UTC scan start timestamp formatted as `YYYY-MM-DDTHH:MM:SS`.
    pub scan_started_at: String,
    /// UTC scan finish timestamp formatted as `YYYY-MM-DDTHH:MM:SS`.
    pub scan_finished_at: String,
    /// Wall-clock scan duration in milliseconds.
    pub duration_ms: u128,
    /// Redacted operator-visible target labels for the requested scan sources.
    pub targets: Vec<String>,
    /// Number of source chunks the scanner consumed for this report.
    pub source_chunks_scanned: usize,
    /// Number of loaded detector specs used by this scan.
    pub detector_count: usize,
}

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
        /// Operator-visible scan coverage-gap summary entries.
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
    Html {
        /// Operator-visible scan coverage-gap summary entries (same data the
        /// SARIF report surfaces), rendered as a "coverage" panel so the report
        /// never reads as a clean bill of health when files went unscanned.
        skip_summary: Vec<(String, usize)>,
        /// Scan identity, timing, target, and size metadata for the report hero.
        metadata: Option<HtmlScanMetadata>,
    },
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
        ReportFormat::Html {
            skip_summary,
            metadata,
        } => finish_reporter(
            html::HtmlReporter::new(writer)
                .with_skip_summary(skip_summary)
                .with_metadata(metadata),
            findings,
        ),
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

/// Implements [`WriterBackedReporter`] for a reporter whose only state behind
/// the trait is a single `writer: W` field. Every reporter in this module is
/// generic over `W: Write + Send` and exposes its writer identically, so the
/// impl is purely mechanical, the macro keeps all nine reporters from drifting
/// to nine subtly different spellings of the same three lines. Invoked as
/// `impl_writer_backed!(CsvReporter);` inside each reporter's module, where both
/// `Write` and `WriterBackedReporter` are already in scope.
macro_rules! impl_writer_backed {
    ($reporter:ident) => {
        impl<W: Write + Send> WriterBackedReporter for $reporter<W> {
            type Writer = W;
            fn writer_mut(&mut self) -> &mut Self::Writer {
                &mut self.writer
            }
        }
    };
}
pub(crate) use impl_writer_backed;

// `BufferedFindingReporter` was the legacy buffer-everything trait. The
// SARIF reporter now streams results directly to its writer (audit
// 2026-04-26 audit), so the trait has no callers and is removed. Other
// reporters that still buffer (text, JSON-array) keep their state inline.
