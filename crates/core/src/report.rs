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

use std::collections::BTreeMap;
use std::io::Write;

use crate::VerifiedFinding;

/// Serialize redacted companion values deterministically for report formats
/// that expose a scalar details field instead of the native JSON object.
pub(crate) fn companions_json(finding: &VerifiedFinding) -> Result<String, ReportError> {
    let companions: BTreeMap<&str, &str> = finding
        .companions_redacted
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    Ok(serde_json::to_string(&companions)?)
}

/// Common error type used by all reporters.
pub use anyhow::Error as ReportError;

/// Format-neutral operator-visible metadata for a completed scan report.
///
/// The metadata belongs to the report, not to one renderer. Individual output
/// formats project the fields they can represent: HTML renders the complete
/// object, while schema-constrained formats retain their established fields.
/// Keeping this model in `keyhog-core` prevents the CLI and a single reporter
/// from growing competing definitions of scan identity and timing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ScanReportMetadata {
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

/// Compatibility name for callers that used the original HTML-only type.
///
/// New code should use [`ScanReportMetadata`]. The alias is intentionally kept
/// so a report-format migration does not break library consumers.
pub type HtmlScanMetadata = ScanReportMetadata;

/// The format-neutral input shared by every report renderer.
///
/// Renderers borrow findings so constructing a report does not copy a large
/// finding set. Metadata is optional for the legacy [`write_report`] wrapper;
/// production scan paths should pass it through [`write_scan_report`].
#[derive(Debug, Clone, Copy)]
pub struct ScanReport<'a> {
    /// Findings after all scan filtering, suppression, and verification.
    pub findings: &'a [VerifiedFinding],
    /// Common scan identity and timing metadata, when the caller has it.
    pub metadata: Option<&'a ScanReportMetadata>,
}

impl<'a> ScanReport<'a> {
    /// Create a report without optional metadata.
    pub fn new(findings: &'a [VerifiedFinding]) -> Self {
        Self {
            findings,
            metadata: None,
        }
    }

    /// Attach the common scan metadata used by format projections.
    #[must_use]
    pub fn with_metadata(mut self, metadata: &'a ScanReportMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }
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
    write_scan_report(writer, format, ScanReport::new(findings))
}

/// Write a complete report from the shared scan model.
///
/// [`write_report`] remains as a compatibility wrapper for callers that only
/// have findings. New scan paths should use this entrypoint so every renderer
/// receives the same report object and metadata cannot be wired only to HTML.
pub fn write_scan_report<W: Write + Send>(
    writer: W,
    format: ReportFormat,
    report: ScanReport<'_>,
) -> Result<(), ReportError> {
    let findings = report.findings;
    let report_metadata = report.metadata;
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
            gitlab_sast::GitlabSastReporter::new(
                writer,
                report_time(
                    report_metadata,
                    scan_started_at,
                    |metadata| &metadata.scan_started_at,
                    "scan_started_at",
                )?,
                report_time(
                    report_metadata,
                    scan_finished_at,
                    |metadata| &metadata.scan_finished_at,
                    "scan_finished_at",
                )?,
            ),
            findings,
        ),
        ReportFormat::Html {
            skip_summary,
            metadata,
        } => finish_reporter(
            html::HtmlReporter::new(writer)
                .with_skip_summary(skip_summary)
                .with_metadata(merge_html_metadata(metadata, report_metadata)?),
            findings,
        ),
        ReportFormat::Junit => finish_reporter(junit::JunitReporter::new(writer), findings),
    }
}

fn report_time(
    metadata: Option<&ScanReportMetadata>,
    explicit: String,
    select: fn(&ScanReportMetadata) -> &String,
    field: &str,
) -> Result<String, ReportError> {
    let Some(metadata) = metadata else {
        return Ok(explicit);
    };
    let canonical = select(metadata);
    if explicit != *canonical {
        anyhow::bail!(
            "report metadata conflict for {field}: format options and ScanReport disagree; pass one canonical value"
        );
    }
    Ok(explicit)
}

fn merge_html_metadata(
    explicit: Option<ScanReportMetadata>,
    report: Option<&ScanReportMetadata>,
) -> Result<Option<ScanReportMetadata>, ReportError> {
    match (explicit, report) {
        (Some(explicit), Some(report)) if explicit != *report => {
            anyhow::bail!(
                "report metadata conflict for HTML: format options and ScanReport disagree; pass one canonical value"
            );
        }
        (Some(explicit), _) => Ok(Some(explicit)),
        (None, report) => Ok(report.cloned()),
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
