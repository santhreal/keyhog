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

/// Serialize the canonical Tier-B remediation projection for scalar report
/// formats. Keeping this beside companion serialization prevents CSV and other
/// adapters from inventing provider-specific remediation logic.
pub(crate) fn remediation_json(finding: &VerifiedFinding) -> Result<String, ReportError> {
    let remediation =
        crate::auto_fix::remediation_for(&finding.detector_id, &finding.service, finding.severity);
    Ok(serde_json::to_string(&remediation)?)
}

/// Common error type used by all reporters.
pub use anyhow::Error as ReportError;

/// Terminal state carried by detached scan artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanCompletionStatus {
    /// The requested input completed without coverage gaps.
    Success,
    /// The artifact completed, but one or more requested inputs were not fully scanned.
    Partial,
    /// The operator or host interrupted the scan before completion.
    Cancelled,
    /// The scan failed before it could produce a trustworthy complete result.
    Failed,
}

impl Default for ScanCompletionStatus {
    fn default() -> Self {
        Self::Success
    }
}

impl ScanCompletionStatus {
    /// Derive the normal terminal state from the coverage summary.
    #[must_use]
    pub fn from_coverage_gaps(has_gaps: bool) -> Self {
        if has_gaps {
            Self::Partial
        } else {
            Self::Success
        }
    }

    /// Resolve metadata and observed coverage into one terminal state.
    ///
    /// A non-empty coverage summary upgrades an optimistic `success` metadata
    /// value to `partial`, while explicit `cancelled` and `failed` states are
    /// preserved even when no gap counter was recorded.
    #[must_use]
    pub fn resolve(metadata: Option<Self>, has_gaps: bool) -> Self {
        match metadata {
            Some(Self::Cancelled) => Self::Cancelled,
            Some(Self::Failed) => Self::Failed,
            Some(Self::Partial) => Self::Partial,
            Some(Self::Success) if has_gaps => Self::Partial,
            Some(status) => status,
            None => Self::from_coverage_gaps(has_gaps),
        }
    }
}

/// Format-neutral operator-visible metadata for a scan report.
///
/// The metadata belongs to the report, not to one renderer. Individual output
/// formats project the fields they can represent: HTML renders the complete
/// object, while schema-constrained formats retain their established fields.
/// Keeping this model in `keyhog-core` prevents the CLI and a single reporter
/// from growing competing definitions of scan identity and timing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanReportMetadata {
    /// Stable non-secret identifier shared by artifacts from one scan run.
    /// Missing values deserialize as empty for reports produced before this
    /// field was introduced; current producers always populate it.
    #[serde(default)]
    pub scan_id: String,
    /// Terminal state for detached artifacts. Older reports default to success
    /// because they predate this explicit field and have no state to recover.
    #[serde(default)]
    pub scan_status: ScanCompletionStatus,
    /// KeyHog crate/binary version that produced the report.
    pub keyhog_version: String,
    /// Git identity of the binary that produced the report.
    pub git_hash: String,
    /// Digest of the embedded detector set compiled into the binary.
    pub detector_digest: String,
    /// Digest of the effective scan configuration, when the orchestrator had
    /// a resolved configuration identity available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_digest: Option<String>,
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
    /// Number of source bytes the scanner consumed for this report.
    pub source_bytes_scanned: u64,
    /// Number of loaded detector specs used by this scan.
    pub detector_count: usize,
}

/// Current major version for the versioned JSON report envelope.
pub const JSON_REPORT_SCHEMA_MAJOR: u16 = 1;
/// Current minor version for the versioned JSON report envelope.
pub const JSON_REPORT_SCHEMA_MINOR: u16 = 4;
/// Current minor version for the versioned JSONL stream contract.
pub const JSONL_REPORT_SCHEMA_MINOR: u16 = 5;

/// Version marker carried by every versioned JSON report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JsonReportSchemaVersion {
    /// Incompatible schema generation.
    pub major: u16,
    /// Backward-compatible additive revision.
    pub minor: u16,
}

/// Versioned machine-readable JSON report.
///
/// A reader must reject an unsupported `major` and may accept any `minor`
/// under a supported major because minor revisions only add optional fields.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonReportEnvelope {
    /// Version marker used to select the reader contract.
    pub schema_version: JsonReportSchemaVersion,
    /// Terminal state for the detached artifact, independent of process exit status.
    #[serde(default)]
    pub scan_status: ScanCompletionStatus,
    /// Optional scan-wide metadata supplied by the producer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ScanReportMetadata>,
    /// Non-zero source or scanner coverage gaps observed during the scan.
    #[serde(default)]
    pub coverage_gap_summary: Vec<JsonReportCoverageGap>,
    /// Findings in the same redacted shape used by the legacy array.
    pub findings: Vec<VerifiedFinding>,
}

/// One scan-wide coverage gap preserved in a versioned JSON report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JsonReportCoverageGap {
    /// Stable machine-readable reason shared with SARIF/HTML projections.
    pub reason: String,
    /// Number of affected files, chunks, or invariant events.
    pub count: usize,
}

impl JsonReportEnvelope {
    /// Parse and validate a versioned JSON report.
    pub fn parse(input: &str) -> Result<Self, ReportError> {
        let report: Self = serde_json::from_str(input)?;
        if report.schema_version.major != JSON_REPORT_SCHEMA_MAJOR {
            anyhow::bail!(
                "unsupported JSON report schema major {}; this reader supports major {}",
                report.schema_version.major,
                JSON_REPORT_SCHEMA_MAJOR
            );
        }
        Ok(report)
    }
}

/// Header written as the first record of a versioned JSONL stream.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JsonlStreamHeader {
    /// Distinguishes the stream header from a finding record.
    pub record_type: String,
    /// Version marker used to select the JSONL reader contract.
    pub schema_version: JsonReportSchemaVersion,
    /// Optional scan-wide metadata supplied by the producer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ScanReportMetadata>,
}

impl JsonlStreamHeader {
    /// Construct a stream header for the current schema.
    #[must_use]
    pub fn new(metadata: Option<&ScanReportMetadata>) -> Self {
        Self {
            record_type: "header".to_string(),
            schema_version: JsonReportSchemaVersion {
                major: JSON_REPORT_SCHEMA_MAJOR,
                minor: JSONL_REPORT_SCHEMA_MINOR,
            },
            metadata: metadata.cloned(),
        }
    }

    /// Parse and validate one JSONL header record.
    pub fn parse(input: &str) -> Result<Self, ReportError> {
        let header: Self = serde_json::from_str(input)?;
        if header.record_type != "header" {
            anyhow::bail!(
                "invalid JSONL stream header record_type {:?}",
                header.record_type
            );
        }
        if header.schema_version.major != JSON_REPORT_SCHEMA_MAJOR {
            anyhow::bail!(
                "unsupported JSONL report schema major {}; this reader supports major {}",
                header.schema_version.major,
                JSON_REPORT_SCHEMA_MAJOR
            );
        }
        Ok(header)
    }
}

/// One validated segment of a JSONL input. Concatenated streams produce one
/// segment per header, so boundaries remain explicit instead of being inferred
/// from finding content.
#[derive(Debug, Clone)]
pub struct JsonlStream {
    /// Header that governed this segment.
    pub header: JsonlStreamHeader,
    /// Terminal summary when the producer completed normally. None means
    /// the input ended before completion and must not be treated as complete.
    pub summary: Option<JsonlStreamSummary>,
    /// Findings following the header until the next header or end of input.
    pub findings: Vec<VerifiedFinding>,
}

/// Terminal record written when a versioned JSONL stream completes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JsonlStreamSummary {
    /// Distinguishes the terminal record from headers and findings.
    pub record_type: String,
    /// Completion state for the stream.
    pub status: String,
    /// Terminal scan state; `status` remains the transport completion marker.
    #[serde(default)]
    pub scan_status: ScanCompletionStatus,
    /// Number of finding records written before this summary.
    pub finding_count: usize,
    /// Coverage gaps observed during the stream.
    #[serde(default)]
    pub coverage_gap_summary: Vec<JsonReportCoverageGap>,
}

impl JsonlStreamSummary {
    /// Construct a complete summary for a stream.
    #[must_use]
    pub fn complete(finding_count: usize, coverage_gap_summary: &[(String, usize)]) -> Self {
        Self::complete_with_status(
            finding_count,
            ScanCompletionStatus::from_coverage_gaps(!coverage_gap_summary.is_empty()),
            coverage_gap_summary,
        )
    }

    /// Construct a complete summary using an explicitly recorded terminal
    /// state from the scan metadata.
    #[must_use]
    pub fn complete_with_status(
        finding_count: usize,
        scan_status: ScanCompletionStatus,
        coverage_gap_summary: &[(String, usize)],
    ) -> Self {
        Self {
            record_type: "summary".to_string(),
            status: "complete".to_string(),
            scan_status,
            finding_count,
            coverage_gap_summary: coverage_gap_summary
                .iter()
                .map(|(reason, count)| JsonReportCoverageGap {
                    reason: reason.clone(),
                    count: *count,
                })
                .collect(),
        }
    }

    fn parse(input: &str) -> Result<Self, ReportError> {
        let summary: Self = serde_json::from_str(input)?;
        if summary.record_type != "summary" || summary.status != "complete" {
            anyhow::bail!(
                "invalid JSONL stream summary: record_type={:?}, status={:?}",
                summary.record_type,
                summary.status
            );
        }
        Ok(summary)
    }
}

impl JsonlStream {
    /// Whether the stream has a validated terminal summary.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.summary.is_some()
    }
}

/// Parse one or more concatenated, versioned JSONL streams.
pub fn parse_jsonl_stream(input: &str) -> Result<Vec<JsonlStream>, ReportError> {
    let mut streams = Vec::new();
    let mut current: Option<JsonlStream> = None;

    for (index, line) in input.lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            anyhow::bail!("JSONL line {line_number} is empty; remove blank records");
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| anyhow::anyhow!("invalid JSONL line {line_number}: {error}"))?;
        let is_header =
            value.get("record_type").and_then(serde_json::Value::as_str) == Some("header");
        if is_header {
            if let Some(stream) = current.take() {
                streams.push(stream);
            }
            current = Some(JsonlStream {
                header: JsonlStreamHeader::parse(line)?,
                summary: None,
                findings: Vec::new(),
            });
            continue;
        }

        let stream = current.as_mut().ok_or_else(|| {
            anyhow::anyhow!("JSONL line {line_number} precedes its stream header")
        })?;
        let is_summary =
            value.get("record_type").and_then(serde_json::Value::as_str) == Some("summary");
        if is_summary {
            if stream.summary.is_some() {
                anyhow::bail!("JSONL line {line_number} repeats the terminal summary");
            }
            let summary = JsonlStreamSummary::parse(line)?;
            if summary.finding_count != stream.findings.len() {
                anyhow::bail!(
                    "JSONL summary count {} does not match {} finding records",
                    summary.finding_count,
                    stream.findings.len()
                );
            }
            stream.summary = Some(summary);
            continue;
        }
        if stream.summary.is_some() {
            anyhow::bail!("JSONL line {line_number} follows the terminal summary");
        }
        let finding = serde_json::from_value(value).map_err(|error| {
            anyhow::anyhow!("invalid finding on JSONL line {line_number}: {error}")
        })?;
        stream.findings.push(finding);
    }

    if let Some(stream) = current {
        streams.push(stream);
    }
    if streams.is_empty() {
        anyhow::bail!("JSONL stream is empty; expected a versioned header record");
    }
    Ok(streams)
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
    /// Versioned JSON envelope output and its scan-wide coverage summary.
    JsonEnvelope {
        /// Non-zero source or scanner coverage gaps observed during the scan.
        coverage_gap_summary: Vec<(String, usize)>,
    },
    /// Newline-delimited JSON output.
    Jsonl,
    /// Versioned newline-delimited JSON output with a stream header.
    JsonlEnvelope {
        /// Non-zero source or scanner coverage gaps observed during the scan.
        coverage_gap_summary: Vec<(String, usize)>,
    },
    /// SARIF output.
    Sarif {
        /// Operator-visible scan coverage-gap summary entries.
        skip_summary: Vec<(String, usize)>,
    },
    /// CSV output.
    Csv,
    /// GitHub Actions workflow command annotations.
    GithubAnnotations,
    /// GitHub Actions annotations with a terminal scan coverage notice.
    GithubAnnotationsCoverage {
        /// Non-zero source or scanner coverage gaps observed during the scan.
        skip_summary: Vec<(String, usize)>,
    },
    /// GitLab SAST security report JSON.
    GitlabSast {
        /// UTC scan start time formatted as `YYYY-MM-DDTHH:MM:SS`.
        scan_started_at: String,
        /// UTC scan end time formatted as `YYYY-MM-DDTHH:MM:SS`.
        scan_finished_at: String,
    },
    /// GitLab SAST output with scan-wide coverage status.
    GitlabSastCoverage {
        /// UTC scan start time formatted as `YYYY-MM-DDTHH:MM:SS`.
        scan_started_at: String,
        /// UTC scan end time formatted as `YYYY-MM-DDTHH:MM:SS`.
        scan_finished_at: String,
        /// Non-zero source or scanner coverage gaps observed during the scan.
        skip_summary: Vec<(String, usize)>,
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
    /// JUnit XML output with deterministic scan coverage properties.
    JunitCoverage {
        /// Non-zero source or scanner coverage gaps observed during the scan.
        skip_summary: Vec<(String, usize)>,
    },
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
        ReportFormat::JsonEnvelope {
            coverage_gap_summary,
        } => finish_reporter(
            json::JsonEnvelopeReporter::new(writer, report_metadata, &coverage_gap_summary)?,
            findings,
        ),
        ReportFormat::Jsonl => finish_reporter(json::JsonlReporter::new(writer), findings),
        ReportFormat::JsonlEnvelope {
            coverage_gap_summary,
        } => finish_reporter(
            json::JsonlEnvelopeReporter::new(writer, report_metadata, &coverage_gap_summary)?,
            findings,
        ),
        ReportFormat::Sarif { skip_summary } => finish_reporter(
            sarif::SarifReporter::new(writer).with_skip_summary(skip_summary),
            findings,
        ),
        ReportFormat::Csv => finish_reporter(csv::CsvReporter::new(writer)?, findings),
        ReportFormat::GithubAnnotations => finish_reporter(
            github_annotations::GithubAnnotationsReporter::new(writer),
            findings,
        ),
        ReportFormat::GithubAnnotationsCoverage { skip_summary } => finish_reporter(
            github_annotations::GithubAnnotationsReporter::new(writer)
                .with_skip_summary(skip_summary),
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
        ReportFormat::GitlabSastCoverage {
            scan_started_at,
            scan_finished_at,
            skip_summary,
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
            )
            .with_skip_summary(skip_summary),
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
        ReportFormat::JunitCoverage { skip_summary } => finish_reporter(
            junit::JunitReporter::new(writer).with_skip_summary(skip_summary),
            findings,
        ),
    }
}

/// Write a CSV scan artifact with a self-describing scan-status preamble.
///
/// This dedicated entrypoint keeps the legacy [`ReportFormat::Csv`] enum
/// variant and its header-first byte contract unchanged for library callers,
/// while CLI scan artifacts can retain coverage state even when no finding row
/// exists.
pub fn write_csv_coverage_report<W: Write + Send>(
    writer: W,
    report: ScanReport<'_>,
    coverage_gap_summary: &[(String, usize)],
) -> Result<(), ReportError> {
    finish_reporter(
        csv::CsvReporter::with_scan_metadata(writer, report.metadata, coverage_gap_summary)?,
        report.findings,
    )
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
