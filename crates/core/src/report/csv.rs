//! Tabular CSV findings reporter.

use std::collections::BTreeMap;
use std::io::Write;

use crate::VerifiedFinding;

use super::{
    escape::escape_csv, impl_writer_backed, ReportError, Reporter, ScanCompletionStatus,
    ScanReportMetadata, WriterBackedReporter,
};

/// Tabular CSV output.
pub(crate) struct CsvReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> CsvReporter<W> {
    /// Create a new CSV reporter and write headers.
    pub(crate) fn new(mut writer: W) -> Result<Self, ReportError> {
        write_header(&mut writer)?;
        Ok(Self { writer })
    }

    /// Create a CSV reporter with a deterministic scan-wide status preamble.
    ///
    /// The preamble is a comment line understood by KeyHog's CSV consumers and
    /// ignored by RFC-4180 readers that support comment records. Keeping it
    /// before the header makes a zero-finding partial scan self-describing.
    pub(crate) fn with_scan_metadata(
        mut writer: W,
        metadata: Option<&ScanReportMetadata>,
        coverage_gap_summary: &[(String, usize)],
    ) -> Result<Self, ReportError> {
        let scan_status = ScanCompletionStatus::resolve(
            metadata.map(|value| value.scan_status),
            !coverage_gap_summary.is_empty(),
        );
        let preamble = CsvScanMetadata {
            schema_version: 2,
            scan_status,
            backend_recoveries: metadata
                .map(|value| value.backend_recoveries.as_slice())
                .unwrap_or_default(), // LAW10: absent report metadata means an empty display-only recovery list; findings still emit
            coverage_gap_summary: coverage_gap_summary
                .iter()
                .map(|(reason, count)| CsvCoverageGap {
                    reason: reason.clone(),
                    count: *count,
                })
                .collect(),
        };
        writeln!(
            writer,
            "# keyhog.scan.metadata={}",
            serde_json::to_string(&preamble)?
        )?;
        write_header(&mut writer)?;
        Ok(Self { writer })
    }
}

fn write_header<W: Write>(writer: &mut W) -> Result<(), ReportError> {
    writeln!(
        writer,
        "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence,entropy,remediation,metadata,additional_locations"
    )?;
    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct CsvScanMetadata<'a> {
    schema_version: u8,
    scan_status: ScanCompletionStatus,
    backend_recoveries: &'a [super::ScanBackendRecoverySummary],
    coverage_gap_summary: Vec<CsvCoverageGap>,
}

#[derive(Debug, serde::Serialize)]
struct CsvCoverageGap {
    reason: String,
    count: usize,
}

impl<W: Write + Send> Reporter for CsvReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        // LAW10 (every optional field below): recall-safe, these format
        // OPTIONAL fields of an already-detected `VerifiedFinding` into CSV
        // cells. A `None` becomes an empty cell; the finding is still emitted in
        // full. No detection happens here, so nothing can be dropped.
        // Numeric fields (line, offset) and the `0.0..=1.0` confidence never
        // contain a CSV metacharacter, so they are written straight through
        // without `escape_csv` and without an intermediate `String`.
        let file_path_str = finding.location.file_path.as_deref().map_or("", |v| v);
        let commit_str = finding.location.commit.as_deref().map_or("", |v| v);
        let author_str = finding.location.author.as_deref().map_or("", |v| v);
        let date_str = finding.location.date.as_deref().map_or("", |v| v);
        let verification = super::style::verification_token(&finding.verification);

        let w = &mut self.writer;
        write!(
            w,
            "{},{},{},{},{},{},{},{},{},",
            escape_csv(&finding.detector_id),
            escape_csv(&finding.detector_name),
            escape_csv(&finding.service),
            escape_csv(finding.severity.as_str()),
            escape_csv(&finding.credential_redacted),
            escape_csv(&crate::hex_encode(finding.credential_hash)),
            escape_csv(&super::companions_json(finding)?),
            escape_csv(&finding.location.source),
            escape_csv(file_path_str),
        )?;
        if let Some(line) = finding.location.line {
            write!(w, "{line}")?;
        }
        write!(
            w,
            ",{},{},{},{},",
            finding.location.offset,
            escape_csv(commit_str),
            escape_csv(author_str),
            escape_csv(date_str),
        )?;
        write!(w, "{},", escape_csv(&verification))?;
        if let Some(confidence) = finding.confidence {
            write!(w, "{confidence}")?;
        }
        write!(w, ",")?;
        if let Some(entropy) = finding.entropy {
            write!(w, "{entropy}")?;
        }
        let metadata = metadata_json(finding)?;
        let additional_locations = serde_json::to_string(&finding.additional_locations)?;
        write!(
            w,
            ",{},{}",
            escape_csv(&super::remediation_json(finding)?),
            escape_csv(&metadata),
        )?;
        write!(w, ",{}", escape_csv(&additional_locations))?;
        writeln!(w)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.flush_writer()
    }
}

impl_writer_backed!(CsvReporter);

/// Serialize detector/provider metadata in key order so repeated scans produce
/// byte-identical CSV even when the source map was populated in a different
/// insertion order.
fn metadata_json(finding: &VerifiedFinding) -> Result<String, ReportError> {
    let metadata: BTreeMap<&str, &str> = finding
        .metadata
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    Ok(serde_json::to_string(&metadata)?)
}
