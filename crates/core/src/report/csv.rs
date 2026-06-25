//! Tabular CSV findings reporter.

use std::io::Write;

use crate::VerifiedFinding;

use super::{escape::escape_csv, impl_writer_backed, ReportError, Reporter, WriterBackedReporter};

/// Tabular CSV output.
pub(crate) struct CsvReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> CsvReporter<W> {
    /// Create a new CSV reporter and write headers.
    pub(crate) fn new(mut writer: W) -> Result<Self, ReportError> {
        writeln!(
            writer,
            "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence"
        )?;
        Ok(Self { writer })
    }
}

impl<W: Write + Send> Reporter for CsvReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        // LAW10 (all six below): recall-safe — these format OPTIONAL fields of an
        // already-detected `VerifiedFinding` into CSV cells. A `None` becomes an
        // empty cell; the finding is still emitted in full. No detection happens
        // here, so nothing can be dropped.
        let line_str = finding
            .location
            .line
            .map(|l| l.to_string())
            .unwrap_or_default(); // LAW10: empty CSV cell for an optional field
        let commit_str = finding
            .location
            .commit
            .as_ref()
            .map(|c| c.as_ref())
            .unwrap_or_default(); // LAW10: empty CSV cell for an optional field
        let author_str = finding
            .location
            .author
            .as_ref()
            .map(|a| a.as_ref())
            .unwrap_or_default(); // LAW10: empty CSV cell for an optional field
        let date_str = finding
            .location
            .date
            .as_ref()
            .map(|d| d.as_ref())
            .unwrap_or_default(); // LAW10: empty CSV cell for an optional field
        let file_path_str = finding
            .location
            .file_path
            .as_ref()
            .map(|f| f.as_ref())
            .unwrap_or_default(); // LAW10: empty CSV cell for an optional field
        let confidence_str = finding
            .confidence
            .map(|c| c.to_string())
            .unwrap_or_default(); // LAW10: empty CSV cell for an optional field

        let verification_str = super::style::verification_token(&finding.verification).into_owned();

        writeln!(
            self.writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            escape_csv(&finding.detector_id),
            escape_csv(&finding.detector_name),
            escape_csv(&finding.service),
            escape_csv(finding.severity.as_str()),
            escape_csv(&finding.credential_redacted),
            escape_csv(&crate::hex_encode(&finding.credential_hash)),
            escape_csv(&finding.location.source),
            escape_csv(file_path_str),
            escape_csv(&line_str),
            escape_csv(&finding.location.offset.to_string()),
            escape_csv(commit_str),
            escape_csv(author_str),
            escape_csv(date_str),
            escape_csv(&verification_str),
            escape_csv(&confidence_str)
        )?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.flush_writer()
    }
}

impl_writer_backed!(CsvReporter);
