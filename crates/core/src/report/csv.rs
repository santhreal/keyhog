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
            "{},{},{},{},{},{},{},{},",
            escape_csv(&finding.detector_id),
            escape_csv(&finding.detector_name),
            escape_csv(&finding.service),
            escape_csv(finding.severity.as_str()),
            escape_csv(&finding.credential_redacted),
            escape_csv(&crate::hex_encode(&finding.credential_hash)),
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
        writeln!(w)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.flush_writer()
    }
}

impl_writer_backed!(CsvReporter);
