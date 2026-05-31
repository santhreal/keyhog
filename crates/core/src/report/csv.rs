//! Tabular CSV findings reporter.

use std::io::Write;

use crate::VerifiedFinding;

use super::{ReportError, Reporter, WriterBackedReporter};

/// Tabular CSV output.
pub struct CsvReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> CsvReporter<W> {
    /// Create a new CSV reporter and write headers.
    pub fn new(mut writer: W) -> Result<Self, ReportError> {
        writeln!(
            writer,
            "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence"
        )?;
        Ok(Self { writer })
    }
}

impl<W: Write + Send> Reporter for CsvReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        let line_str = finding
            .location
            .line
            .map(|l| l.to_string())
            .unwrap_or_default();
        let commit_str = finding
            .location
            .commit
            .as_ref()
            .map(|c| c.as_ref())
            .unwrap_or_default();
        let author_str = finding
            .location
            .author
            .as_ref()
            .map(|a| a.as_ref())
            .unwrap_or_default();
        let date_str = finding
            .location
            .date
            .as_ref()
            .map(|d| d.as_ref())
            .unwrap_or_default();
        let file_path_str = finding
            .location
            .file_path
            .as_ref()
            .map(|f| f.as_ref())
            .unwrap_or_default();
        let confidence_str = finding
            .confidence
            .map(|c| c.to_string())
            .unwrap_or_default();

        let verification_str = match &finding.verification {
            crate::VerificationResult::Live => "live".to_string(),
            crate::VerificationResult::Revoked => "revoked".to_string(),
            crate::VerificationResult::Dead => "dead".to_string(),
            crate::VerificationResult::RateLimited => "rate_limited".to_string(),
            crate::VerificationResult::Error(err) => format!("error: {err}"),
            crate::VerificationResult::Unverifiable => "unverifiable".to_string(),
            crate::VerificationResult::Skipped => "skipped".to_string(),
        };

        writeln!(
            self.writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            escape_csv(&finding.detector_id),
            escape_csv(&finding.detector_name),
            escape_csv(&finding.service),
            escape_csv(&finding.severity.to_string()),
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

impl<W: Write + Send> WriterBackedReporter for CsvReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

fn escape_csv(val: &str) -> String {
    if val.contains(',') || val.contains('"') || val.contains('\n') || val.contains('\r') {
        let escaped = val.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        val.to_string()
    }
}
