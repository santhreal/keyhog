//! Machine-readable JSON reporters: versioned envelopes for batch output,
//! legacy arrays for library compatibility, and JSON Lines for streams.

use std::io::Write;

use crate::VerifiedFinding;

use super::{
    impl_writer_backed, JsonReportCoverageGap, JsonlStreamHeader, JsonlStreamSummary, ReportError,
    Reporter, ScanReportMetadata, WriterBackedReporter, JSON_REPORT_SCHEMA_MAJOR,
    JSON_REPORT_SCHEMA_MINOR,
};

/// One JSON object per line (JSONL).
///
/// # Examples
///
/// ```ignore
/// // Crate-internal reporter; public callers use `write_report`.
/// use keyhog_core::report::json::JsonlReporter;
///
/// let reporter = JsonlReporter::new(Vec::new());
/// let _ = reporter;
/// ```
pub(crate) struct JsonlReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> JsonlReporter<W> {
    /// Create a JSON Lines reporter.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Crate-internal reporter; public callers use `write_report`.
    /// use keyhog_core::report::json::JsonlReporter;
    ///
    /// let reporter = JsonlReporter::new(Vec::new());
    /// let _ = reporter;
    /// ```
    pub(crate) fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write + Send> Reporter for JsonlReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        serde_json::to_writer(&mut self.writer, finding)?;
        writeln!(self.writer)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.flush_writer()
    }
}

impl_writer_backed!(JsonlReporter);

/// Versioned JSON Lines output with an explicit first-record stream header.
pub(crate) struct JsonlEnvelopeReporter<W: Write + Send> {
    writer: W,
    finding_count: usize,
    coverage_gap_summary: Vec<(String, usize)>,
}

impl<W: Write + Send> JsonlEnvelopeReporter<W> {
    pub(crate) fn new(
        mut writer: W,
        metadata: Option<&ScanReportMetadata>,
        coverage_gap_summary: &[(String, usize)],
    ) -> Result<Self, ReportError> {
        serde_json::to_writer(&mut writer, &JsonlStreamHeader::new(metadata))?;
        writeln!(writer)?;
        Ok(Self {
            writer,
            finding_count: 0,
            coverage_gap_summary: coverage_gap_summary.to_vec(),
        })
    }
}

impl<W: Write + Send> Reporter for JsonlEnvelopeReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        serde_json::to_writer(&mut self.writer, finding)?;
        writeln!(self.writer)?;
        self.finding_count += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        serde_json::to_writer(
            &mut self.writer,
            &JsonlStreamSummary::complete(self.finding_count, &self.coverage_gap_summary),
        )?;
        writeln!(self.writer)?;
        self.flush_writer()
    }
}

impl_writer_backed!(JsonlEnvelopeReporter);

/// Full JSON array output.
///
/// # Examples
///
/// ```ignore
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Crate-internal reporter; public callers use `write_report`.
/// use keyhog_core::report::json::JsonArrayReporter;
///
/// let reporter = JsonArrayReporter::new(Vec::new())?;
/// let _ = reporter;
/// # Ok(()) }
/// ```
pub(crate) struct JsonArrayReporter<W: Write + Send> {
    writer: W,
    first: bool,
}

impl<W: Write + Send> JsonArrayReporter<W> {
    /// Create a JSON array reporter.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Crate-internal reporter; public callers use `write_report`.
    /// use keyhog_core::report::json::JsonArrayReporter;
    ///
    /// let reporter = JsonArrayReporter::new(Vec::new())?;
    /// let _ = reporter;
    /// # Ok(()) }
    /// ```
    pub(crate) fn new(mut writer: W) -> Result<Self, ReportError> {
        write!(writer, "[")?;
        Ok(Self {
            writer,
            first: true,
        })
    }
}

impl<W: Write + Send> Reporter for JsonArrayReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        if !self.first {
            write!(self.writer, ",")?;
        }
        serde_json::to_writer(&mut self.writer, finding)?;
        self.first = false;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        write!(self.writer, "]")?;
        self.flush_writer()
    }
}

impl_writer_backed!(JsonArrayReporter);

/// Versioned JSON envelope output for operator-facing machine artifacts.
pub(crate) struct JsonEnvelopeReporter<W: Write + Send> {
    writer: W,
    first: bool,
}

impl<W: Write + Send> JsonEnvelopeReporter<W> {
    /// Create a versioned JSON envelope reporter.
    pub(crate) fn new(
        mut writer: W,
        metadata: Option<&ScanReportMetadata>,
        coverage_gap_summary: &[(String, usize)],
    ) -> Result<Self, ReportError> {
        write!(
            writer,
            "{{\"schema_version\":{{\"major\":{},\"minor\":{}}}",
            JSON_REPORT_SCHEMA_MAJOR, JSON_REPORT_SCHEMA_MINOR
        )?;
        if let Some(metadata) = metadata {
            write!(writer, ",\"metadata\":")?;
            serde_json::to_writer(&mut writer, metadata)?;
        }
        write!(writer, ",\"coverage_gap_summary\":[")?;
        for (index, (reason, count)) in coverage_gap_summary.iter().enumerate() {
            if index > 0 {
                write!(writer, ",")?;
            }
            serde_json::to_writer(
                &mut writer,
                &JsonReportCoverageGap {
                    reason: reason.clone(),
                    count: *count,
                },
            )?;
        }
        write!(writer, "]")?;
        write!(writer, ",\"findings\":[")?;
        Ok(Self {
            writer,
            first: true,
        })
    }
}

impl<W: Write + Send> Reporter for JsonEnvelopeReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        if !self.first {
            write!(self.writer, ",")?;
        }
        serde_json::to_writer(&mut self.writer, finding)?;
        self.first = false;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        write!(self.writer, "]}}")?;
        self.flush_writer()
    }
}

impl_writer_backed!(JsonEnvelopeReporter);
