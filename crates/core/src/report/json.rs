//! Machine-readable JSON reporters: JSON Lines for streams and pretty JSON arrays
//! for batch output.

use std::io::Write;

use crate::VerifiedFinding;

use super::{ReportError, Reporter, WriterBackedReporter};

/// One JSON object per line (JSONL).
///
/// # Examples
///
/// ```rust
/// use keyhog_core::JsonlReporter;
///
/// let reporter = JsonlReporter::new(Vec::new());
/// let _ = reporter;
/// ```
pub struct JsonlReporter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> JsonlReporter<W> {
    /// Create a JSON Lines reporter.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::JsonlReporter;
    ///
    /// let reporter = JsonlReporter::new(Vec::new());
    /// let _ = reporter;
    /// ```
    pub fn new(writer: W) -> Self {
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

impl<W: Write + Send> WriterBackedReporter for JsonlReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

/// Full JSON array output.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use keyhog_core::JsonArrayReporter;
///
/// let reporter = JsonArrayReporter::new(Vec::new())?;
/// let _ = reporter;
/// # Ok(()) }
/// ```
pub struct JsonArrayReporter<W: Write + Send> {
    writer: W,
    first: bool,
}

impl<W: Write + Send> JsonArrayReporter<W> {
    /// Create a JSON array reporter.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use keyhog_core::JsonArrayReporter;
    ///
    /// let reporter = JsonArrayReporter::new(Vec::new())?;
    /// let _ = reporter;
    /// # Ok(()) }
    /// ```
    pub fn new(mut writer: W) -> Result<Self, ReportError> {
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

impl<W: Write + Send> WriterBackedReporter for JsonArrayReporter<W> {
    type Writer = W;

    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.writer
    }
}

/// Alias for [`JsonArrayReporter`] for standard JSON output.
pub type JsonReporter<W> = JsonArrayReporter<W>;
