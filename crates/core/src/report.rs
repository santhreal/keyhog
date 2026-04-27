//! Reporting logic for scan results.

mod json;
mod sarif;
mod text;

pub mod banner;

use std::io::Write;

use crate::VerifiedFinding;

pub use json::{JsonArrayReporter, JsonReporter, JsonlReporter};
pub use sarif::SarifReporter;
pub use text::TextReporter;

/// Common error type used by all reporters.
pub type ReportError = anyhow::Error;

/// Common trait for all finding reporters.
pub trait Reporter: Send {
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
