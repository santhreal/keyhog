//! Reporting logic for scan results.

mod csv;
mod html;
mod json;
mod junit;
mod sarif;
mod text;

#[path = "report/sarif_uri.rs"]
pub mod sarif_uri;

pub mod banner;

// Shared reporter test fixtures. Declared unconditionally here (the
// `report_no_inline_tests` gate forbids any test-config attribute token in
// this file); the module file itself is gated as test-only via an inner
// attribute, so it compiles to nothing outside test builds. See
// `report/test_support.rs`.
mod test_support;

use std::io::Write;

use crate::VerifiedFinding;

pub use csv::CsvReporter;
pub use html::HtmlReporter;
pub use json::{JsonArrayReporter, JsonReporter, JsonlReporter};
pub use junit::JunitReporter;
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
