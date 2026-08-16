//! Output formatting and streaming report generation.
//!
//! Provides streaming report formatters for CLI scan execution. Envelopes
//! and findings stream directly into buffered writers to minimize memory
//! overhead on large finding sets.

use std::io::BufWriter;

pub(crate) use crate::reporting::report_findings_with_metadata;
/// Default buffer capacity in bytes for streaming report writers.
pub(crate) const REPORT_BUFFER_CAPACITY: usize = 64 * 1024;

/// Wrap a writer in a standard buffered writer sized for report streaming.
pub(crate) fn buffered_report_writer<W: std::io::Write>(writer: W) -> BufWriter<W> {
    BufWriter::with_capacity(REPORT_BUFFER_CAPACITY, writer)
}
