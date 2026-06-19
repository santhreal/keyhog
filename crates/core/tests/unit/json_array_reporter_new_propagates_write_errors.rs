//! Public JSON report writing surfaces opening write failures.

use keyhog_core::{write_report, ReportFormat};
use std::io::{self, Write};

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn json_array_report_propagates_write_errors() {
    let error = write_report(FailingWriter, ReportFormat::Json, &[]).unwrap_err();
    assert!(error.to_string().contains("write failed"));
}
