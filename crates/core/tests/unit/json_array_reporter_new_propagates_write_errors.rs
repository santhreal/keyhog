//! JsonArrayReporter::new surfaces opening write failures.

use keyhog_core::JsonArrayReporter;
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
fn json_array_reporter_new_propagates_write_errors() {
    match JsonArrayReporter::new(FailingWriter) {
        Ok(_) => panic!("expected write failure"),
        Err(error) => assert!(error.to_string().contains("write failed")),
    }
}
