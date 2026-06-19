//! Finishing a JSONL reporter without findings leaves output empty.

use crate::support::reporters::JsonlReporter;
#[test]
fn jsonl_reporter_empty_finish_still_valid() {
    let mut buf = Vec::new();
    let mut reporter = JsonlReporter::new(&mut buf);
    reporter.finish().unwrap();
    assert!(buf.is_empty());
}
