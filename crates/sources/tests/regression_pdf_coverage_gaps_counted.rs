//! PDF extraction failures are coverage gaps, not clean scans.
//!
//! Own test binary: the skip counters are process-global atomics. Keeping these
//! assertions out of `tests/all_tests.rs` lets the fixture reset the counters
//! without racing unrelated source tests in the same process.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

fn write_pdf(bytes: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bad.pdf"), bytes).expect("write pdf");
    dir
}

fn drain_pdf(bytes: &[u8]) {
    let dir = write_pdf(bytes);
    let _chunks = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>();
}

#[test]
fn pdf_extraction_failures_bump_unreadable_gaps() {
    TestApi.reset_skip_counters();
    drain_pdf(b"%PDF-1.7\ntrailer\n<< /Encrypt 2 0 R >>\n%%EOF\n");
    drain_pdf(
        b"%PDF-1.7\n1 0 obj\n<< /Length 17 /Filter /FlateDecode >>\nstream\nnot-a-flate-stream\nendstream\nendobj\n%%EOF\n",
    );
    assert_eq!(
        skip_counts().unreadable,
        2,
        "encrypted PDFs and corrupt FlateDecode streams must both be surfaced as unreadable coverage gaps"
    );
}
