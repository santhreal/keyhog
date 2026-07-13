//! Migrated from `src/report/text.rs` inline tests.

use crate::support::reporters::TextReporter;
#[test]
fn empty_with_zero_suppressions_says_no_secrets_detected() {
    let mut buf = Vec::new();
    let mut r = TextReporter::with_color(&mut buf, false);
    r.finish().unwrap();
    let s = String::from_utf8(buf).unwrap();
    // A scanner cannot prove the ABSENCE of secrets and skipped/unreadable files
    // are not covered at all, so the empty-result message states only what is
    // true (nothing was detected in what was scanned. It must NOT claim "clean").
    assert!(
        s.contains("No secrets detected in the scanned files"),
        "got: {s}"
    );
    assert!(
        !s.to_ascii_lowercase().contains("your code is clean"),
        "must not overclaim a clean bill of health (absence is unprovable): {s}"
    );
    assert!(
        !s.contains("example/test"),
        "must not mention suppressions when there were none: {s}"
    );
}
