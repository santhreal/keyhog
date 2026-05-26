//! Migrated from `src/report/text.rs` inline tests.
use keyhog_core::{Reporter, TextReporter};
#[test]
fn empty_with_zero_suppressions_says_clean() {
    let mut buf = Vec::new();
    let mut r = TextReporter::with_color(&mut buf, false);
    r.finish().unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("Your code is clean"), "got: {s}");
    assert!(
        !s.contains("example/test"),
        "must not mention suppressions when there were none: {s}"
    );
}
