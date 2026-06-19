//! Migrated from `src/report/text.rs` inline tests.

use crate::support::reporters::TextReporter;
#[test]
fn empty_with_one_suppression_uses_singular() {
    let mut buf = Vec::new();
    let mut r = TextReporter::with_color(&mut buf, false);
    r.set_example_suppressions(1);
    r.finish().unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("1 example/test key suppressed"), "got: {s}");
}
