//! Migrated from `src/report/text.rs` inline tests.
use keyhog_core::{Reporter, TextReporter};
#[test]
fn empty_with_suppressions_says_examples_were_silenced() {
    let mut buf = Vec::new();
    let mut r = TextReporter::with_color(&mut buf, false);
    r.set_example_suppressions(6);
    r.finish().unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(
        s.contains("6 example/test keys suppressed"),
        "summary must surface the suppression count: {s}"
    );
    assert!(
        s.contains("--dogfood"),
        "summary should point at --dogfood: {s}"
    );
    assert!(
        !s.contains("Your code is clean"),
        "must not claim cleanliness when matches were silenced: {s}"
    );
}
