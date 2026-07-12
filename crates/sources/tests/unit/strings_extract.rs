//! Contract for `strings::extract_printable_strings` + `join_sensitive_strings`
//! (reached via the `SourceTestApi` facade). Migrated out of an inline
//! `#[cfg(test)]` block in `src/strings.rs` to satisfy the sources folder
//! contract (`strings_no_inline_tests`).
//!
//! `extract_printable_strings` recovers printable ASCII runs of at least
//! `min_len` from arbitrary bytes AND UTF-16LE wide strings (each ASCII byte
//! followed by 0x00), dropping short runs; `join_sensitive_strings` inserts the
//! separator between parts only.

use keyhog_core::SensitiveString;
use keyhog_sources::testing::{SourceTestApi, TestApi};

fn as_strs(v: &[SensitiveString]) -> Vec<&str> {
    v.iter().map(|s| s.as_ref()).collect()
}

#[test]
fn extracts_ascii_run_and_drops_short_runs() {
    // "hi" (len 2) is below min_len and dropped; the long run is kept.
    let out = TestApi.extract_printable_strings(b"hi\x00this_is_long_enough\x00", 5);
    assert_eq!(as_strs(&out), vec!["this_is_long_enough"]);
}

#[test]
fn extracts_utf16le_wide_string() {
    // Each ASCII byte is followed by 0x00; the ASCII pass sees only
    // length-1 runs (all dropped) and only the wide pass recovers "Secret".
    let out = TestApi.extract_printable_strings(b"S\x00e\x00c\x00r\x00e\x00t\x00", 5);
    assert_eq!(as_strs(&out), vec!["Secret"]);
}

#[test]
fn pure_ascii_text_yields_no_spurious_wide_strings() {
    let out = TestApi.extract_printable_strings(b"AKIAIOSFODNN7EXAMPLE", 8);
    assert_eq!(as_strs(&out), vec!["AKIAIOSFODNN7EXAMPLE"]);
}

#[test]
fn empty_input_yields_nothing() {
    assert!(TestApi.extract_printable_strings(b"", 4).is_empty());
}

#[test]
fn join_inserts_separator_between_parts_only() {
    let parts = [
        SensitiveString::from("a"),
        SensitiveString::from("b"),
        SensitiveString::from("c"),
    ];
    assert_eq!(
        TestApi.join_sensitive_strings(&parts, "/").as_ref(),
        "a/b/c"
    );
}

#[test]
fn join_empty_slice_is_empty() {
    assert_eq!(TestApi.join_sensitive_strings(&[], "/").as_ref(), "");
}
