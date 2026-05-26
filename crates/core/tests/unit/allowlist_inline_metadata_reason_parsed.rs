//! Inline metadata `reason=` must survive Allowlist::parse.

use keyhog_core::Allowlist;

#[test]
fn allowlist_inline_metadata_reason_parsed() {
    let raw = r#"detector:foo ; reason="rotate after release" ; expires=2099-01-01 ; approved_by="alice@example.com""#;
    let al = Allowlist::parse(raw);
    assert!(al.ignored_detectors.contains("foo"));
}
